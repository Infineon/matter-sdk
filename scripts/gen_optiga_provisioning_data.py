#!/usr/bin/env python
#
# Copyright (c) 2022 Project CHIP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Optiga provisioning data generator

This is a helper script for generating Optiga provisioning data.

"""

import argparse
import base64
import hashlib
import hmac
import secrets
import sys
from struct import pack

import zcbor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, EllipticCurvePrivateKey)
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import pkcs12


def main():
    args = parse_args()

    outputs = {}

    outputs["trust_anchor_metadata"] = create_trust_anchor_metadata()
    outputs["secret_metadata"] = create_secret_metadata()
    outputs["key_metadata"] = create_key_metadata(args.dac_object_id)

    unencrypted_fragment = create_fragment(args.att_cert.key)
    outputs["secret"] = secrets.token_bytes(64)
    seed = secrets.token_bytes(64)

    outputs["fragment"] = encrypt_fragment(
        unencrypted_fragment, 1, 0, outputs["secret"], args.label, seed)

    outputs["manifest"] = create_manifest(
        len(unencrypted_fragment), outputs["fragment"], seed, args)

    for key, value in outputs.items():
        print(f"{key} = \"{base64.b64encode(value).decode()}\"")

    return 0


def parse_args():
    def att_cert_arg(arg: str) -> pkcs12.PKCS12KeyAndCertificates:
        with open(arg, "rb") as f:
            return pkcs12.load_pkcs12(f.read(), None)

    def cddl_arg(arg: str):
        with open(arg, mode="r", encoding="utf-8") as f:
            return zcbor.DataTranslator.from_cddl(f.read(), 3)

    parser = argparse.ArgumentParser()
    parser.add_argument("--att_cert", required=True, type=att_cert_arg)
    parser.add_argument("--secret_object_id", required=True,
                        type=lambda x: int(x, 0))
    parser.add_argument("--dac_object_id", required=True,
                        type=lambda x: int(x, 0))
    parser.add_argument("--dac_key_object_id",
                        required=True, type=lambda x: int(x, 0))
    parser.add_argument("--label", required=True, type=lambda x: x.encode())
    parser.add_argument("--cddl", required=True, type=cddl_arg)
    return parser.parse_args()


def create_trust_anchor_metadata():
    # Execute access condition = Always
    # Data object type = Trust Anchor
    return bytes.fromhex(
        """
        20 06
        D3 01 00
        E8 01 11
        """)


def create_secret_metadata():
    # Execute access condition = Always
    # Data object type = Protected updated secret
    return bytes.fromhex(
        """
        20 06
        D3 01 00
        E8 01 23
        """)


def create_key_metadata(trust_anchor_oid):
    # Change access condition = Integrity protected
    # Execute access condition = Always
    return bytes.fromhex(
        f"""
        20 0C
        C1 02 00 00
        D0 03 21 {trust_anchor_oid:02x}
        D3 01 00
        """)


def create_fragment(key: EllipticCurvePrivateKey):
    ECC_PRIVATE_KEY_TAG = 1
    ECC_PUBLIC_KEY_TAG = 2

    key_size = int(key.key_size / 8)

    private_numbers = key.private_numbers()
    private_value = private_numbers.private_value.to_bytes(key_size, 'big')

    public_numbers = private_numbers.public_numbers
    public_value = public_numbers.x.to_bytes(key_size, 'big')
    public_value += public_numbers.y.to_bytes(key_size, 'big')

    fragment = pack(">BH", ECC_PRIVATE_KEY_TAG,
                    len(private_value)) + private_value
    fragment += pack(">BH", ECC_PUBLIC_KEY_TAG,
                     len(public_value)) + public_value

    return fragment


def tls_prf_sha256(key, message):
    hmac1 = hmac.new(key, message, hashlib.sha256)
    return hmac.new(key, hmac1.digest() + message, hashlib.sha256).digest()


def encrypt_fragment(fragment: bytes, fragment_number: int, fragment_offset: int, secret: bytes, label: bytes, seed: bytes) -> bytes:
    digest = tls_prf_sha256(secret, label + seed)

    key = digest[:16]
    nonce = digest[16:27] + pack(">H", fragment_number)
    associated_data = create_associated_data(3, fragment_offset, len(fragment))

    return AESCCM(key, tag_length=8).encrypt(nonce, fragment, associated_data)


def create_associated_data(payload_version, fragment_offset, payload_length):
    associated_data = payload_version.to_bytes(2, byteorder="big")
    associated_data += fragment_offset.to_bytes(3, byteorder="big")
    associated_data += payload_length.to_bytes(3, byteorder="big")
    return associated_data


def create_manifest(payload_length, fragment: bytes, seed: bytes, args):

    protected_signed_header_trust_yaml = create_protected_signed_header_trust_yaml()
    unprotected_signed_header_trust_yaml = create_unprotected_signed_header_trust_yaml(
        args.dac_object_id)
    trust_manifest_yaml = create_trust_manifest_yaml(
        args, payload_length, fragment, seed)

    # create manifest signature
    sig_structure_yaml = create_sig_structure_yaml(
        protected_signed_header_trust_yaml, trust_manifest_yaml)
    sig_structure = yaml_to_cbor(
        args.cddl.my_types["Sig_structure"], sig_structure_yaml)
    signature = ecdsa_sign_message(args.att_cert.key, sig_structure)

    # create manifest
    manifest_yaml = create_manifest_yaml(protected_signed_header_trust_yaml,
                                         unprotected_signed_header_trust_yaml, trust_manifest_yaml, signature)
    return yaml_to_cbor(args.cddl.my_types["COSE_Sign1_Trust"], manifest_yaml)


def create_sig_structure_yaml(protected_signed_header_trust_yaml: str, trust_manifest_yaml: str) -> str:
    return f"""
- zcbor_bstr: {b'Signature1'.hex()}
{protected_signed_header_trust_yaml}
- zcbor_bstr: ''
{trust_manifest_yaml}
"""


def create_manifest_yaml(protected_signed_header_trust_yaml: str, unprotected_signed_header_trust_yaml: str, trust_manifest_yaml: str, signature: bytes) -> str:
    return f"""
{protected_signed_header_trust_yaml}
{unprotected_signed_header_trust_yaml}
{trust_manifest_yaml}
- zcbor_bstr: {signature.hex()}
"""


def create_protected_signed_header_trust_yaml() -> str:
    return """
- zcbor_bstr:
    zcbor_keyval0:
      key: 1
      # Trust Sign Algorithm
      val: -7 # ES-256
"""


def create_unprotected_signed_header_trust_yaml(trust_anchor_oid: int) -> str:
    return f"""
- zcbor_keyval0:
    key: 4
    val:
      # Trust Anchor OID
      zcbor_bstr: {trust_anchor_oid:04x}
"""


def create_trust_manifest_yaml(args, payload_length, fragment, seed) -> str:
    fragment_digest = hashlib.sha256(fragment).digest()

    return f"""
# Payload
- zcbor_bstr:
  # Manifest data model version
  - 1
  # Preconditions
  - null
  # Postconditions
  - null
  # Resources
    # Trust Payload Type
  - - -3 # Payload_Key
    # Payload Length
    - {payload_length}
    # Trust Payload version
    - 3
    # Trust Add info data
      # key algorithm
    - - 3 # ECC-NIST-P256
      # key usage
      - 16 # SIGN (0x10)
  # Trust Processors
    # Processing step integrity
      # Process
  - - - -1
      # IFX Digest info
      - zcbor_bstr:
        # Digest Algorithm
        - 41 # SHA-256
        # Digest data
        - zcbor_bstr: {fragment_digest.hex()}
    # Processing step decrypt
      # Process
    - - 1
      # COSE_Encrypt_Trust
        # protected-encrypt-header-Trust
      - - zcbor_bstr:
            # Algorithm
            zcbor_keyval0:
              key: 1
              val: 10 # AES-CCM-16-64-128, 128-bit key, 64-bit Authentication(MAC) tag, 13-byte nonce
        # recipients
          # COSE_Recipient_Trust
            # protected-recipient-header-Trust
        - - - zcbor_bstr:
                # Shared secret OID
                zcbor_keyval0:
                  key: 4
                  val:
                    zcbor_bstr: {args.secret_object_id:04x}
                # KeyDerivationAlgorithms
                zcbor_keyval1:
                  key: 1
                  val: -65720 # IFX_KDF-TLS12_PRF_SHA256
                # Trust_Key_derivation_IV
                zcbor_keyval2:
                  key: 5
                  val:
                  # label
                  - zcbor_bstr: '{args.label.hex()}'
                  # seed
                  - zcbor_bstr: {seed.hex()}
            # ciphertext
            - null
        # AdditionalInfo
        - null
  # Trust Target
    # Component identifier
  - - zcbor_bstr: ''
    # Storage identifier; Optiga target OID
    - zcbor_bstr: {args.dac_key_object_id:04x}
"""


def yaml_to_cbor(data_translator: zcbor.DataTranslator, yaml: str) -> bytes:
    cbor = data_translator.from_yaml(yaml, yaml_compat=True)
    data_translator.validate_str(cbor)
    return cbor


def ecdsa_sign_message(key: EllipticCurvePrivateKey, message: bytes) -> bytes:
    (r, s) = utils.decode_dss_signature(
        key.sign(message, signature_algorithm=ECDSA(hashes.SHA256())))
    return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


if __name__ == "__main__":
    sys.exit(main())
