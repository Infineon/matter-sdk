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
"""SS Hex file generator

This is a helper script for generating SS hex file.

"""

import argparse
import base64
import os
import pathlib
import re
import sys
import typing
import zlib
from collections import OrderedDict
from struct import pack, unpack

import leb128
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          pkcs12)
from intelhex import IntelHex

THREAD_FACTORY_KEY_BASE = 0x2000
MATTER_FACTORY_KEY_BASE = 0x2100


def main():
    args = parse_args()

    configs = gen_thread_factory_config()
    configs.update(gen_matter_factory_config(args.config_header))

    try:
        att_cert = load_att_cert(args.att_cert, args.att_cert_password)
    except ValueError as e:
        print(f"[Error] Failed to load {args.att_cert}: {str(e)}")
        return -1

    parse_config_args(configs, args.config, att_cert)

    ss_hex = insert_config(IntelHex(str(args.ss_skeleton_hex)), configs)
    ss_hex.write_hex_file(args.output)

    return 0


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--ss_skeleton_hex", required=True, type=pathlib.Path)
    parser.add_argument("--config_header", required=True, type=pathlib.Path)
    parser.add_argument("--config", action="append", type=str)
    parser.add_argument("--att_cert", required=True, type=pathlib.Path)
    parser.add_argument("--att_cert_password",
                        type=lambda x: x.encode() if x else None)
    return parser.parse_args()


def gen_thread_factory_config() -> OrderedDict:
    configs = OrderedDict()
    configs["ExtendedAddress"] = {
        "key": THREAD_FACTORY_KEY_BASE, "value": os.urandom(8)}
    return configs


def gen_matter_factory_config(path: pathlib.Path) -> OrderedDict:
    # compile the regex for extracting name and key of factory configurations.
    factory_config_re = re.compile(r"""
      .*                    # Prefix
      kConfigKey_(\w+)      # Parse the config name
      \s*=.*                # Allow spaces
      kChipFactory_KeyBase  # Only match factory configurations
      \s*,\s*               # Allow spaces
      (0x[0-9a-fA-F]+)      # Parse the config key
    """, re.VERBOSE)

    configs = OrderedDict()
    with open(str(path), mode="r") as config_file:
        for line in config_file:
            match = factory_config_re.match(line.strip())
            if match:
                name = match[1]
                key = MATTER_FACTORY_KEY_BASE + int(match[2], 0)
                configs[name] = {"key": key}
    return configs


def load_att_cert(path: pathlib.Path, password: typing.Optional[bytes]) -> pkcs12.PKCS12KeyAndCertificates:
    """
    Load the private key and certificates in PKCS#12 format from the given path.
    """
    with open(path, mode="rb") as file:
        return pkcs12.load_pkcs12(file.read(), password)


def parse_config_args(configs: OrderedDict, args: list, att_cert: pkcs12.PKCS12KeyAndCertificates):
    for arg in args:
        name, category, value = arg.split(":")

        if name not in configs:
            print(f"[Warning] Ignored unknown config: {name}")
            continue

        if category == "address":
            addr = bytearray.fromhex(value)

            if len(addr) == 6:
                # RFC 4291 Appendix A
                addr[3:3] = b'\xff\xfe'
            elif len(addr) != 8:
                print(
                    f"[Warning] Ignored config {name}: Invalid length: {len(addr)}")
                return

            configs[name]["value"] = addr[::-1]
        elif category == "base64":
            configs[name]["value"] = base64.b64decode(value)
        elif category == "octets":
            with open(value, mode="rb") as file:
                configs[name]["value"] = file.read()
        elif category == "att-cert":
            configs[name]["value"] = decode_att_cert(value, att_cert)
        elif category == "string":
            configs[name]["value"] = value.encode()
        elif category == "uint16":
            configs[name]["value"] = int(
                value, 0).to_bytes(2, byteorder="little")
        elif category == "uint32":
            configs[name]["value"] = int(
                value, 0).to_bytes(4, byteorder="little")
        else:
            print(
                f"[Warning] Ignored config {name}: Invalid category: {category}")


def decode_att_cert(entry: str, att_cert: pkcs12.PKCS12KeyAndCertificates):
    """
    Decode the specified entry from the given PKCS#12 object
    and convert it to the DER format.
    """

    if entry == "dac":
        return att_cert.cert.certificate.public_bytes(encoding=Encoding.DER)

    if entry == "dac-key":
        return att_cert.key.private_bytes(encoding=Encoding.DER, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())

    if entry == "pai-cert":
        return att_cert.additional_certs[0].certificate.public_bytes(encoding=Encoding.DER)

    print(f"[Error] Invalid att-cert entry: {entry}")
    return None


def insert_config(origin_hex: IntelHex, configs: OrderedDict):
    ss_segment = origin_hex.segments()[0]

    origin_ss_header = origin_hex.tobinarray(
        start=ss_segment[0], end=ss_segment[0] + 0x10 - 1)
    origin_ss_data = origin_hex.tobinarray(
        start=ss_segment[0] + 0x10, end=ss_segment[1] - 1)

    signature, _, _ = unpack("<8sLL", origin_ss_header)

    ss_data = bytearray()
    for config in configs.values():
        if "value" in config:
            ss_data += config["key"].to_bytes(2, byteorder="little")
            ss_data += leb128.u.encode(len(config["value"]))
            ss_data += config["value"]
    ss_data += origin_ss_data

    ss_header = pack("<8sLL", signature, zlib.crc32(ss_data), len(ss_data))

    ss_hex = IntelHex()
    ss_hex.puts(ss_segment[0], ss_header + ss_data)
    return ss_hex


if __name__ == "__main__":
    sys.exit(main())
