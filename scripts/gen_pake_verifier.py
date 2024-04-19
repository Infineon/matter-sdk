#!/usr/bin/env python
#
# Copyright (c) 2024 Project CHIP Authors
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
"""PAKE verifier generator

This script generates PAKE verifier.

"""

import argparse
import base64
import hashlib
import os
import struct
import sys

from ecdsa.curves import NIST256p

# Forbidden passcodes as listed in the "5.1.7.1. Invalid Passcodes" section of the Matter spec
INVALID_PASSCODES = [00000000,
                     11111111,
                     22222222,
                     33333333,
                     44444444,
                     55555555,
                     66666666,
                     77777777,
                     88888888,
                     99999999,
                     12345678,
                     87654321, ]

# Length of `w0s` and `w1s` elements
WS_LENGTH = NIST256p.baselen + 8

TEST_PASSCODE = 20202021
TEST_SALT = b'SPAKE2P Key Salt'


def generate_verifier(passcode: int, salt: bytes, iterations: int) -> bytes:
    ws = hashlib.pbkdf2_hmac('sha256', struct.pack(
        '<I', passcode), salt, iterations, WS_LENGTH * 2)
    w0 = int.from_bytes(ws[:WS_LENGTH], byteorder='big') % NIST256p.order
    w1 = int.from_bytes(ws[WS_LENGTH:], byteorder='big') % NIST256p.order
    l = NIST256p.generator * w1

    return w0.to_bytes(NIST256p.baselen, byteorder='big') + l.to_bytes('uncompressed')


def main():
    option = parse_args()

    if len(option.salt) == 0:
        if option.passcode == TEST_PASSCODE:
            salt = TEST_SALT
        else:
            salt = os.urandom(32)
    else:
        salt = option.salt

    verifier = generate_verifier(option.passcode, salt, option.iteration_count)

    print(f"salt = \"{base64.b64encode(salt).decode('ascii')}\"")
    print(f"verifier = \"{base64.b64encode(verifier).decode('ascii')}\"")


def parse_args():
    def passcode_arg(arg: str) -> int:
        passcode = int(arg, 0)

        if not 0 <= passcode <= 99999999:
            raise argparse.ArgumentTypeError('passcode out of range')

        if passcode in INVALID_PASSCODES:
            raise argparse.ArgumentTypeError('invalid passcode')

        return passcode

    def salt_arg(arg: str) -> bytes:
        salt = base64.b64decode(arg)

        if len(salt) > 0 and not 16 <= len(salt) <= 32:
            raise argparse.ArgumentTypeError('invalid salt length')

        return salt

    def iteration_count_arg(arg: str) -> int:
        iterations = int(arg, 0)

        if not 1000 <= iterations <= 100000:
            raise argparse.ArgumentTypeError('iteration count out of range')

        return iterations

    parser = argparse.ArgumentParser()
    parser.add_argument("--passcode", required=True, type=passcode_arg)
    parser.add_argument("--salt", required=True, type=salt_arg)
    parser.add_argument("--iteration-count", required=True,
                        type=iteration_count_arg)
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(main())
