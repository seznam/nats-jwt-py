#    Copyright 2024 Seznam.cz, a.s.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from __future__ import annotations

import base64
import os
import typing

import nkeys
from nacl.signing import VerifyKey
from nkeys import crc16

if typing.TYPE_CHECKING:
    from nats_jwt.v2.claims import PrefixByte


def correct_padding(src: bytes) -> bytes:
    """ Base32 encoding requires padding to be a multiple of 8 """
    length = len(src)

    if length % 8 == 0:
        return src

    return src + b"=" * (8 - length % 8)


def b32decode(src: bytes) -> bytes:
    """ Base32 decoding with correct padding """
    return base64.b32decode(correct_padding(src))


class PublicKey:
    def __init__(self, pub_key: bytes):
        self.kp = pub_key

    @property
    def verify_key(self) -> VerifyKey:
        return VerifyKey(self.kp)


def keypair_from_pubkey(pub_key: bytes) -> "nkeys.KeyPair":
    raw: bytearray = _decode(bytearray(pub_key))
    return nkeys.KeyPair(keys=PublicKey(
        pub_key=bytes(raw[1:]),
    ))


def Encode(prefix: typing.Union["PrefixByte", int], src: bytes) -> bytes:
    """Encode will encode a raw key or seed with the prefix and crc16 and then base32 encoded."""
    if not nkeys.valid_prefix_byte(prefix):
        raise ValueError(f"nkeys: invalid prefix byte: {prefix}")

    raw = bytearray()

    # write prefix byte
    if isinstance(prefix, bytearray):
        raw.extend(prefix)
    else:
        raw.append(prefix)  # noqa

    # write payload
    raw.extend(src)

    # Calculate and write crc16 checksum
    crc = crc16(raw)
    crc_bytes = crc.to_bytes(2, byteorder='little')

    raw.extend(crc_bytes)

    # Encode to base32
    encode = base64.b32encode(raw)

    # return cut without padding as go-version does
    return encode.rstrip(b"=")


def _decode(src: bytearray) -> bytearray:
    raw = bytearray(b32decode(src))

    if len(raw) < 4:
        raise ValueError("nkeys: invalid encoding")

    crc = int.from_bytes(raw[-2:], byteorder='little')

    # ensure checksum is valid
    if crc != crc16(raw[:-2]):
        raise ValueError("nkeys: invalid checksum")

    return raw[:-2]


def Decode(expected_prefix: "PrefixByte", src: bytearray | bytes) -> bytearray:
    """Decode will decode the base32 string and check crc16 and enforce the prefix is what is expected."""
    if not nkeys.valid_prefix_byte(expected_prefix):
        raise ValueError(f"nkeys: invalid prefix byte: {src[0]}")

    raw = _decode(src)

    b1 = raw[0] & 248  # 248 = 11111000

    if b1 != expected_prefix:
        raise ValueError("nkeys: invalid prefix byte")

    return raw[1:]


def create_seed() -> bytes:
    return os.urandom(32)


def encode_seed(prefix: int, seed: bytes) -> bytes:
    # To make this human printable for both bytes, we need to do a little
    # bit manipulation to setup for base32 encoding which takes 5 bits at a time.
    b1 = nkeys.PREFIX_BYTE_SEED | (prefix >> 5)
    b2 = (prefix & 31) << 3  # 31 = 00011111

    raw = bytearray()

    # write prefix bytes
    raw.append(b1)
    raw.append(b2)

    # write payload
    raw.extend(seed)

    # Calculate and write crc16 checksum
    crc = crc16(raw)
    crc_bytes = crc.to_bytes(2, byteorder='little')

    raw.extend(crc_bytes)

    # Encode to base32
    # return cut without padding as go-version does
    return base64.b32encode(raw).rstrip(b"=")


def create_pair_with_rand(prefix: int, seed: bytes = None) -> nkeys.KeyPair:
    seed = seed or create_seed()

    return nkeys.from_seed(encode_seed(prefix,seed))


def create_operator_pair() -> nkeys.KeyPair:
    return create_pair_with_rand(nkeys.PREFIX_BYTE_OPERATOR)


def create_account_pair() -> nkeys.KeyPair:
    return create_pair_with_rand(nkeys.PREFIX_BYTE_ACCOUNT)


def create_user_pair() -> nkeys.KeyPair:
    return create_pair_with_rand(nkeys.PREFIX_BYTE_USER)
