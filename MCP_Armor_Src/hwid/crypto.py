# -*- coding: utf-8 -*-
"""Small Python 2/3 compatible XOR codec for HWID tokens."""
from __future__ import absolute_import

import binascii


HWID_XOR_KEY = 'Conla_Deobf'


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    return value.encode('utf-8')


def xor_bytes(data, key=HWID_XOR_KEY):
    data = bytearray(_as_bytes(data))
    key = bytearray(_as_bytes(key))
    if not key:
        raise ValueError('XOR key must not be empty')
    return bytearray(value ^ key[index % len(key)]
                     for index, value in enumerate(data))


def xor_encrypt_hex(value, key=HWID_XOR_KEY):
    encoded = binascii.hexlify(xor_bytes(value, key))
    if not isinstance(encoded, str):
        encoded = encoded.decode('ascii')
    return encoded.upper()


def xor_decrypt_hex(value, key=HWID_XOR_KEY):
    raw = binascii.unhexlify(_as_bytes(value))
    decoded = bytes(xor_bytes(raw, key))
    return decoded.decode('utf-8')
