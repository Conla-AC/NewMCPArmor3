# -*- coding: utf-8 -*-
"""Self-contained cryptographic primitives for the loader payload pipeline.

Pure Python 2.7-compatible so the same code runs in the build worker and in
the generated NetEase runtime.  CityHash64 drives a chained XChaCha20 variant,
followed by an MT19937_64 stream XOR.
"""

import struct
import sys
import zlib

_M64 = 0xFFFFFFFFFFFFFFFF
_IS_PY3 = sys.version_info[0] >= 3
_MT_SEED_CONST = 0xD017CBBA7B5D3581


def _rotr64(x, n):
    x &= _M64
    if n == 0:
        return x
    return ((x >> n) | (x << (64 - n))) & _M64


def _rotl32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _bswap64(x):
    x &= _M64
    return (((x & 0x00000000000000FF) << 56) |
            ((x & 0x000000000000FF00) << 40) |
            ((x & 0x0000000000FF0000) << 24) |
            ((x & 0x00000000FF000000) << 8) |
            ((x & 0x000000FF00000000) >> 8) |
            ((x & 0x0000FF0000000000) >> 24) |
            ((x & 0x00FF000000000000) >> 40) |
            ((x & 0xFF00000000000000) >> 56)) & _M64


def _byte_at(data, i):
    value = data[i]
    return value if isinstance(value, int) else ord(value)


def _fetch64(data, i):
    return struct.unpack('<Q', data[i:i + 8])[0] & _M64


def _fetch32(data, i):
    return struct.unpack('<I', data[i:i + 4])[0]


def _as_bytes(data):
    if _IS_PY3 and isinstance(data, str):
        return data.encode('latin1')
    return data


def _join_bytes(values):
    if _IS_PY3:
        return bytes(values)
    return ''.join(chr(v & 255) for v in values)


# ---- CityHash64 (with seed) ----


_K0 = 0xc3a5c85c97cb3127
_K1 = 0xb492b66fbe98f273
_K2 = 0x9ae16a3b2f90404f
_MUL = 0x9ddfea08eb382d69


def _add64(a, b):
    return (a + b) & _M64


def _sub64(a, b):
    return (a - b) & _M64


def _mul64(a, b):
    return (a * b) & _M64


def _shiftmix(x):
    x &= _M64
    return (x ^ (x >> 47)) & _M64


def _hash128to64(u, v):
    a = _mul64(u ^ v, _MUL)
    a ^= (a >> 47)
    b = _mul64(v ^ a, _MUL)
    b ^= (b >> 47)
    b = _mul64(b, _MUL)
    return b


def _hashlen16(u, v):
    return _hash128to64(u & _M64, v & _M64)


def _hashlen16_mul(u, v, mul):
    """Murmur-inspired 3-arg HashLen16 used by HashLen0to16/17to32."""
    a = _mul64(u ^ v, mul)
    a ^= (a >> 47)
    b = _mul64(v ^ a, mul)
    b ^= (b >> 47)
    b = _mul64(b, mul)
    return b


def _hashlen0to16(data, length):
    if length >= 8:
        mul = _add64(_K2, length * 2)
        a = _add64(_fetch64(data, 0), _K2)
        b = _fetch64(data, length - 8)
        c = _add64(_mul64(_rotr64(b, 37), mul), a)
        d = _mul64(_add64(_rotr64(a, 25), b), mul)
        return _hashlen16_mul(c, d, mul)
    if length >= 4:
        mul = _add64(_K2, length * 2)
        a = _fetch32(data, 0)
        return _hashlen16_mul(_add64(length, a << 3),
                              _fetch32(data, length - 4), mul)
    if length > 0:
        a = _byte_at(data, 0)
        b = _byte_at(data, length >> 1)
        c = _byte_at(data, length - 1)
        y = a + (b << 8)
        z = length + (c << 2)
        return _mul64(_shiftmix(_mul64(y, _K2) ^ _mul64(z, _K0)), _K2)
    return _K2


def _hashlen17to32(data, length):
    mul = _add64(_K2, length * 2)
    a = _mul64(_fetch64(data, 0), _K1)
    b = _fetch64(data, 8)
    c = _mul64(_fetch64(data, length - 8), mul)
    d = _mul64(_fetch64(data, length - 16), _K2)
    return _hashlen16_mul(
        _add64(_add64(_rotr64(a + b, 43), _rotr64(c, 30)), d),
        _add64(_add64(a, _rotr64(_add64(b, _K2), 18)), c),
        mul)


def _hashlen33to64(data, length):
    mul = _add64(_K2, length * 2)
    a = _mul64(_fetch64(data, 0), _K2)
    b = _fetch64(data, 8)
    c = _fetch64(data, length - 24)
    d = _fetch64(data, length - 32)
    e = _mul64(_fetch64(data, 16), _K2)
    f = _mul64(_fetch64(data, 24), 9)
    g = _fetch64(data, length - 8)
    h = _mul64(_fetch64(data, length - 16), mul)
    u = _add64(_rotr64(a + g, 43), _mul64(_add64(_rotr64(b, 30), c), 9))
    v = _add64(_add64((a + g) ^ d, f), 1)
    w = _add64(_bswap64(_mul64(u + v, mul)), h)
    x = _add64(_rotr64(e + f, 42), c)
    y = _mul64(_add64(_bswap64(_mul64(v + w, mul)), g), mul)
    z = _add64(_add64(e, f), c)
    a = _add64(_bswap64(_add64(_mul64(x + z, mul), y)), b)
    b = _mul64(_shiftmix(_add64(_mul64(z + a, mul), _add64(d, h))), mul)
    return _add64(b, x)


def _weak_hash_words(w, x, y, z, a, b):
    a = _add64(a, w)
    b = _rotr64(_add64(_add64(b, a), z), 21)
    c = a
    a = _add64(_add64(a, x), y)
    b = _add64(b, _rotr64(a, 44))
    return _add64(a, z), _add64(b, c)


def _weak_hash(data, a, b):
    return _weak_hash_words(
        _fetch64(data, 0), _fetch64(data, 8),
        _fetch64(data, 16), _fetch64(data, 24), a, b)


def _cityhash64(data):
    length = len(data)
    if length <= 32:
        return _hashlen0to16(data, length) if length <= 16 else _hashlen17to32(data, length)
    if length <= 64:
        return _hashlen33to64(data, length)
    x = _fetch64(data, length - 40)
    y = _add64(_fetch64(data, length - 16), _fetch64(data, length - 56))
    z = _hashlen16(_add64(_fetch64(data, length - 48), length),
                   _fetch64(data, length - 24))
    v0, v1 = _weak_hash(data[length - 64:], length, z)
    w0, w1 = _weak_hash(data[length - 32:], _add64(y, _K1), x)
    x = _add64(_mul64(x, _K1), _fetch64(data, 0))
    remaining = (length - 1) & ~63
    pos = 0
    while remaining:
        x = _mul64(_rotr64(_add64(_add64(_add64(x, y), v0), _fetch64(data, pos + 8)), 37), _K1)
        y = _mul64(_rotr64(_add64(_add64(y, v1), _fetch64(data, pos + 48)), 42), _K1)
        x ^= w1
        y = _add64(_add64(y, v0), _fetch64(data, pos + 40))
        z = _mul64(_rotr64(_add64(z, w0), 33), _K1)
        v0, v1 = _weak_hash(data[pos:], _mul64(v1, _K1), _add64(x, w0))
        w0, w1 = _weak_hash(data[pos + 32:], _add64(z, w1),
                            _add64(y, _fetch64(data, pos + 16)))
        z, x = x, z
        pos += 64
        remaining -= 64
    return _hashlen16(
        _add64(_add64(_hashlen16(v0, w0), _mul64(_shiftmix(y), _K1)), z),
        _add64(_hashlen16(v1, w1), x))


def cityhash64(data, seed=0):
    """CityHash64WithSeed.  ``data`` is a byte string (py2 str / py3 bytes)."""
    data = _as_bytes(data)
    return _hashlen16(_sub64(_cityhash64(data), _K2), seed & _M64)


# ---- MT19937_64 (std::mt19937_64) ----


class MT19937_64(object):
    def __init__(self, seed):
        self.state = [0] * 312
        self.index = 312
        self.state[0] = seed & _M64
        for i in range(1, 312):
            self.state[i] = (6364136223846793005 *
                             (self.state[i - 1] ^ (self.state[i - 1] >> 62)) + i) & _M64

    def _twist(self):
        for i in range(312):
            x = (self.state[i] & 0xFFFFFFFF80000000) | \
                (self.state[(i + 1) % 312] & 0x7FFFFFFF)
            xa = x >> 1
            if x & 1:
                xa ^= 0xB5026F5AA96619E9
            self.state[i] = self.state[(i + 156) % 312] ^ xa
        self.index = 0

    def next64(self):
        if self.index >= 312:
            self._twist()
        y = self.state[self.index]
        self.index += 1
        y ^= (y >> 29) & 0x5555555555555555
        y ^= (y << 17) & 0x71D67FFFEDA60000
        y ^= (y << 37) & 0xFFF7EEE000000000
        y ^= y >> 43
        return y & _M64


def mt19937_xor(data, seed):
    """XOR ``data`` with the MT19937_64 stream seeded by ``seed``."""
    data = _as_bytes(data)
    prng = MT19937_64(seed)
    out = []
    pos = 0
    length = len(data)
    while pos < length:
        word = prng.next64()
        block = struct.pack('<Q', word)
        for i in range(8):
            if pos >= length:
                break
            out.append(_byte_at(data, pos) ^ _byte_at(block, i))
            pos += 1
    return _join_bytes(out)


# ---- ChaCha20 / XChaCha20 ----


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _chacha_block(key_words, counter, nonce_words, rounds):
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state.extend(key_words)
    state.append(counter & 0xFFFFFFFF)
    state.extend(nonce_words)
    working = list(state)
    for _ in range(rounds // 2):
        _quarter(working, 0, 4, 8, 12)
        _quarter(working, 1, 5, 9, 13)
        _quarter(working, 2, 6, 10, 14)
        _quarter(working, 3, 7, 11, 15)
        _quarter(working, 0, 5, 10, 15)
        _quarter(working, 1, 6, 11, 12)
        _quarter(working, 2, 7, 8, 13)
        _quarter(working, 3, 4, 9, 14)
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xFFFFFFFF
    return struct.pack('<16I', *working)


def _key_words(key):
    return list(struct.unpack('<8I', key))


def _nonce3_words(nonce12):
    return list(struct.unpack('<3I', nonce12))


def hchacha20(key, nonce16):
    """HChaCha20: 32-byte subkey from key + 16-byte nonce."""
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state.extend(_key_words(key))
    state.extend(_nonce3_words(nonce16[:12]))
    state.append(_nonce3_words(nonce16[12:16] + b'\x00' * 8)[0])
    working = list(state)
    for _ in range(10):
        _quarter(working, 0, 4, 8, 12)
        _quarter(working, 1, 5, 9, 13)
        _quarter(working, 2, 6, 10, 14)
        _quarter(working, 3, 7, 11, 15)
        _quarter(working, 0, 5, 10, 15)
        _quarter(working, 1, 6, 11, 12)
        _quarter(working, 2, 7, 8, 13)
        _quarter(working, 3, 4, 9, 14)
    return struct.pack('<8I', working[0], working[1], working[2], working[3],
                       working[12], working[13], working[14], working[15])


def _xor_bytes(a, b):
    out = [_byte_at(a, i) ^ _byte_at(b, i) for i in range(len(a))]
    return _join_bytes(out)


def chacha20_xor(key, nonce12, counter, data, rounds):
    """XOR ``data`` with ChaCha20 keystream.  Returns (out, next_counter)."""
    data = _as_bytes(data)
    key_words = _key_words(key)
    nonce_words = _nonce3_words(nonce12)
    parts = []
    pos = 0
    length = len(data)
    while pos < length:
        block = _chacha_block(key_words, counter, nonce_words, rounds)
        chunk = data[pos:pos + 64]
        parts.append(_xor_bytes(chunk, block[:len(chunk)]))
        counter += 1
        pos += 64
    return b''.join(parts) if _IS_PY3 else ''.join(parts), counter


def xchacha20_chained_xor(key, nonce24, data, initial_hash, decrypt=False):
    """Chained, modified XChaCha20 XOR.

    Each variable-size block uses ChaCha20 with a hash-derived round count; the
    block size and round count for the next block are derived from CityHash64
    of the *plaintext* block just processed (the spec's "decrypted block"
    digest).  For a symmetric stream cipher the plaintext is the input when
    encrypting and the output when decrypting, hence the ``decrypt`` flag.
    """
    key = _as_bytes(key)
    nonce24 = _as_bytes(nonce24)
    data = _as_bytes(data)
    subkey = hchacha20(key, nonce24[:16])
    nonce12 = nonce24[16:24] + b'\x00\x00\x00\x00'
    counter = 0
    h = initial_hash & _M64
    rounds = 10 * (h % 3) + 10
    block_size = ((h & 0x3F) | 0x40) << 6
    parts = []
    pos = 0
    length = len(data)
    while pos < length:
        chunk = data[pos:pos + block_size]
        out, counter = chacha20_xor(subkey, nonce12, counter, chunk, rounds)
        parts.append(out)
        # chain on the plaintext block digest
        plain = out if decrypt else chunk
        h = cityhash64(plain, 0)
        rounds = 10 * (h % 3) + 10
        block_size = ((h & 0x3F) | 0x40) << 6
        pos += len(chunk)
    return b''.join(parts) if _IS_PY3 else ''.join(parts)


# ---- full payload pipeline ----


def _xor_head(data, key2):
    """XOR the first ``len(key2)`` bytes of ``data`` with ``key2``."""
    data = _as_bytes(data)
    key2 = _as_bytes(key2)
    out = [_byte_at(data, i) for i in range(len(data))]
    for i in range(min(len(key2), len(out))):
        out[i] = _byte_at(data, i) ^ _byte_at(key2, i)
    return _join_bytes(out)


def encrypt_payload(raw, key32, nonce24, banner=b'', compress_level=9):
    """Encrypt a byte payload with the full layered pipeline.

    ``banner`` (the watermark) is folded into both the MT19937 seed and the
    XChaCha20 chain init, so the payload cannot be decrypted with key+nonce
    alone.
    """
    import random
    raw = _as_bytes(raw)
    key32 = _as_bytes(key32)
    nonce24 = _as_bytes(nonce24)
    banner = _as_bytes(banner)
    compressed = zlib.compress(raw, compress_level)
    modified = _xor_head(compressed, key32[:2])
    pad_len = random.randint(0, 1023)
    padding = _join_bytes([random.randint(0, 255) for _ in range(pad_len)])
    padded = struct.pack('<H', pad_len) + padding + modified
    mt_seed = cityhash64(key32 + nonce24 + banner, _MT_SEED_CONST)
    mt_xored = mt19937_xor(padded, mt_seed)
    initial_hash = cityhash64(nonce24 + banner, 0)
    return xchacha20_chained_xor(key32, nonce24, mt_xored, initial_hash, decrypt=False)


def decrypt_payload(encrypted, key32, nonce24, banner=b''):
    """Reverse ``encrypt_payload``."""
    key32 = _as_bytes(key32)
    nonce24 = _as_bytes(nonce24)
    banner = _as_bytes(banner)
    mt_seed = cityhash64(key32 + nonce24 + banner, _MT_SEED_CONST)
    initial_hash = cityhash64(nonce24 + banner, 0)
    mt_xored = xchacha20_chained_xor(key32, nonce24, encrypted, initial_hash, decrypt=True)
    padded = mt19937_xor(mt_xored, mt_seed)
    pad_len = struct.unpack('<H', padded[:2])[0] & 0x3FF
    modified = padded[2 + pad_len:]
    compressed = _xor_head(modified, key32[:2])
    return zlib.decompress(compressed)
