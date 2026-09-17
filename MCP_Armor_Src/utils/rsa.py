# -*- coding: utf-8 -*-
"""Small RSA-style helpers for loader payload key obfuscation.

These produce a real (p, q, n, e, d) key so the payload key is stored as a
modular-exponentiation residue instead of plaintext.  This is obfuscation-grade
cryptography: it raises the reversing bar, not a general-purpose cipher.
"""

import random

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                 59, 61, 67, 71, 73, 79, 83, 89, 97)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _egcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a, m):
    """Return ``a^-1 mod m`` via the extended Euclidean algorithm."""
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    return x % m


def is_probable_prime(n, rounds=12):
    if n < 2:
        return False
    for prime in _SMALL_PRIMES:
        if n % prime == 0:
            return n == prime
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    """Return a probable prime with the requested bit length."""
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def generate_key(bits=512):
    """Generate an RSA-style (n, e, d) triple."""
    p = random_prime(bits // 2)
    q = random_prime(bits // 2)
    while q == p:
        q = random_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while _gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return n, e, d
