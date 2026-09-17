# -*- coding: utf-8 -*-
"""Generated py2.7 runtime source for the layered payload crypto.

All identifiers are ``_mcp_``-prefixed so the loader's final
``obfuscate_reserved_generated_identifiers`` pass renames them consistently.
"""

CRYPTO_RUNTIME_SOURCE = r'''
_mcp_st = __import__('struct')
_mcp_zl = __import__('zlib')

def _mcp_ca(a, b): return (a + b) & 0xFFFFFFFFFFFFFFFF
def _mcp_cs(a, b): return (a - b) & 0xFFFFFFFFFFFFFFFF
def _mcp_cm(a, b): return (a * b) & 0xFFFFFFFFFFFFFFFF
def _mcp_cr(x, n):
    x &= 0xFFFFFFFFFFFFFFFF
    if n == 0: return x
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF
def _mcp_cb(x):
    x &= 0xFFFFFFFFFFFFFFFF
    return (((x & 0xFF) << 56) | ((x & 0xFF00) << 40) | ((x & 0xFF0000) << 24) |
            ((x & 0xFF000000) << 8) | ((x & 0xFF00000000) >> 8) |
            ((x & 0xFF0000000000) >> 24) | ((x & 0xFF000000000000) >> 40) |
            ((x & 0xFF00000000000000) >> 56)) & 0xFFFFFFFFFFFFFFFF
def _mcp_cf64(d, i): return _mcp_st.unpack('<Q', d[i:i + 8])[0] & 0xFFFFFFFFFFFFFFFF
def _mcp_cf32(d, i): return _mcp_st.unpack('<I', d[i:i + 4])[0]
def _mcp_cba(d, i): return ord(d[i])

_mcp_ck0 = 0xc3a5c85c97cb3127
_mcp_ck1 = 0xb492b66fbe98f273
_mcp_ck2 = 0x9ae16a3b2f90404f
_mcp_ckm = 0x9ddfea08eb382d69

def _mcp_csm(x): return (x ^ (x >> 47)) & 0xFFFFFFFFFFFFFFFF
def _mcp_ch128(u, v):
    a = _mcp_cm(u ^ v, _mcp_ckm)
    a ^= (a >> 47)
    b = _mcp_cm(v ^ a, _mcp_ckm)
    b ^= (b >> 47)
    return _mcp_cm(b, _mcp_ckm)
def _mcp_chl16(u, v): return _mcp_ch128(u & 0xFFFFFFFFFFFFFFFF, v & 0xFFFFFFFFFFFFFFFF)
def _mcp_chl16m(u, v, m):
    a = _mcp_cm(u ^ v, m)
    a ^= (a >> 47)
    b = _mcp_cm(v ^ a, m)
    b ^= (b >> 47)
    return _mcp_cm(b, m)
def _mcp_ch0to16(d, n):
    if n >= 8:
        m = _mcp_ca(_mcp_ck2, n * 2)
        a = _mcp_ca(_mcp_cf64(d, 0), _mcp_ck2)
        b = _mcp_cf64(d, n - 8)
        c = _mcp_ca(_mcp_cm(_mcp_cr(b, 37), m), a)
        e = _mcp_cm(_mcp_ca(_mcp_cr(a, 25), b), m)
        return _mcp_chl16m(c, e, m)
    if n >= 4:
        m = _mcp_ca(_mcp_ck2, n * 2)
        a = _mcp_cf32(d, 0)
        return _mcp_chl16m(_mcp_ca(n, a << 3), _mcp_cf32(d, n - 4), m)
    if n > 0:
        a = _mcp_cba(d, 0)
        b = _mcp_cba(d, n >> 1)
        c = _mcp_cba(d, n - 1)
        y = a + (b << 8)
        z = n + (c << 2)
        return _mcp_cm(_mcp_csm(_mcp_cm(y, _mcp_ck2) ^ _mcp_cm(z, _mcp_ck0)), _mcp_ck2)
    return _mcp_ck2
def _mcp_ch17to32(d, n):
    m = _mcp_ca(_mcp_ck2, n * 2)
    a = _mcp_cm(_mcp_cf64(d, 0), _mcp_ck1)
    b = _mcp_cf64(d, 8)
    c = _mcp_cm(_mcp_cf64(d, n - 8), m)
    e = _mcp_cm(_mcp_cf64(d, n - 16), _mcp_ck2)
    return _mcp_chl16m(
        _mcp_ca(_mcp_ca(_mcp_cr(a + b, 43), _mcp_cr(c, 30)), e),
        _mcp_ca(_mcp_ca(a, _mcp_cr(_mcp_ca(b, _mcp_ck2), 18)), c), m)
def _mcp_ch33to64(d, n):
    m = _mcp_ca(_mcp_ck2, n * 2)
    a = _mcp_cm(_mcp_cf64(d, 0), _mcp_ck2)
    b = _mcp_cf64(d, 8)
    c = _mcp_cf64(d, n - 24)
    e = _mcp_cf64(d, n - 32)
    f = _mcp_cm(_mcp_cf64(d, 16), _mcp_ck2)
    g = _mcp_cm(_mcp_cf64(d, 24), 9)
    h = _mcp_cf64(d, n - 8)
    i = _mcp_cm(_mcp_cf64(d, n - 16), m)
    u = _mcp_ca(_mcp_cr(a + h, 43), _mcp_cm(_mcp_ca(_mcp_cr(b, 30), c), 9))
    v = _mcp_ca(_mcp_ca((a + h) ^ e, g), 1)
    w = _mcp_ca(_mcp_cb(_mcp_cm(u + v, m)), i)
    x = _mcp_ca(_mcp_cr(f + g, 42), c)
    y = _mcp_cm(_mcp_ca(_mcp_cb(_mcp_cm(v + w, m)), h), m)
    z = _mcp_ca(_mcp_ca(f, g), c)
    a = _mcp_ca(_mcp_cb(_mcp_ca(_mcp_cm(x + z, m), y)), b)
    b = _mcp_cm(_mcp_csm(_mcp_ca(_mcp_cm(z + a, m), _mcp_ca(e, i))), m)
    return _mcp_ca(b, x)
def _mcp_cwh(w, x, y, z, a, b):
    a = _mcp_ca(a, w)
    b = _mcp_cr(_mcp_ca(_mcp_ca(b, a), z), 21)
    c = a
    a = _mcp_ca(_mcp_ca(a, x), y)
    b = _mcp_ca(b, _mcp_cr(a, 44))
    return _mcp_ca(a, z), _mcp_ca(b, c)
def _mcp_cwhs(d, a, b):
    return _mcp_cwh(_mcp_cf64(d, 0), _mcp_cf64(d, 8), _mcp_cf64(d, 16), _mcp_cf64(d, 24), a, b)
def _mcp_city(d):
    n = len(d)
    if n <= 32:
        return _mcp_ch0to16(d, n) if n <= 16 else _mcp_ch17to32(d, n)
    if n <= 64:
        return _mcp_ch33to64(d, n)
    x = _mcp_cf64(d, n - 40)
    y = _mcp_ca(_mcp_cf64(d, n - 16), _mcp_cf64(d, n - 56))
    z = _mcp_chl16(_mcp_ca(_mcp_cf64(d, n - 48), n), _mcp_cf64(d, n - 24))
    v0, v1 = _mcp_cwhs(d[n - 64:], n, z)
    w0, w1 = _mcp_cwhs(d[n - 32:], _mcp_ca(y, _mcp_ck1), x)
    x = _mcp_ca(_mcp_cm(x, _mcp_ck1), _mcp_cf64(d, 0))
    r = (n - 1) & ~63
    p = 0
    while r:
        x = _mcp_cm(_mcp_cr(_mcp_ca(_mcp_ca(_mcp_ca(x, y), v0), _mcp_cf64(d, p + 8)), 37), _mcp_ck1)
        y = _mcp_cm(_mcp_cr(_mcp_ca(_mcp_ca(y, v1), _mcp_cf64(d, p + 48)), 42), _mcp_ck1)
        x ^= w1
        y = _mcp_ca(_mcp_ca(y, v0), _mcp_cf64(d, p + 40))
        z = _mcp_cm(_mcp_cr(_mcp_ca(z, w0), 33), _mcp_ck1)
        v0, v1 = _mcp_cwhs(d[p:], _mcp_cm(v1, _mcp_ck1), _mcp_ca(x, w0))
        w0, w1 = _mcp_cwhs(d[p + 32:], _mcp_ca(z, w1), _mcp_ca(y, _mcp_cf64(d, p + 16)))
        z, x = x, z
        p += 64
        r -= 64
    return _mcp_chl16(
        _mcp_ca(_mcp_ca(_mcp_chl16(v0, w0), _mcp_cm(_mcp_csm(y), _mcp_ck1)), z),
        _mcp_ca(_mcp_chl16(v1, w1), x))
def _mcp_cityseed(d, s):
    return _mcp_chl16(_mcp_cs(_mcp_city(d), _mcp_ck2), s & 0xFFFFFFFFFFFFFFFF)

def _mcp_mt_ctor(seed):
    st = [0] * 312
    st[0] = seed & 0xFFFFFFFFFFFFFFFF
    for i in range(1, 312):
        st[i] = (6364136223846793005 * (st[i - 1] ^ (st[i - 1] >> 62)) + i) & 0xFFFFFFFFFFFFFFFF
    return [st, 312]
def _mcp_mt_twist(st):
    for i in range(312):
        x = (st[0][i] & 0xFFFFFFFF80000000) | (st[0][(i + 1) % 312] & 0x7FFFFFFF)
        xa = x >> 1
        if x & 1: xa ^= 0xB5026F5AA96619E9
        st[0][i] = st[0][(i + 156) % 312] ^ xa
    st[1] = 0
def _mcp_mt_next(st):
    if st[1] >= 312: _mcp_mt_twist(st)
    y = st[0][st[1]]
    st[1] += 1
    y ^= (y >> 29) & 0x5555555555555555
    y ^= (y << 17) & 0x71D67FFFEDA60000
    y ^= (y << 37) & 0xFFF7EEE000000000
    y ^= y >> 43
    return y & 0xFFFFFFFFFFFFFFFF
def _mcp_mtxor(d, seed):
    st = _mcp_mt_ctor(seed)
    out = []
    p = 0
    n = len(d)
    while p < n:
        w = _mcp_mt_next(st)
        blk = _mcp_st.pack('<Q', w)
        for i in range(8):
            if p >= n: break
            out.append(chr(ord(d[p]) ^ ord(blk[i])))
            p += 1
    return ''.join(out)

def _mcp_qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = ((s[d] ^ s[a]) << 16 | (s[d] ^ s[a]) >> 16) & 0xFFFFFFFF
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = ((s[b] ^ s[c]) << 12 | (s[b] ^ s[c]) >> 20) & 0xFFFFFFFF
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = ((s[d] ^ s[a]) << 8 | (s[d] ^ s[a]) >> 24) & 0xFFFFFFFF
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = ((s[b] ^ s[c]) << 7 | (s[b] ^ s[c]) >> 25) & 0xFFFFFFFF
def _mcp_cblk(kw, ctr, nw, rnd):
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + kw + [ctr & 0xFFFFFFFF] + nw
    w = list(s)
    for _ in range(rnd // 2):
        _mcp_qr(w, 0, 4, 8, 12); _mcp_qr(w, 1, 5, 9, 13)
        _mcp_qr(w, 2, 6, 10, 14); _mcp_qr(w, 3, 7, 11, 15)
        _mcp_qr(w, 0, 5, 10, 15); _mcp_qr(w, 1, 6, 11, 12)
        _mcp_qr(w, 2, 7, 8, 13); _mcp_qr(w, 3, 4, 9, 14)
    for i in range(16):
        w[i] = (w[i] + s[i]) & 0xFFFFFFFF
    return _mcp_st.pack('<16I', *w)
def _mcp_kw(k): return list(_mcp_st.unpack('<8I', k))
def _mcp_nw(n12): return list(_mcp_st.unpack('<3I', n12))
def _mcp_hchacha(k, n16):
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + _mcp_kw(k) + _mcp_nw(n16[:12])
    s.append(_mcp_st.unpack('<I', n16[12:16])[0])
    w = list(s)
    for _ in range(10):
        _mcp_qr(w, 0, 4, 8, 12); _mcp_qr(w, 1, 5, 9, 13)
        _mcp_qr(w, 2, 6, 10, 14); _mcp_qr(w, 3, 7, 11, 15)
        _mcp_qr(w, 0, 5, 10, 15); _mcp_qr(w, 1, 6, 11, 12)
        _mcp_qr(w, 2, 7, 8, 13); _mcp_qr(w, 3, 4, 9, 14)
    return _mcp_st.pack('<8I', w[0], w[1], w[2], w[3], w[12], w[13], w[14], w[15])
def _mcp_cxor(k, n12, ctr, d, rnd):
    kw = _mcp_kw(k); nw = _mcp_nw(n12)
    out = []; p = 0; n = len(d)
    while p < n:
        blk = _mcp_cblk(kw, ctr, nw, rnd)
        ch = d[p:p + 64]
        out.append(''.join(chr(ord(ch[i]) ^ ord(blk[i])) for i in range(len(ch))))
        ctr += 1; p += 64
    return ''.join(out), ctr
def _mcp_chained(k, n24, d, h0):
    sk = _mcp_hchacha(k, n24[:16])
    n12 = n24[16:24] + '\x00\x00\x00\x00'
    ctr = 0
    h = h0 & 0xFFFFFFFFFFFFFFFF
    rnd = 10 * (h % 3) + 10
    bs = ((h & 0x3F) | 0x40) << 6
    out = []; p = 0; n = len(d)
    while p < n:
        ch = d[p:p + bs]
        enc, ctr = _mcp_cxor(sk, n12, ctr, ch, rnd)
        out.append(enc)
        h = _mcp_cityseed(enc, 0)
        rnd = 10 * (h % 3) + 10
        bs = ((h & 0x3F) | 0x40) << 6
        p += len(ch)
    return ''.join(out)

def _mcp_ts(t):
    if isinstance(t, tuple):
        return ''.join(chr(v & 255) for v in t)
    return t

def _mcp_xor(d, k):
    return ''.join(chr(ord(d[i]) ^ ord(k[i % len(k)])) for i in range(len(d)))

def _mcp_glue(a, b):
    out = []
    for i in range(len(b)):
        out.append(a[i]); out.append(b[i])
    if len(a) > len(b):
        out.append(a[len(b)])
    return ''.join(out)

_mcp_fA = '__MCP_FA_PH__'
_mcp_kA = '__MCP_KA_PH__'

def _mcp_wm_a():
    return _mcp_xor(_mcp_ts(_mcp_fA), _mcp_ts(_mcp_kA))

def _mcp_wm_b1():
    return _mcp_xor(_mcp_ts(_mcp_d0()), _mcp_ts(_mcp_d2()))

def _mcp_wm_b2():
    return _mcp_xor(_mcp_ts(_mcp_d1()), _mcp_ts(_mcp_d3()))

def _mcp_decrypt(enc, k32, n24):
    k32 = _mcp_ts(k32)
    n24 = _mcp_ts(n24)
    partA = _mcp_wm_a()
    partB = _mcp_wm_b1() + _mcp_wm_b2()
    banner = _mcp_glue(partA, partB)
    mtseed = _mcp_cityseed(k32 + n24 + banner, 0xD017CBBA7B5D3581)
    h0 = _mcp_cityseed(n24 + banner, 0)
    mtx = _mcp_chained(k32, n24, enc, h0)
    padded = _mcp_mtxor(mtx, mtseed)
    n = _mcp_st.unpack('<H', padded[:2])[0] & 0x3FF
    mod = padded[2 + n:]
    head = [_mcp_cba(mod, i) for i in range(len(mod))]
    for i in range(min(2, len(head))):
        head[i] = _mcp_cba(mod, i) ^ _mcp_cba(k32, i)
    return _mcp_zl.decompress(''.join(chr(v) for v in head))

def _mcp_fake0(x):
    # FNV-1a-like mixing (decoy: looks like a hash, result is discarded)
    x = _mcp_ts(x)
    h = 0xcbf29ce484222325
    for i in range(len(x)):
        h = ((h ^ ord(x[i])) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

def _mcp_fake1(x, k):
    # stream XOR with position term (decoy: looks like a cipher, discarded)
    x = _mcp_ts(x)
    k = _mcp_ts(k)
    return ''.join(chr(ord(x[i]) ^ ord(k[i % len(k)]) ^ (i & 255)) for i in range(len(x)))

def _mcp_fake2(k, n):
    # multiplicative key mixer (decoy: looks like key derivation, discarded)
    k = _mcp_ts(k)
    n = _mcp_ts(n)
    h = 0x9ae16a3b2f90404f
    for c in k + n:
        h = ((h ^ ord(c)) * 0x9ddfea08eb382d69) & 0xFFFFFFFFFFFFFFFF
    return h ^ 0x5A5A5A5A5A5A5A5A

def _mcp_fake3(seed):
    # LCG step (decoy: looks like a PRNG, discarded)
    return (seed * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF

def _mcp_fake4(x):
    # 32-bit FNV-1a checksum (decoy: looks like a hash, discarded)
    x = _mcp_ts(x)
    s = 0x811c9dc5
    for i in range(len(x)):
        s = ((s * 0x01000193) ^ ord(x[i])) & 0xFFFFFFFF
    return s
'''
