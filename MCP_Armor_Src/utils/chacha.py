#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
import sys

# ChaCha8 常量
WQSWORD_CHACHA_KEY = "1234567890123456" + "\xa4\xcd\xf7\x6b\xf2\xde\x21\xf2\x51\x77\xfe\xee\x02\xd4\x84\xe6"
WQSWORD_CHACHA_TAIL = "\\x00\\x00\\x00\\x00163 NetEase\\n"
WQSWORD_CHACHA_SIGMA = "expand 32-byte k"


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    return value.encode('latin1')


def rotl32(value, shift):
    """32位循环左移"""
    value &= 0xFFFFFFFF
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))


def quarter_round(state, a, b, c, d):
    """ChaCha quarter round 操作"""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 7)


def chacha_crypt(data, key=WQSWORD_CHACHA_KEY, tail=WQSWORD_CHACHA_TAIL, rounds=8):
    """
    ChaCha 加密/解密函数
    
    参数:
        data: 要加密/解密的数据
        key: 32字节密钥
        tail: 12字节随机数(nonce)
        rounds: 轮数 (8, 12, 20)
    
    返回:
        加密/解密后的数据
    """
    # 初始化状态
    original_text = sys.version_info[0] >= 3 and isinstance(data, str)
    data = _as_bytes(data)
    key = _as_bytes(key)
    # Normalize variable UI keys to ChaCha's fixed 32-byte key and 16-byte
    # nonce fields. Repetition/truncation is deterministic across runtimes.
    if not key:
        key = _as_bytes(WQSWORD_CHACHA_KEY)
    if len(key) != 32:
        key = (key * ((32 + len(key) - 1) // len(key)))[:32]
    tail = _as_bytes(tail)
    if len(tail) != 16:
        tail = (tail * ((16 + len(tail) - 1) // len(tail)))[:16]
    sigma = _as_bytes(WQSWORD_CHACHA_SIGMA)
    state = list(struct.unpack("<4I", sigma))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", tail))
    
    out = []
    block = b''
    offset = 64
    
    for ch in data:
        if offset == 64:
            # 复制工作状态
            working = list(state)
            
            # 执行指定轮数的quarter rounds
            for _ in range(int(rounds) >> 1):
                # 列混合
                quarter_round(working, 0, 4, 8, 12)
                quarter_round(working, 1, 5, 9, 13)
                quarter_round(working, 2, 6, 10, 14)
                quarter_round(working, 3, 7, 11, 15)
                # 对角线混合
                quarter_round(working, 0, 5, 10, 15)
                quarter_round(working, 1, 6, 11, 12)
                quarter_round(working, 2, 7, 8, 13)
                quarter_round(working, 3, 4, 9, 14)
            
            # 混合结果
            mixed = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
            block = struct.pack("<16I", *mixed)
            
            # 增加计数器
            state[12] = (state[12] + 1) & 0xFFFFFFFF
            offset = 0
        
        # XOR操作
        left = ch if isinstance(ch, int) else ord(ch)
        right = block[offset] if isinstance(block[offset], int) else ord(block[offset])
        out.append(left ^ right)
        offset += 1
    
    if sys.version_info[0] < 3:
        result = ''.join(chr(value) for value in out)
    else:
        result = bytes(out)
    return result.decode('latin1') if original_text else result


def chacha8(data, key=WQSWORD_CHACHA_KEY, tail=WQSWORD_CHACHA_TAIL):
    """ChaCha8 快捷函数"""
    return chacha_crypt(data, key, tail, 8)


def chacha12(data, key=WQSWORD_CHACHA_KEY, tail=WQSWORD_CHACHA_TAIL):
    """ChaCha12 快捷函数"""
    return chacha_crypt(data, key, tail, 12)


def chacha20(data, key=WQSWORD_CHACHA_KEY, tail=WQSWORD_CHACHA_TAIL):
    """ChaCha20 快捷函数"""
    return chacha_crypt(data, key, tail, 20)\n