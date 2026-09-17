# -*- coding: utf-8 -*-
"""Build the optional one-shot loader anti-debug and anti-tamper guard."""


import hashlib
import hmac
import random

from MCP_Armor_Src.utils.encoding import byte_char, byte_value, random_bytes, random_ident, visual_int


DEBUG_MODULES = (
    'pdb', 'bdb', 'pydevd', 'debugpy', '_pydevd_bundle',
    'frida', 'winpdb', 'rpdb',
)


def _encoded_bytes(value):
    seed = random.randint(1, 255)
    row = tuple(
        byte_value(ch) ^ ((seed + (index * 131)) & 255)
        for index, ch in enumerate(value)
    )
    return repr(row), seed


def _encoded_pair(value):
    row, seed = _encoded_bytes(value)
    return '(%s, %s)' % (row, visual_int(seed))


def _digest(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def empty_anti_debug_parts():
    return {
        'anti_debug_top_code': '',
        'anti_debug_pre_code': '',
        'anti_debug_raw_code': '',
        'anti_debug_code_code': '',
    }


def build_anti_debug_parts(encoded, raw, enabled=False, code_guard=False,
                           data_name=None, raw_name=None, code_name=None):
    """Return generated guard source fragments for one loader payload."""
    if not enabled:
        return empty_anti_debug_parts()

    names = {}
    for label in (
            'failure', 'decode', 'importer', 'constant_equal', 'mac',
            'precheck', 'rawcheck', 'codecheck', 'builtins', 'import_func',
            'row', 'seed', 'index', 'value', 'left', 'right', 'delta',
            'hashlib_mod', 'hmac_mod', 'sys_mod', 'time_mod', 'getter',
            'attr', 'modules', 'module_row', 'module_seed', 'frame_getter',
            'frame', 'depth', 'clock', 'started', 'elapsed', 'state',
            'sentinel', 'data', 'raw', 'token', 'key', 'expected',
            'actual', 'code', 'code_type', 'queue', 'item', 'const',
            'count'):
        names[label] = random_ident(label[:4])

    import_pair = _encoded_pair('__import__')
    hashlib_pair = _encoded_pair('hashlib')
    hmac_pair = _encoded_pair('hmac')
    sys_pair = _encoded_pair('sys')
    time_pair = _encoded_pair('time')
    trace_pairs = ', '.join((
        _encoded_pair('gettrace'), _encoded_pair('getprofile')))
    frame_pair = _encoded_pair('_getframe')
    frame_trace_pair = _encoded_pair('f_trace')
    frame_back_pair = _encoded_pair('f_back')
    modules_pair = _encoded_pair('modules')
    time_func_pair = _encoded_pair('time')
    debug_pairs = ', '.join(_encoded_pair(name) for name in DEBUG_MODULES)

    cipher_key = random_bytes(24)
    raw_key = random_bytes(24)
    cipher_tag = _digest(cipher_key, encoded)
    raw_tag = _digest(raw_key, raw)
    cipher_key_pair = _encoded_pair(cipher_key)
    raw_key_pair = _encoded_pair(raw_key)
    cipher_tag_pair = _encoded_pair(cipher_tag)
    raw_tag_pair = _encoded_pair(raw_tag)

    timing_seed = random.randint(1, 0x7fffffff)
    timing_mul = random.randint(0x10001, 0x7fffffff) | 1
    timing_bias = random.randint(1, 0x7fffffff)
    timing_rounds = random.randint(96, 160)
    timing_expected = timing_seed
    for index in range(timing_rounds):
        timing_expected = (
            ((timing_expected ^ (index * 0x45D9F3B)) * timing_mul) +
            timing_bias
        ) & 0x7fffffff

    token_seed = random.randint(1, 0x7fffffff)
    token_mul = random.randint(0x10001, 0x7fffffff) | 1
    token_bias = random.randint(1, 0x7fffffff)
    cipher_token = (
        ((len(encoded) ^ token_seed) * token_mul) + token_bias
    ) & 0x7fffffff
    raw_token_seed = random.randint(1, 0x7fffffff)
    raw_token_mul = random.randint(0x10001, 0x7fffffff) | 1
    raw_token_bias = random.randint(1, 0x7fffffff)
    code_token = (
        ((cipher_token ^ len(raw) ^ raw_token_seed) * raw_token_mul) +
        raw_token_bias
    ) & 0x7fffffff

    failure_label = random_ident('guard')
    top_code = r'''class %(failure)s(RuntimeError):
    pass

def %(decode)s(%(row)s, %(seed)s):
    return ''.join(chr(%(value)s ^ ((%(seed)s + (%(index)s * 131)) & 255)) for %(index)s, %(value)s in enumerate(%(row)s))

def %(importer)s(%(row)s, %(seed)s):
    %(builtins)s = __builtins__
    if isinstance(%(builtins)s, dict):
        %(import_func)s = %(builtins)s[%(decode)s%(import_pair)s]
    else:
        %(import_func)s = getattr(%(builtins)s, %(decode)s%(import_pair)s)
    return %(import_func)s(%(decode)s(%(row)s, %(seed)s))

def %(constant_equal)s(%(left)s, %(right)s):
    if len(%(left)s) != len(%(right)s):
        return False
    %(delta)s = 0
    for %(index)s in xrange(len(%(left)s)):
        %(delta)s |= ord(%(left)s[%(index)s]) ^ ord(%(right)s[%(index)s])
    return %(delta)s == 0

def %(mac)s(%(data)s, %(key)s):
    %(hashlib_mod)s = %(importer)s%(hashlib_pair)s
    %(hmac_mod)s = %(importer)s%(hmac_pair)s
    return %(hmac_mod)s.new(%(key)s, %(data)s, %(hashlib_mod)s.sha256).digest()

def %(precheck)s(%(data)s):
    %(sys_mod)s = %(importer)s%(sys_pair)s
    for %(row)s, %(seed)s in (%(trace_pairs)s,):
        %(getter)s = getattr(%(sys_mod)s, %(decode)s(%(row)s, %(seed)s), None)
        if callable(%(getter)s) and %(getter)s() is not None:
            raise %(failure)s()
    %(frame_getter)s = getattr(%(sys_mod)s, %(decode)s%(frame_pair)s, None)
    if callable(%(frame_getter)s):
        %(frame)s = %(frame_getter)s()
        %(depth)s = 0
        while %(frame)s is not None and %(depth)s < 32:
            if getattr(%(frame)s, %(decode)s%(frame_trace_pair)s, None) is not None:
                raise %(failure)s()
            %(frame)s = getattr(%(frame)s, %(decode)s%(frame_back_pair)s, None)
            %(depth)s += 1
    %(modules)s = getattr(%(sys_mod)s, %(decode)s%(modules_pair)s, {})
    for %(module_row)s, %(module_seed)s in (%(debug_pairs)s,):
        if %(decode)s(%(module_row)s, %(module_seed)s) in %(modules)s:
            raise %(failure)s()
    %(time_mod)s = %(importer)s%(time_pair)s
    %(clock)s = getattr(%(time_mod)s, %(decode)s%(time_func_pair)s, None)
    %(started)s = %(clock)s() if callable(%(clock)s) else None
    %(state)s = %(timing_seed)s
    for %(index)s in xrange(%(timing_rounds)s):
        %(state)s = (((%(state)s ^ (%(index)s * 0x45D9F3B)) * %(timing_mul)s) + %(timing_bias)s) & 0x7fffffff
    if %(state)s != %(timing_expected)s:
        raise %(failure)s()
    if %(started)s is not None:
        %(elapsed)s = %(clock)s() - %(started)s
        if %(elapsed)s > 2.0:
            raise %(failure)s()
    try:
        raise %(failure)s()
    except %(failure)s:
        pass
    %(key)s = %(decode)s%(cipher_key_pair)s
    %(expected)s = %(decode)s%(cipher_tag_pair)s
    %(actual)s = %(mac)s(%(data)s, %(key)s)
    if not %(constant_equal)s(%(actual)s, %(expected)s):
        raise %(failure)s()
    %(token)s = (((len(%(data)s) ^ %(token_seed)s) * %(token_mul)s) + %(token_bias)s) & 0x7fffffff
    return %(token)s

def %(rawcheck)s(%(raw)s, %(token)s):
    if %(token)s != %(cipher_token)s:
        raise %(failure)s()
    %(key)s = %(decode)s%(raw_key_pair)s
    %(expected)s = %(decode)s%(raw_tag_pair)s
    %(actual)s = %(mac)s(%(raw)s, %(key)s)
    if not %(constant_equal)s(%(actual)s, %(expected)s):
        raise %(failure)s()
    return (((%(token)s ^ len(%(raw)s) ^ %(raw_token_seed)s) * %(raw_token_mul)s) + %(raw_token_bias)s) & 0x7fffffff

def %(codecheck)s(%(code)s, %(token)s):
    if %(token)s != %(code_token)s:
        raise %(failure)s()
    %(code_type)s = (lambda: None).func_code.__class__
    if not isinstance(%(code)s, %(code_type)s) or %(code)s.co_freevars:
        raise %(failure)s()
    %(queue)s = [%(code)s]
    %(count)s = 0
    while %(queue)s:
        %(item)s = %(queue)s.pop()
        if (not isinstance(%(item)s.co_code, str) or %(item)s.co_argcount < 0 or
                %(item)s.co_nlocals < %(item)s.co_argcount or
                len(%(item)s.co_varnames) < %(item)s.co_nlocals):
            raise %(failure)s()
        %(count)s += 1
        if %(count)s > 4096:
            raise %(failure)s()
        for %(const)s in %(item)s.co_consts:
            if isinstance(%(const)s, %(code_type)s):
                %(queue)s.append(%(const)s)
    return %(token)s
''' % dict(names,
           import_pair=import_pair, hashlib_pair=hashlib_pair,
           hmac_pair=hmac_pair, sys_pair=sys_pair, time_pair=time_pair,
           trace_pairs=trace_pairs, frame_pair=frame_pair,
           frame_trace_pair=frame_trace_pair, frame_back_pair=frame_back_pair,
           modules_pair=modules_pair, time_func_pair=time_func_pair,
           debug_pairs=debug_pairs, timing_seed=visual_int(timing_seed),
           timing_mul=visual_int(timing_mul), timing_bias=visual_int(timing_bias),
           timing_rounds=visual_int(timing_rounds),
           timing_expected=visual_int(timing_expected),
           cipher_key_pair=cipher_key_pair, cipher_tag_pair=cipher_tag_pair,
           raw_key_pair=raw_key_pair, raw_tag_pair=raw_tag_pair,
           token_seed=visual_int(token_seed), token_mul=visual_int(token_mul),
           token_bias=visual_int(token_bias),
           cipher_token=visual_int(cipher_token),
           raw_token_seed=visual_int(raw_token_seed),
           raw_token_mul=visual_int(raw_token_mul),
           raw_token_bias=visual_int(raw_token_bias),
           code_token=visual_int(code_token), failure_label=failure_label)

    pre_code = '    %s = %s(%s)' % (
        names['token'], names['precheck'], data_name or names['data'])
    raw_code = '    %s = %s(%s, %s)' % (
        names['token'], names['rawcheck'], raw_name or names['raw'],
        names['token'])
    code_code = ''
    if code_guard:
        code_code = '    %s = %s(%s, %s)' % (
            names['token'], names['codecheck'], code_name or names['code'],
            names['token'])

    return {
        'anti_debug_top_code': top_code,
        'anti_debug_pre_code': pre_code,
        'anti_debug_raw_code': raw_code,
        'anti_debug_code_code': code_code,
    }
