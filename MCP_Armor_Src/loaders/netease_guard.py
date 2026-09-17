# -*- coding: utf-8 -*-
"""NetEase-native loader guards and behavior-pack UUID binding."""


import json
import os
import random

from MCP_Armor_Src.utils.encoding import byte_char, byte_value, random_ident, visual_int
from MCP_Armor_Src.utils.chacha import chacha8


def find_behavior_pack_uuid(start_path, max_depth=12):
    """Find the nearest ancestor manifest and return header.uuid."""
    current = os.path.abspath(start_path)
    if os.path.isfile(current):
        current = os.path.dirname(current)
    for _unused in range(max(1, int(max_depth))):
        manifest = os.path.join(current, 'manifest.json')
        if os.path.isfile(manifest):
            try:
                handle = open(manifest, 'rb')
                try:
                    raw = handle.read()
                finally:
                    handle.close()
                if raw.startswith('\xef\xbb\xbf'):
                    raw = raw[3:]
                data = json.loads(raw.decode('utf-8'))
                value = data.get('header', {}).get('uuid', '')
                value = str(value).strip().lower()
                if value:
                    return value, manifest
            except Exception:
                return None, manifest
        parent = os.path.dirname(current)
        if not parent or parent == current:
            break
        current = parent
    return None, None


def _encoded_bytes(value):
    seed = random.randint(1, 255)
    row = tuple(
        byte_value(ch) ^ ((seed + index * 131) & 255)
        for index, ch in enumerate(value)
    )
    return repr(row), seed


def _decode_call(name, value):
    row, seed = _encoded_bytes(value)
    return '%s(%s, %s)' % (name, row, visual_int(seed))


def build_netease_key_guard(module_name, key_name, key, manifest_uuid):
    """Generate a native _chacha and behavior-pack UUID key selector."""
    expected_uuid = str(manifest_uuid or '').strip().lower()
    if not expected_uuid:
        raise ValueError('anti_debug requires behavior-pack manifest header.uuid')

    names = {}
    for label in (
            'decode', 'guard', 'row', 'seed', 'index', 'value', 'module',
            'key', 'scope', 'builtin_type', 'attr', 'builtins', 'importer',
            'os_mod', 'json_mod',
            'sys_mod', 'starts', 'item', 'current', 'depth', 'seen',
            'manifest', 'handle', 'raw', 'data', 'actual', 'parent',
            'mixed', 'char', 'owner', 'owner_type', 'result', 'valid',
            'create_fn', 'get_fn', 'destroy_fn', 'probe_index'):
        names[label] = random_ident(label[:4])
    for label in (
            'path_mod', 'dirname_fn', 'abspath_fn', 'isfile_fn',
            'getcwd_fn', 'loads_fn', 'read_fn', 'close_fn',
            'startswith_fn', 'decode_fn', 'strip_fn', 'lower_fn',
            'map_get_fn'):
        names[label] = random_ident(label[:4])

    decode = names['decode']
    module_label = _decode_call(decode, '_chacha')
    create_label = _decode_call(decode, 'create')
    get_label = _decode_call(decode, 'get_encrypted_text')
    destroy_label = _decode_call(decode, 'destroy')
    file_label = _decode_call(decode, '__file__')
    manifest_label = _decode_call(decode, 'manifest.json')
    header_label = _decode_call(decode, 'header')
    uuid_label = _decode_call(decode, 'uuid')
    utf8_label = _decode_call(decode, 'utf-8')
    os_label = _decode_call(decode, 'os')
    json_label = _decode_call(decode, 'json')
    sys_label = _decode_call(decode, 'sys')
    import_label = _decode_call(decode, '__import__')
    name_label = _decode_call(decode, '__name__')
    code_label = _decode_call(decode, 'func_code')
    modern_code_label = _decode_call(decode, '__code__')
    path_label = _decode_call(decode, 'path')
    dirname_label = _decode_call(decode, 'dirname')
    abspath_label = _decode_call(decode, 'abspath')
    isfile_label = _decode_call(decode, 'isfile')
    getcwd_label = _decode_call(decode, 'getcwd')
    loads_label = _decode_call(decode, 'loads')
    read_label = _decode_call(decode, 'read')
    close_label = _decode_call(decode, 'close')
    startswith_label = _decode_call(decode, 'startswith')
    decode_label = _decode_call(decode, 'decode')
    strip_label = _decode_call(decode, 'strip')
    lower_label = _decode_call(decode, 'lower')
    map_get_label = _decode_call(decode, 'get')
    expected_label = _decode_call(decode, expected_uuid)
    probe_key = ''.join(byte_char(random.randint(0, 255)) for _unused in range(32))
    probe_data = ''.join(byte_char(random.randint(0, 255)) for _unused in range(
        random.randint(13, 31)))
    probe_expected = chacha8(probe_data, probe_key)
    probe_key_label = repr(probe_key)
    probe_data_label = repr(probe_data)
    probe_expected_label = repr(probe_expected)
    binding_seed = random.randint(1, 255)
    stored_key = ''.join(
        byte_char(byte_value(char) ^ ((byte_value(expected_uuid[index % len(expected_uuid)]) +
                          binding_seed + index * 41) & 255))
        for index, char in enumerate(key)
    )
    scramble_seed = random.randint(1, 255)

    source = r'''def %(decode)s(%(row)s, %(seed)s):
    return ''.join(chr(%(value)s ^ ((%(seed)s + %(index)s * 131) & 255)) for %(index)s, %(value)s in enumerate(%(row)s))

def %(guard)s(%(module)s, %(key)s, %(scope)s):
    %(builtin_type)s = type(len)
    try:
        if getattr(%(module)s, %(name_label)s, None) != %(module_label)s:
            raise ValueError
        %(create_fn)s = getattr(%(module)s, %(create_label)s, None)
        %(get_fn)s = getattr(%(module)s, %(get_label)s, None)
        %(destroy_fn)s = getattr(%(module)s, %(destroy_label)s, None)
        for %(attr)s in (%(create_fn)s, %(get_fn)s, %(destroy_fn)s):
            if not isinstance(%(attr)s, %(builtin_type)s):
                raise ValueError
            if getattr(%(attr)s, %(code_label)s, None) is not None:
                raise ValueError
            if getattr(%(attr)s, %(modern_code_label)s, None) is not None:
                raise ValueError
        %(owner_type)s = type(%(module_label)s, (object,), {})
        %(owner)s = %(owner_type)s()
        %(handle)s = %(create_fn)s(%(owner)s, 8, %(probe_key)s)
        try:
            %(result)s = %(get_fn)s(%(handle)s, %(probe_data)s, len(%(probe_data)s))
        finally:
            %(destroy_fn)s(%(handle)s)
        %(valid)s = isinstance(%(result)s, str) and len(%(result)s) == len(%(probe_expected)s)
        if %(valid)s:
            for %(probe_index)s in xrange(len(%(probe_expected)s)):
                %(valid)s = %(valid)s and (ord(%(result)s[%(probe_index)s]) == ord(%(probe_expected)s[%(probe_index)s]))
        if not %(valid)s:
            raise ValueError
        %(builtins)s = __builtins__
        if isinstance(%(builtins)s, dict):
            %(importer)s = %(builtins)s[%(import_label)s]
        else:
            %(importer)s = getattr(%(builtins)s, %(import_label)s)
        %(os_mod)s = %(importer)s(%(os_label)s)
        %(json_mod)s = %(importer)s(%(json_label)s)
        %(sys_mod)s = %(importer)s(%(sys_label)s)
        %(path_mod)s = getattr(%(os_mod)s, %(path_label)s)
        %(dirname_fn)s = getattr(%(path_mod)s, %(dirname_label)s)
        %(abspath_fn)s = getattr(%(path_mod)s, %(abspath_label)s)
        %(isfile_fn)s = getattr(%(path_mod)s, %(isfile_label)s)
        %(getcwd_fn)s = getattr(%(os_mod)s, %(getcwd_label)s)
        %(loads_fn)s = getattr(%(json_mod)s, %(loads_label)s)
        %(map_get_fn)s = getattr(%(scope)s, %(map_get_label)s)
        %(starts)s = []
        %(item)s = %(map_get_fn)s(%(file_label)s)
        if %(item)s:
            %(starts)s.append(%(dirname_fn)s(%(abspath_fn)s(%(item)s)))
        try:
            %(starts)s.append(%(getcwd_fn)s())
        except Exception:
            pass
        for %(item)s in getattr(%(sys_mod)s, %(path_label)s, ()):
            if isinstance(%(item)s, str) and %(item)s:
                %(starts)s.append(%(item)s)
        %(seen)s = set()
        for %(item)s in %(starts)s:
            %(current)s = %(abspath_fn)s(%(item)s)
            for %(depth)s in xrange(12):
                if %(current)s in %(seen)s:
                    break
                %(seen)s.add(%(current)s)
                %(manifest)s = getattr(%(path_mod)s, %(join_label)s)(%(current)s, %(manifest_label)s)
                if %(isfile_fn)s(%(manifest)s):
                    %(handle)s = open(%(manifest)s, 'rb')
                    try:
                        %(read_fn)s = getattr(%(handle)s, %(read_label)s)
                        %(raw)s = %(read_fn)s()
                    finally:
                        %(close_fn)s = getattr(%(handle)s, %(close_label)s)
                        %(close_fn)s()
                    %(startswith_fn)s = getattr(%(raw)s, %(startswith_label)s)
                    if %(startswith_fn)s('\xef\xbb\xbf'):
                        %(raw)s = %(raw)s[3:]
                    %(decode_fn)s = getattr(%(raw)s, %(decode_label)s)
                    %(data)s = %(loads_fn)s(%(decode_fn)s(%(utf8_label)s))
                    %(actual)s = getattr(%(data)s, %(map_get_label)s)(%(header_label)s, {})
                    %(actual)s = getattr(%(actual)s, %(map_get_label)s)(%(uuid_label)s, '')
                    %(actual)s = str(%(actual)s)
                    %(strip_fn)s = getattr(%(actual)s, %(strip_label)s)
                    %(actual)s = %(strip_fn)s()
                    %(lower_fn)s = getattr(%(actual)s, %(lower_label)s)
                    %(actual)s = %(lower_fn)s()
                    if %(actual)s == %(expected_label)s:
                        %(mixed)s = []
                        for %(index)s, %(char)s in enumerate(%(key)s):
                            %(mixed)s.append(chr(ord(%(char)s) ^ ((ord(%(actual)s[%(index)s %% len(%(actual)s)]) + %(binding_seed)s + %(index)s * 41) & 255)))
                        return ''.join(%(mixed)s)
                %(parent)s = %(dirname_fn)s(%(current)s)
                if not %(parent)s or %(parent)s == %(current)s:
                    break
                %(current)s = %(parent)s
    except Exception:
        pass
    %(mixed)s = []
    for %(index)s, %(char)s in enumerate(%(key)s):
        %(mixed)s.append(chr(ord(%(char)s) ^ ((%(scramble_seed)s + %(index)s * 73) & 255)))
    return ''.join(%(mixed)s)

%(key_name)s = %(guard)s(%(module_name)s, %(key_repr)s, globals())
''' % dict(names,
           module_label=module_label, create_label=create_label,
           get_label=get_label, destroy_label=destroy_label,
           file_label=file_label, manifest_label=manifest_label,
           header_label=header_label, uuid_label=uuid_label,
           utf8_label=utf8_label, os_label=os_label,
           json_label=json_label, sys_label=sys_label,
           import_label=import_label, name_label=name_label,
           code_label=code_label, modern_code_label=modern_code_label,
           path_label=path_label, dirname_label=dirname_label,
           abspath_label=abspath_label, isfile_label=isfile_label,
           getcwd_label=getcwd_label, loads_label=loads_label,
           read_label=read_label, close_label=close_label,
           startswith_label=startswith_label, decode_label=decode_label,
           strip_label=strip_label, lower_label=lower_label,
           map_get_label=map_get_label,
           join_label=_decode_call(decode, 'join'),
           probe_key=probe_key_label, probe_data=probe_data_label,
           probe_expected=probe_expected_label,
           expected_label=expected_label,
           binding_seed=visual_int(binding_seed),
           scramble_seed=visual_int(scramble_seed), key_name=key_name,
           module_name=module_name, key_repr=repr(stored_key))
    return source
