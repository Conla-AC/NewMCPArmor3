#!/usr/bin/env python2
# -*- coding: utf-8 -*-



import argparse
import ast
import base64
import json
import marshal
import os
import random
import string
import struct
import sys
import time
import types
import zlib

from MCP_Armor_Src.netease import policy_checker as netease_policy_checker
from MCP_Armor_Src.utils.encoding import (
    obfuscate_reserved_generated_identifiers,
    random_ident,
)
from MCP_Armor_Src.utils.chacha import chacha_crypt
from MCP_Armor_Src.utils.pyc import build_timestamp_pyc
from MCP_Armor_Src.core import py27_opcode


DEFAULT_TAUNT_TEXT = '\u89e3\u4e0d\u6b7b\u554a\uff0c\u8fd9\u4e48\u7231\u89e3\u600e\u4e48\u4e0d\u53bb\u6b7b\u554a \u50bb\u903c'.encode('utf-8')
DEFAULT_OUTER_TAUNT_TEXT = '(\u53c8\u6765\u89e3\u5305\uff1f\u4eb2\u4eba\u600e\u4e48\u529e\uff1f)'.encode('utf-8')

EMBEDDED_MCS_OPCODE_MAPS = {1: {0: 74, 1: 15, 2: 28, 3: 56, 4: 40, 5: 41, 6: 42, 7: 43, 8: 11, 9: 24, 10: 9, 12: 25, 13: 66, 15: 82, 16: 78, 17: 85, 18: 27, 20: 50, 21: 51, 22: 52, 23: 53, 26: 60, 27: 71, 28: 64, 29: 12, 30: 73, 31: 22, 36: 19, 37: 86, 38: 81, 39: 3, 41: 75, 42: 26, 43: 54, 44: 25, 45: 79, 46: 63, 47: 77, 48: 65, 49: 5, 50: 68, 52: 72, 53: 2, 55: 89, 56: 20, 57: 87, 59: 83, 60: 80, 62: 84, 63: 23, 64: 115, 65: 88, 67: 61, 69: 64, 70: 57, 71: 30, 72: 31, 73: 32, 74: 33, 75: 62, 78: 76, 79: 60, 80: 4, 84: 10, 86: 1, 88: 55, 92: 71, 93: 100, 95: 122, 100: 93, 101: 143, 102: 125, 107: 133, 114: 90, 116: 91, 119: 131, 122: 102, 123: 134, 130: 107, 131: 146, 134: 137, 135: 106, 138: 92, 139: 109, 140: 95, 144: 96, 148: 108, 150: 116, 152: 126, 153: 120, 158: 135, 160: 114, 173: 136, 179: 60, 183: 97, 192: 140, 193: 141, 194: 142, 197: 111, 198: 132, 199: 110, 202: 99, 204: 145, 207: 98, 210: 94, 211: 115, 212: 121, 226: 124, 230: 112, 231: 105, 232: 101, 233: 115, 234: 60, 235: 130, 240: 104, 243: 121, 247: 119, 250: 113, 252: 103}, 2: {1: 83, 2: 81, 4: 62, 5: 74, 8: 30, 9: 31, 10: 32, 11: 33, 12: 9, 14: 55, 15: 23, 16: 11, 18: 82, 20: 75, 21: 68, 23: 2, 26: 24, 27: 106, 28: 63, 31: 66, 32: 27, 34: 4, 35: 85, 36: 87, 37: 57, 38: 54, 40: 77, 42: 79, 43: 65, 44: 20, 45: 71, 46: 56, 47: 60, 48: 71, 49: 27, 50: 12, 51: 3, 52: 71, 53: 22, 55: 89, 56: 86, 60: 40, 61: 41, 62: 42, 63: 43, 64: 28, 67: 61, 68: 1, 69: 72, 70: 26, 71: 25, 72: 56, 73: 80, 74: 10, 76: 24, 77: 84, 78: 5, 79: 88, 81: 19, 84: 50, 85: 51, 86: 52, 87: 53, 88: 64, 89: 76, 91: 73, 92: 78, 94: 137, 97: 105, 100: 110, 102: 99, 110: 111, 114: 145, 116: 131, 120: 121, 130: 95, 139: 133, 141: 140, 142: 141, 143: 142, 148: 110, 149: 90, 158: 92, 172: 134, 175: 102, 176: 114, 185: 122, 188: 130, 190: 98, 192: 125, 194: 132, 196: 112, 198: 146, 202: 96, 204: 101, 205: 136, 209: 104, 210: 106, 212: 97, 213: 107, 214: 119, 217: 135, 219: 109, 220: 143, 221: 91, 223: 100, 229: 103, 232: 113, 233: 120, 235: 108, 238: 93, 244: 124, 253: 116, 242: 115, 243: 111, 247: 94}, 3: {0: 61, 1: 9, 2: 19, 3: 82, 4: 20, 6: 65, 8: 84, 9: 11, 10: 26, 11: 25, 12: 50, 13: 51, 14: 52, 15: 53, 16: 66, 17: 28, 20: 24, 22: 62, 24: 74, 25: 86, 26: 78, 28: 40, 29: 41, 30: 42, 31: 43, 41: 75, 42: 71, 43: 79, 45: 2, 46: 3, 47: 88, 48: 27, 49: 54, 50: 1, 52: 22, 53: 72, 54: 63, 55: 12, 59: 68, 60: 83, 63: 80, 67: 10, 68: 76, 69: 77, 71: 81, 72: 64, 73: 57, 74: 87, 76: 73, 78: 23, 80: 89, 81: 56, 82: 55, 83: 4, 85: 30, 86: 31, 87: 32, 88: 33, 90: 60, 96: 120, 101: 107, 103: 112, 105: 134, 107: 98, 108: 122, 109: 103, 110: 94, 114: 93, 118: 119, 119: 110, 120: 95, 126: 131, 136: 111, 148: 137, 151: 140, 152: 141, 153: 142, 155: 146, 158: 97, 169: 91, 172: 105, 173: 143, 178: 92, 183: 96, 185: 108, 190: 102, 192: 124, 199: 104, 200: 115, 211: 136, 212: 101, 214: 100, 215: 132, 219: 130, 222: 125, 223: 109, 224: 99, 228: 90, 231: 106, 241: 114, 244: 116, 246: 135, 247: 121, 254: 113}, 4: {0: 9, 1: 5, 2: 76, 3: 15, 4: 40, 5: 41, 6: 42, 7: 43, 8: 25, 9: 72, 10: 21, 11: 19, 13: 75, 14: 27, 15: 68, 16: 56, 17: 87, 18: 86, 19: 28, 20: 54, 21: 20, 23: 71, 24: 57, 26: 81, 27: 30, 28: 31, 29: 32, 30: 33, 31: 63, 35: 60, 39: 66, 40: 88, 41: 77, 42: 21, 43: 4, 44: 10, 46: 80, 47: 73, 52: 3, 53: 82, 54: 24, 59: 62, 60: 78, 62: 50, 63: 51, 64: 52, 65: 53, 67: 89, 68: 79, 70: 11, 71: 24, 72: 65, 73: 23, 75: 22, 77: 55, 78: 66, 79: 85, 80: 2, 81: 83, 82: 84, 83: 1, 86: 12, 87: 26, 88: 74, 89: 61, 92: 64, 96: 137, 107: 93, 110: 99, 111: 104, 116: 122, 121: 110, 123: 113, 132: 101, 133: 136, 134: 97, 135: 91, 136: 116, 137: 106, 140: 124, 144: 131, 159: 125, 161: 105, 162: 126, 163: 109, 166: 134, 167: 119, 175: 103, 182: 130, 189: 146, 194: 143, 195: 111, 201: 90, 208: 120, 209: 121, 212: 95, 213: 112, 214: 135, 216: 94, 218: 114, 222: 100, 223: 147, 225: 96, 228: 107, 229: 102, 233: 140, 234: 141, 235: 142, 240: 98, 243: 115, 247: 132, 250: 108, 252: 133, 254: 92}}


# Complete NetEase Python 2.7 V1 table from netease_opcode.go,
# neteaseOpcodes[0].  The older unpacker table is incomplete and contains
# several guessed aliases (notably BINARY_DIVIDE -> 0x0A).  Keep this table
# embedded so frozen builds do not depend on the .go source file.
AUTHORITATIVE_MCS_OPCODE_MAP_V1 = {
    0: 74, 1: 15, 2: 28, 3: 56, 4: 40, 5: 41, 6: 42, 7: 43,
    8: 11, 9: 24, 13: 66, 15: 82, 16: 78, 17: 85, 18: 27,
    20: 50, 21: 51, 22: 52, 23: 53, 26: 58, 27: 70, 28: 59,
    29: 12, 30: 73, 31: 22, 36: 19, 37: 86, 38: 81, 39: 3,
    41: 75, 42: 26, 43: 54, 44: 25, 45: 79, 46: 63, 47: 77,
    48: 65, 49: 5, 50: 68, 52: 72, 53: 2, 55: 89, 56: 20,
    57: 87, 59: 83, 60: 80, 62: 84, 63: 23, 64: 21, 65: 88,
    67: 61, 69: 64, 70: 57, 71: 30, 72: 31, 73: 32, 74: 33,
    75: 62, 78: 76, 79: 60, 80: 4, 82: 13, 84: 10, 86: 1,
    88: 55, 89: 29, 90: 9, 91: 67, 92: 71, 93: 100, 95: 122,
    100: 93, 101: 143, 102: 125, 107: 133, 114: 90, 116: 91,
    119: 131, 122: 102, 123: 134, 130: 107, 131: 146, 134: 137,
    135: 106, 138: 92, 139: 109, 140: 95, 144: 96, 148: 108,
    150: 116, 152: 126, 153: 120, 158: 135, 160: 114, 173: 136,
    183: 97, 192: 140, 193: 141, 194: 142, 197: 111, 198: 132,
    199: 110, 202: 99, 204: 145, 207: 98, 210: 94, 211: 115,
    212: 121, 226: 124, 230: 112, 231: 105, 232: 101, 234: 147,
    235: 130, 240: 104, 247: 119, 250: 113, 252: 103,
}


MODMAIN_TEMPLATE = r'''# -*- coding: utf-8 -*-
{bloat_head}
{outer_lambda_block}
{outer_control_block}
from mod.common.mod import Mod
import random as {random_var}
{sys_var} = getattr(Mod.Binding, 'func_globals', {{}}).get(chr(115) + chr(121) + chr(115))
if {sys_var} is None:
    {sys_var} = getattr(__builtins__[chr(95) + chr(95) + chr(105) + chr(109) + chr(112) + chr(111) + chr(114) + chr(116) + chr(95) + chr(95)](chr(109) + chr(111) + chr(100) + chr(46) + chr(99) + chr(111) + chr(109) + chr(109) + chr(111) + chr(110) + chr(46) + chr(109) + chr(105) + chr(110) + chr(101) + chr(99) + chr(114) + chr(97) + chr(102) + chr(116) + chr(77) + chr(111) + chr(100), globals(), locals(), [chr(120)]), chr(115) + chr(121) + chr(115))
{module_var} = {sys_var}.modules.get({module_label!r})
if {module_var} is None:
    {module_var} = {random_var}.__class__({module_label!r})
    {module_var}.__builtins__ = __builtins__
    {sys_var}.modules[{module_label!r}] = {module_var}
{fake_module_block}

def {load_name}({module_arg}, {side_arg}):
{load_doc}
{load_control_block}
    {loaded_key_var} = {loaded_attr!r} + {side_arg}
    if getattr({module_arg}, {loaded_key_var}, False):
        return
    if {side_arg} == 'client':
{client_payload_block}
    else:
{server_payload_block}
    if {blob_var} is None:
        return
    import base64 as {b64_name}
    import zlib as {zlib_name}
{key_block}
    if not isinstance({blob_var}, basestring):
        {blob_var}.sort()
        {blob_var} = ''.join(_x[1] for _x in {blob_var} if _x[0] >= 0)
    {blob_var} = {b64_name}.b64decode({blob_var})

    def {xor_name}({data_arg}, {key_arg}):
{xor_doc}
        return ''.join(chr(ord({ch_arg}) ^ ord({key_arg}[{idx_arg} % len({key_arg})]))
                       for {idx_arg}, {ch_arg} in enumerate({data_arg}))

    def {roll_name}({data_arg}):
{roll_doc}
        {arr_var} = bytearray({data_arg})
        for {idx_arg} in xrange(len({arr_var})):
            {arr_var}[{idx_arg}] ^= {idx_arg} % 256
        return str({arr_var})

    {blob_var} = {roll_name}({blob_var})
{cipher_decode_block}
    {blob_var} = {blob_var}[::-1]
    {blob_var} = {zlib_name}.decompress({blob_var})
    import marshal as {marshal_name}
    {code_var} = {marshal_name}.loads({blob_var})
    try:
        (lambda: None).__class__({code_var}, {module_arg}.__dict__)()
    except Exception as {outer_exc_name}:
        raise
    finally:
        {outer_noise_a} = {outer_noise_seed_a} ^ {outer_noise_seed_a}
    setattr({module_arg}, {loaded_key_var}, True)
    return

@Mod.Binding(name={binding_name!r}, version={version!r})
class {binding_cls}(object):
    MOD_NAME = {binding_name!r}
    VERSION = {version!r}
{lifecycle_methods}
{bloat_tail}
'''


LIFECYCLE_METHOD_TEMPLATE = '''
    def {method_name}(self):
{method_doc}
{control_block}
        try:
            {load_name}({module_var}, {side!r})
            return {lifecycle_call}
        except Exception as {outer_exc_name}:
            raise
        finally:
            {outer_noise_var} = {outer_noise_seed} ^ {outer_noise_seed}
    {method_name}.{decorator_attr} = {decorator_value!r}
'''


LIFECYCLE_DIRECT_INIT_TEMPLATE = '''
    def {method_name}(self):
{method_doc}
{control_block}
        try:
            import {api_module} as {api_name}
{register_block}
        except Exception as {outer_exc_name}:
            raise
        finally:
            {outer_noise_var} = {outer_noise_seed} ^ {outer_noise_seed}
    {method_name}.{decorator_attr} = {decorator_value!r}
'''


LIFECYCLE_DIRECT_DESTROY_TEMPLATE = '''
    def {method_name}(self):
{method_doc}
{control_block}
        try:
            return None
        except Exception as {outer_exc_name}:
            raise
        finally:
            {outer_noise_var} = {outer_noise_seed} ^ {outer_noise_seed}
    {method_name}.{decorator_attr} = {decorator_value!r}
'''


INNER_MODULE_TEMPLATE = '''# -*- coding: utf-8 -*-
{server_sources_name} = {server_sources!r}
{client_sources_name} = {client_sources!r}
{aliases_name} = {aliases!r}
{exports_name} = {exports!r}
{server_modules_name} = {server_modules!r}
{client_modules_name} = {client_modules!r}
{external_aliases_name} = {external_aliases!r}
{external_alias_order_name} = {external_alias_order!r}

def {ensure_pkg_name}():
    import random as {random_api}
    {sys_api} = {import_sys_expr}
    {pkg_name} = {namespace!r}
    {pkg_mod} = {sys_api}.modules.get({pkg_name})
    if {pkg_mod} is None:
        {pkg_mod} = {random_api}.__class__({pkg_name})
        {pkg_mod}.__name__ = {pkg_name}
        {pkg_mod}.__package__ = {pkg_name}
        {pkg_mod}.__path__ = [{pkg_name}]
        {pkg_mod}.__builtins__ = __builtins__
        {sys_api}.modules[{pkg_name}] = {pkg_mod}
    return {pkg_mod}

def {ensure_parent_name}({mod_name_arg}):
    import random as {random_api}
    {sys_api} = {import_sys_expr}
    {ensure_pkg_name}()
    {parts_var} = {mod_name_arg}.split('.')
    {parent_var} = None
    {prefix_var} = ''
    {limit_var} = len({parts_var}) - 1
    {pos_var} = 0
    for {part_var} in {parts_var}:
        if {pos_var} >= {limit_var}:
            break
        if {prefix_var}:
            {prefix_var} = {prefix_var} + '.' + {part_var}
        else:
            {prefix_var} = {part_var}
        {pkg_mod} = {sys_api}.modules.get({prefix_var})
        if {pkg_mod} is None:
            {pkg_mod} = {random_api}.__class__({prefix_var})
            {pkg_mod}.__name__ = {prefix_var}
            {pkg_mod}.__package__ = {prefix_var}
            {pkg_mod}.__path__ = [{prefix_var}.replace('.', '/')]
            {pkg_mod}.__builtins__ = __builtins__
            {sys_api}.modules[{prefix_var}] = {pkg_mod}
        if {parent_var} is not None:
            setattr({parent_var}, {part_var}, {pkg_mod})
        {parent_var} = {pkg_mod}
        {pos_var} += 1
    return {parent_var}

def {split_name_func}({mod_name_arg}):
    {parts_var} = {mod_name_arg}.split('.')
    {limit_var} = len({parts_var}) - 1
    {pos_var} = 0
    {prefix_var} = ''
    {leaf_var} = ''
    for {part_var} in {parts_var}:
        if {pos_var} >= {limit_var}:
            {leaf_var} = {part_var}
            break
        if {prefix_var}:
            {prefix_var} = {prefix_var} + '.' + {part_var}
        else:
            {prefix_var} = {part_var}
        {pos_var} += 1
    return {prefix_var}, {leaf_var}

def {install_name}({mod_name_arg}, {source_arg}, {side_arg}, {stub_arg}=False):
    import random as {random_api}
    {sys_api} = {import_sys_expr}
    {parent_mod} = {ensure_parent_name}({mod_name_arg})
    {old_mod} = {sys_api}.modules.get({mod_name_arg})
    if {old_mod} is not None:
        {new_mod} = {old_mod}
    else:
        {new_mod} = {random_api}.__class__({mod_name_arg})
        {sys_api}.modules[{mod_name_arg}] = {new_mod}
    {new_mod}.__name__ = {mod_name_arg}
    {new_mod}.__package__ = ''
    {leaf_parts_var} = {mod_name_arg}.split('.')
    {leaf_name_var} = {leaf_parts_var}.pop()
    if {parent_mod} is not None:
        {new_mod}.__package__ = {parent_mod}.__name__
    {new_mod}.__builtins__ = __builtins__
    {new_mod}.__file__ = '<' + {mod_name_arg} + '>'
    if {parent_mod} is not None:
        setattr({parent_mod}, {leaf_name_var}, {new_mod})
    if {stub_arg}:
        return {new_mod}
    {ensure_aliases_name}({side_arg})
    import marshal as {marshal_api}
    {code_var} = {marshal_api}.loads({source_arg})
    (lambda: None).__class__({code_var}, {new_mod}.__dict__)()
    for {export_arg} in {exports_name}.get({mod_name_arg}, ()):
        {export_obj} = {new_mod}.__dict__.get({export_arg})
        if {export_obj} is not None:
            setattr({new_mod}, {export_arg}, {export_obj})
    return {new_mod}

def {ensure_aliases_name}({side_arg}):
    {sys_api} = {import_sys_expr}
    for {alias_arg} in {external_alias_order_name}:
        if {side_arg} == 'client' and {alias_arg}.startswith('server'):
            continue
        if {side_arg} == 'server' and {alias_arg}.startswith('client'):
            continue
        if {alias_arg} in {sys_api}.modules:
            continue
        {alias_src_name} = {external_aliases_name}.get({alias_arg})
        if not {alias_src_name}:
            continue
        {sys_api}.modules[{alias_arg}] = __import__({alias_src_name}, globals(), locals(), ['x'])
        if '.' in {alias_arg}:
            {parent_name_var}, {leaf_name_var} = {split_name_func}({alias_arg})
            {parent_mod} = {sys_api}.modules.get({parent_name_var})
            if {parent_mod} is not None:
                setattr({parent_mod}, {leaf_name_var}, {sys_api}.modules[{alias_arg}])

def {install_many_name}({names_arg}, {side_arg}):
    if {side_arg} == 'client':
        {sources_ref_name} = {client_sources_name}
    else:
        {sources_ref_name} = {server_sources_name}
    for {item_arg} in {names_arg}:
        {install_name}({item_arg}, '', {side_arg}, True)
        for {alias_arg} in {aliases_name}.get({item_arg}, ()):
            {install_name}({alias_arg}, '', {side_arg}, True)
    for {item_arg} in {names_arg}:
        {src_name} = {sources_ref_name}.get({item_arg})
        if {src_name} is None and {side_arg} == 'client':
            {src_name} = {server_sources_name}.get({item_arg})
        if {src_name} is None:
            {install_name}({item_arg}, '', {side_arg}, True)
        else:
            {install_name}({item_arg}, {src_name}, {side_arg})
            for {alias_arg} in {aliases_name}.get({item_arg}, ()):
                {sys_api} = {import_sys_expr}
                {sys_api}.modules[{alias_arg}] = {sys_api}.modules.get({item_arg})

class {server_cls}(object):
    def {server_init}(self):
        {install_many_name}({server_modules_name}, 'server')
        import mod.server.extraServerApi as {server_api}
{server_register_block}
    def {server_destroy}(self):
        return None

class {client_cls}(object):
    def {client_init}(self):
        {install_many_name}({client_modules_name}, 'client')
        import mod.client.extraClientApi as {client_api}
{client_register_block}
    def {client_destroy}(self):
        return None

{server_obj} = {server_cls}()
{client_obj} = {client_cls}()
'''


LADDER_PAYLOAD_TEMPLATE = '''# -*- coding: utf-8 -*-
{banner}

def {make_module_name}({module_name_arg}):
    import random as {random_api}
    {sys_api} = {import_sys_expr}
    {old_module_var} = {sys_api}.modules.get({module_name_arg})
    if {old_module_var} is not None:
        return {old_module_var}
    {module_var} = {random_api}.__class__({module_name_arg})
    {module_var}.__builtins__ = __builtins__
    {module_var}.__file__ = '<' + {module_name_arg} + '>'
    {sys_api}.modules[{module_name_arg}] = {module_var}
    return {module_var}

{extra_body}

class {server_holder_cls}(object):
    def {server_init}(self):
{server_init_body}
    def {server_destroy}(self):
        print '[{namespace}] ladder DestroyServer'
        return None

class {client_holder_cls}(object):
    def {client_init}(self):
{client_init_body}
    def {client_destroy}(self):
        print '[{namespace}] ladder DestroyClient'
        return None

{server_obj} = {server_holder_cls}()
{client_obj} = {client_holder_cls}()
'''


def require_py27():
    if sys.version_info[:2] != (2, 7):
        sys.stderr.write('error: run with Python 2.7\n')
        sys.exit(2)


def random_identifier(prefix):
    return random_ident(prefix)


def random_plain_name(length=None):
    tail = string.ascii_lowercase + string.digits
    if length is None:
        length = random.randint(14, 24)
    return random.choice(string.ascii_lowercase) + ''.join(random.choice(tail) for _ in range(length - 1))


def xor_data(data, key):
    return ''.join(chr(ord(ch) ^ ord(key[index % len(key)])) for index, ch in enumerate(data))


def split_chunks(data, min_size=47, max_size=113):
    chunks = []
    index = 0
    while index < len(data):
        step = random.randint(min_size, max_size)
        chunks.append(data[index:index + step])
        index += step
    return chunks


def build_join_block(target_var, data, noise_count, indent):
    chunks = split_chunks(data)
    entries = [(True, index, chunk) for index, chunk in enumerate(chunks)]
    for _ in range(noise_count):
        entries.append((False, random.randint(0, len(chunks) + 9), random_plain_name()))
    real_tag = random.randint(10000, 99999)
    fake_tags = [random.randint(10000, 99999) for _ in range(max(1, noise_count))]
    tagged = []
    for is_real, index, chunk in entries:
        tag = real_tag if is_real else random.choice(fake_tags)
        tagged.append((tag, index, chunk))
    random.shuffle(tagged)
    arr_name = random_identifier('arr')
    item_name = random_identifier('it')
    out_name = random_identifier('out')
    lines = [
        indent + '%s = %r' % (arr_name, tagged),
        indent + '%s = []' % out_name,
        indent + 'for %s in %s:' % (item_name, arr_name),
        indent + '    if %s[0] == %r:' % (item_name, real_tag),
        indent + '        %s.append((%s[1], %s[2]))' % (out_name, item_name, item_name),
        indent + '%s.sort()' % out_name,
        indent + '%s = %r.join([%s[1] for %s in %s])' % (target_var, '', item_name, item_name, out_name),
    ]
    return '\n'.join(lines)


def build_literal_block(target_var, data, split_enabled, noise_count, indent):
    if split_enabled:
        return build_join_block(target_var, data, noise_count, indent)
    return indent + '%s = %r' % (target_var, data)


def build_payload_block(target_var, data, split_enabled, noise_count, indent, fragments=0):
    if fragments and data:
        count = max(2, min(64, int(fragments)))
        chunk_size = max(1, (len(data) + count - 1) // count)
        items = []
        index = 0
        for start in range(0, len(data), chunk_size):
            items.append((index, data[start:start + chunk_size]))
            index += 1
        for fake_index in range(max(1, min(count, noise_count // 8 + 1))):
            items.append((-(fake_index + 1), random_bytes_literal(random.randint(8, 32))))
        random.shuffle(items)
        return indent + '%s = %r' % (target_var, items)
    return build_literal_block(target_var, data, split_enabled, noise_count, indent)


def build_fake_module_block(count, sys_var, random_var, indent=''):
    lines = []
    for _ in range(max(0, count)):
        name = random_identifier('fm')
        label = random_plain_name(random.randint(8, 18))
        attr = random_identifier('fa')
        lines.extend([
            indent + '%s = %s.__class__(%r)' % (name, random_var, label),
            indent + '%s.__builtins__ = __builtins__' % name,
            indent + '%s.%s = %r' % (name, attr, random_bytes_literal(random.randint(8, 32))),
            indent + '%s.modules[%r] = %s' % (sys_var, label, name),
        ])
    return '\n'.join(lines) + ('\n' if lines else '')


def build_key_block(target_var, key, split_enabled, noise_count, indent, masked=False):
    if not masked:
        return build_literal_block(target_var, key, split_enabled, noise_count, indent)
    mask = os.urandom(len(key))
    masked_key = xor_data(key, mask)
    masked_var = random_identifier('mk')
    mask_var = random_identifier('ms')
    idx_var = random_identifier('i')
    ch_var = random_identifier('c')
    lines = [
        build_literal_block(masked_var, masked_key, split_enabled, noise_count, indent),
        build_literal_block(mask_var, mask, split_enabled, noise_count, indent),
        indent + "%s = ''.join(chr(ord(%s) ^ ord(%s[%s %% len(%s)])) for %s, %s in enumerate(%s))" % (
            target_var, ch_var, mask_var, idx_var, mask_var, idx_var, ch_var, masked_var
        ),
    ]
    return '\n'.join(lines)


def random_bytes_literal(length):
    return ''.join(chr(random.randint(1, 255)) for _ in range(length)).encode('string_escape')


def random_raw_bytes(length):
    return ''.join(chr(random.randint(1, 255)) for _ in range(length))


def random_hex_doc_lines(line_count, min_bytes=24, max_bytes=54):
    lines = []
    for _ in range(max(1, line_count)):
        raw = ''.join(chr(random.randint(1, 255)) for _ in range(random.randint(min_bytes, max_bytes)))
        lines.append(raw.encode('string_escape'))
    return lines


def build_docstring(line_count, indent, min_bytes=24, max_bytes=54):
    if line_count <= 0:
        return ''
    lines = [indent + '"""']
    for item in random_hex_doc_lines(line_count, min_bytes, max_bytes):
        lines.append(indent + item)
    lines.append(indent + '"""')
    return '\n'.join(lines)


def utf8_byte_list(text):
    if text is None:
        text = ''
    if isinstance(text, str):
        text = text.encode('utf-8')
    return [ord(ch) for ch in text]


def build_outer_lambda_block(enabled, count, taunt_text, repeat):
    if not enabled or count <= 0:
        return ''
    values = utf8_byte_list(taunt_text or DEFAULT_OUTER_TAUNT_TEXT)
    chunk = [10] + values + [10]
    payload = chunk * max(1, repeat)
    expr = 'bytearray(%r)' % payload
    lines = []
    for index in range(max(1, count)):
        if index % 3 == 0:
            lines.append("lambda: %s" % expr)
        elif index % 3 == 1:
            name = random_identifier('x')
            lines.append("(lambda %s=%s: %s)" % (name, expr, name))
        else:
            name = random_identifier('lmd')
            lines.append("%s = lambda: %s" % (name, expr))
            lines.append("del %s" % name)
    return '\n'.join(lines) + '\n'


def build_outer_control_block(enabled, count, indent=''):
    if not enabled or count <= 0:
        return ''
    lines = []
    for _ in range(max(1, count)):
        a = random_identifier('oc')
        b = random_identifier('oc')
        c = random_identifier('oc')
        seed = random.randint(1000, 999999)
        mode = random.randint(0, 2)
        if mode == 0:
            lines.extend([
                '%s = %d' % (a, seed),
                'if (%s ^ %s) == 0:' % (a, a),
                '    %s = %s + 1' % (b, a),
                'else:',
                '    %s = %s - 1' % (b, a),
                'del %s' % a,
                'del %s' % b,
            ])
        elif mode == 1:
            lines.extend([
                'try:',
                '    %s = %d' % (a, seed),
                '    %s = (%s & 7)' % (b, a),
                'except Exception as %s:' % c,
                '    %s = None' % b,
                'finally:',
                '    %s = 0' % a,
                'del %s' % a,
                'del %s' % b,
            ])
        else:
            lines.extend([
                '%s = %d' % (a, seed),
                '%s = 1 if %s else 0' % (b, a),
                'if %s:' % b,
                '    pass',
                'else:',
                '    %s = %s' % (a, b),
                'del %s' % a,
                'del %s' % b,
            ])
    if indent:
        lines = [indent + line if line else line for line in lines]
    return '\n'.join(lines) + '\n'


def build_bloat_block(lines, target_kb, style):
    if lines <= 0 and target_kb <= 0:
        return ''
    output = []
    line_no = 0
    target_bytes = max(0, target_kb) * 1024
    while line_no < lines or (target_bytes and len('\n'.join(output)) < target_bytes):
        name = random_identifier('junk')
        if style == 'strings':
            output.append('%r' % random_bytes_literal(random.randint(48, 160)))
        else:
            output.append('%s = %r' % (name, random_bytes_literal(random.randint(48, 160))))
            output.append('%s = (%s, %r)' % (random_identifier('junk'), name, random_bytes_literal(random.randint(24, 96))))
        line_no += 1
    return '\n'.join(output) + '\n'


def load_std2mcs_map(version):
    maps = {}
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, 'MCPK_Quick_Unpack', 'MCPK_Quick_Unpack', 'opcode_map.py'),
        os.path.join(os.getcwd(), 'MCPK_Quick_Unpack', 'MCPK_Quick_Unpack', 'opcode_map.py'),
    ]
    bundle_root = getattr(sys, '_MEIPASS', None)
    if bundle_root:
        candidates.append(os.path.join(bundle_root, 'MCPK_Quick_Unpack', 'MCPK_Quick_Unpack', 'opcode_map.py'))
    for path in candidates:
        if not os.path.isfile(path):
            continue
        source = read_file(path)
        source = source.split('MAP_STORE', 1)[0]
        source = '\n'.join(line for line in source.splitlines() if not line.startswith('from typing import'))
        namespace = {}
        exec(source, namespace, namespace)
        for key, value in list(namespace.items()):
            if key.startswith('OP_MAP_V') and isinstance(value, dict):
                try:
                    maps[int(key[len('OP_MAP_V'):])] = value
                except ValueError:
                    pass
        if maps:
            break
    if not maps:
        maps = EMBEDDED_MCS_OPCODE_MAPS
    if version == 1:
        mcs2std = AUTHORITATIVE_MCS_OPCODE_MAP_V1
    else:
        mcs2std = maps.get(version) or maps.get(1)
    if not mcs2std:
        raise SystemExit('error: cannot load MCS opcode map version %s' % version)
    std2mcs = dict((std_op, mcs_op) for mcs_op, std_op in list(mcs2std.items()))
    return std2mcs


def parse_opcode_overrides(items):
    overrides = {}
    if not items:
        return overrides
    dis = py27_opcode
    for item in items:
        if '=' not in item:
            raise SystemExit('error: --mcs-op-override expects NAME=VALUE')
        name, value = item.split('=', 1)
        name = name.strip()
        value = value.strip()
        if name in dis.opmap:
            std_op = dis.opmap[name]
        else:
            try:
                std_op = int(name, 0)
            except ValueError:
                raise SystemExit('error: unknown opcode name %r' % name)
        overrides[std_op] = int(value, 0)
    return overrides


def parse_opcode_token(token):
    dis = py27_opcode
    token = str(token).strip()
    if token in dis.opmap:
        return dis.opmap[token]
    return int(token, 0)


def checked_opcode_value(value, label):
    value = int(value)
    if value < 0 or value > 255:
        raise SystemExit('error: %s opcode must be 0..255, got %s' % (label, value))
    return value


def normalize_inner_opcode_table(data):
    mapping = {}
    if isinstance(data, dict):
        if 'std_to_custom' in data:
            items = list(data['std_to_custom'].items())
        elif 'custom_to_std' in data:
            items = [(std, custom) for custom, std in list(data['custom_to_std'].items())]
        else:
            items = list(data.items())
    else:
        items = data
    for item in items:
        if isinstance(item, dict):
            std = item.get('std', item.get('standard', item.get('from')))
            custom = item.get('custom', item.get('to'))
        else:
            std, custom = item[0], item[1]
        std = checked_opcode_value(parse_opcode_token(std), 'standard')
        custom = checked_opcode_value(parse_opcode_token(custom), 'custom')
        if std in mapping and mapping[std] != custom:
            raise SystemExit('error: duplicate custom opcode mapping for std opcode %s' % std)
        mapping[std] = custom
    used_custom = {}
    for std, custom in list(mapping.items()):
        if custom in used_custom and used_custom[custom] != std:
            raise SystemExit('error: custom opcode %s is used by both %s and %s' % (custom, used_custom[custom], std))
        used_custom[custom] = std
    return mapping


def load_inner_opcode_table(path):
    if not path:
        return {}
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise SystemExit('error: cannot find inner opcode table: %s' % path)
    source = read_file(path).strip()
    if not source:
        return {}
    try:
        return normalize_inner_opcode_table(json.loads(source))
    except Exception:
        pass
    try:
        return normalize_inner_opcode_table(ast.literal_eval(source))
    except Exception:
        pass
    rows = []
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        for sep in ('#', '//'):
            if sep in line:
                line = line.split(sep, 1)[0].strip()
        if '=' in line:
            left, right = line.split('=', 1)
        elif ':' in line:
            left, right = line.split(':', 1)
        else:
            parts = line.replace(',', ' ').split()
            if len(parts) < 2:
                raise SystemExit('error: invalid inner opcode table line: %r' % line)
            left, right = parts[0], parts[1]
        rows.append((left.strip(), right.strip()))
    return normalize_inner_opcode_table(rows)


def string_encrypt_chain(args):
    chain = []
    if getattr(args, 'string_enc_zlib', False):
        chain.append('zlib')
    if getattr(args, 'string_enc_xor', False):
        chain.append('xor')
    if getattr(args, 'string_enc_add', False):
        chain.append('add')
    if getattr(args, 'string_enc_reverse', False):
        chain.append('reverse')
    return chain


def remap_bytecode(bytecode, op_map):
    output = []
    index = 0
    size = len(bytecode)
    while index < size:
        op = ord(bytecode[index])
        mapped = op_map.get(op, op)
        output.append(chr(mapped))
        index += 1
        if op >= 90 and index + 1 < size:
            output.append(bytecode[index])
            output.append(bytecode[index + 1])
            index += 2
    return ''.join(output)


def remap_code_object(code, op_map):
    consts = []
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            consts.append(remap_code_object(const, op_map))
        else:
            consts.append(const)
    return types.CodeType(
        code.co_argcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        remap_bytecode(code.co_code, op_map),
        tuple(consts),
        code.co_names,
        code.co_varnames,
        code.co_filename,
        code.co_name,
        code.co_firstlineno,
        code.co_lnotab,
        code.co_freevars,
        code.co_cellvars,
    )


def collect_code_opcodes(code, result=None):
    if result is None:
        result = set()
    index = 0
    size = len(code.co_code)
    while index < size:
        op = ord(code.co_code[index])
        result.add(op)
        index += 1
        if op >= HAVE_ARGUMENT and index + 1 < size:
            index += 2
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            collect_code_opcodes(const, result)
    return result


def build_inner_custom_opcode_maps(code, user_table=None):
    used = sorted(collect_code_opcodes(code))
    user_table = dict(user_table or {})
    no_arg_pool = list(range(1, HAVE_ARGUMENT))
    arg_pool = list(range(HAVE_ARGUMENT, 256))
    for custom in list(user_table.values()):
        if custom < HAVE_ARGUMENT:
            if custom in no_arg_pool:
                no_arg_pool.remove(custom)
        else:
            if custom in arg_pool:
                arg_pool.remove(custom)
    random.shuffle(no_arg_pool)
    random.shuffle(arg_pool)
    std_to_custom = {}
    custom_to_std = {}
    for op in used:
        if op in user_table:
            custom = user_table[op]
        else:
            pool = arg_pool if op >= HAVE_ARGUMENT else no_arg_pool
            if not pool:
                custom = op
            else:
                custom = pool.pop()
                if custom == op and pool:
                    pool.insert(0, custom)
                    custom = pool.pop()
        if custom in custom_to_std and custom_to_std[custom] != op:
            raise SystemExit('error: custom opcode %s is used by both %s and %s' % (custom, custom_to_std[custom], op))
        std_to_custom[op] = custom
        custom_to_std[custom] = op
    custom_has_arg = tuple(sorted(custom for op, custom in list(std_to_custom.items()) if op >= HAVE_ARGUMENT))
    return std_to_custom, custom_to_std, custom_has_arg


def remap_code_object_per_code(code, runtime_op_map=None, user_table=None):
    std_to_custom, custom_to_std, custom_has_arg = build_inner_custom_opcode_maps(code, user_table)
    runtime_map = custom_to_std
    if runtime_op_map:
        runtime_map = dict((custom, runtime_op_map.get(std, std)) for custom, std in list(custom_to_std.items()))
    consts = []
    child_maps = []
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            child_code, child_map = remap_code_object_per_code(const, runtime_op_map, user_table)
            consts.append(child_code)
            child_maps.append(child_map)
        else:
            consts.append(const)
    consts.append((sorted(runtime_map.items()), custom_has_arg, tuple(child_maps)))
    stored = make_code_like(code, code_bytes=remap_bytecode(code.co_code, std_to_custom), consts=consts)
    return stored, (sorted(runtime_map.items()), custom_has_arg, tuple(child_maps))


LOAD_CONST_OP = 100
NAME_REFERENCE_OPS = set([90, 91, 95, 96, 97, 98, 101, 106, 108, 109, 116])
FAST_REFERENCE_OPS = set([124, 125, 126])


def rewrite_bytecode_args(bytecode, const_map=None, name_map=None, varname_map=None):
    const_map = const_map or {}
    name_map = name_map or {}
    varname_map = varname_map or {}
    output = []
    index = 0
    size = len(bytecode)
    while index < size:
        op = ord(bytecode[index])
        output.append(bytecode[index])
        index += 1
        if op >= HAVE_ARGUMENT and index + 1 < size:
            arg = ord(bytecode[index]) + (ord(bytecode[index + 1]) << 8)
            if op == LOAD_CONST_OP and arg in const_map:
                arg = const_map[arg]
            elif op in NAME_REFERENCE_OPS and arg in name_map:
                arg = name_map[arg]
            elif op in FAST_REFERENCE_OPS and arg in varname_map:
                arg = varname_map[arg]
            output.append(code_word(arg))
            index += 2
    return ''.join(output)


def shuffled_index_map(size, keep_first=False):
    order = list(range(size))
    start = 1 if keep_first and size > 1 else 0
    tail = order[start:]
    random.shuffle(tail)
    order = order[:start] + tail
    return dict((old, new) for new, old in enumerate(order)), order


def shuffle_code_metadata(code, shuffle_consts=False, shuffle_names=False, fake_name_count=0, taunt_text=None, shuffle_varnames=False):
    consts = []
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            consts.append(shuffle_code_metadata(const, shuffle_consts, shuffle_names, max(0, fake_name_count // 2), taunt_text, shuffle_varnames))
        else:
            consts.append(const)
    names = list(code.co_names)
    const_map = {}
    name_map = {}
    varname_map = {}
    if shuffle_consts and len(consts) > 1:
        keep_first = bool(consts and isinstance(consts[0], str))
        const_map, const_order = shuffled_index_map(len(consts), keep_first)
        consts = [consts[index] for index in const_order]
    if shuffle_names and names:
        original_count = len(names)
        for _ in range(max(0, fake_name_count)):
            if taunt_text and random.randint(0, 2) == 0:
                names.append(taunt_text + random_bytes_literal(random.randint(2, 12)))
            else:
                names.append(random_identifier('nx'))
        name_map, name_order = shuffled_index_map(len(names), False)
        names = [names[index] for index in name_order]
        name_map = dict((old, name_map[old]) for old in range(original_count))
    varnames = list(code.co_varnames)
    if shuffle_varnames and len(varnames) > code.co_argcount + 1:
        fixed = list(range(code.co_argcount))
        tail = list(range(code.co_argcount, len(varnames)))
        random.shuffle(tail)
        order = fixed + tail
        varname_map = dict((old, new) for new, old in enumerate(order))
        varnames = [varnames[index] for index in order]
    code_bytes = rewrite_bytecode_args(code.co_code, const_map, name_map, varname_map)
    return make_code_like(code, code_bytes=code_bytes, consts=consts, names=tuple(names), varnames=tuple(varnames))


def sanitize_code_for_mcs(code):
    consts = []
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            consts.append(sanitize_code_for_mcs(const))
        else:
            consts.append(const)
    bytecode = []
    index = 0
    size = len(code.co_code)
    while index < size:
        op = ord(code.co_code[index])
        bytecode.append('\x09' if op == 0 else code.co_code[index])
        index += 1
        if op >= HAVE_ARGUMENT and index + 1 < size:
            bytecode.append(code.co_code[index])
            bytecode.append(code.co_code[index + 1])
            index += 2
    return types.CodeType(
        code.co_argcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        ''.join(bytecode),
        tuple(consts),
        code.co_names,
        code.co_varnames,
        code.co_filename,
        code.co_name,
        code.co_firstlineno,
        code.co_lnotab,
        code.co_freevars,
        code.co_cellvars,
    )


def make_code_like(code, code_bytes=None, consts=None, names=None, varnames=None, filename=None, name=None, lnotab=None, stacksize=None):
    return types.CodeType(
        code.co_argcount,
        code.co_nlocals,
        stacksize if stacksize is not None else code.co_stacksize,
        code.co_flags,
        code_bytes if code_bytes is not None else code.co_code,
        tuple(consts) if consts is not None else code.co_consts,
        names if names is not None else code.co_names,
        varnames if varnames is not None else code.co_varnames,
        filename if filename is not None else code.co_filename,
        name if name is not None else code.co_name,
        code.co_firstlineno,
        lnotab if lnotab is not None else code.co_lnotab,
        code.co_freevars,
        code.co_cellvars,
    )


def random_code_name():
    return random_ident('code')


def random_safe_filename():
    alphabet = string.ascii_letters + string.digits + '_-!@#$%^&()[]{}.,;='
    parts = []
    for _ in range(random.randint(2, 5)):
        parts.append(''.join(random.choice(alphabet) for _ in range(random.randint(8, 24))))
    return '<' + '/'.join(parts) + '>'


def random_lnotab():
    return random_raw_bytes(random.randint(0, 48))


HAVE_ARGUMENT = 90
FOR_ITER_OP = 93
JUMP_FORWARD_OP = 110
JUMP_ABSOLUTE_OP = 113
SETUP_LOOP_OP = 120
SETUP_EXCEPT_OP = 121
SETUP_FINALLY_OP = 122
EXTENDED_ARG_OP = 145
ABSOLUTE_JUMPS = set([111, 112, 113, 114, 115, 119])
RELATIVE_JUMPS = set([FOR_ITER_OP, JUMP_FORWARD_OP, SETUP_LOOP_OP, SETUP_EXCEPT_OP, SETUP_FINALLY_OP])
LOOP_TRAMPOLINE_OPS = set([FOR_ITER_OP, JUMP_ABSOLUTE_OP, SETUP_LOOP_OP, SETUP_EXCEPT_OP, SETUP_FINALLY_OP])


def code_word(value):
    return chr(value & 255) + chr((value >> 8) & 255)


def fix_absolute_jumps(bytecode, delta):
    output = []
    index = 0
    size = len(bytecode)
    while index < size:
        op = ord(bytecode[index])
        output.append(bytecode[index])
        index += 1
        if op >= HAVE_ARGUMENT and index + 1 < size:
            arg = ord(bytecode[index]) + (ord(bytecode[index + 1]) << 8)
            if op in ABSOLUTE_JUMPS:
                arg += delta
            output.append(code_word(arg))
            index += 2
    return ''.join(output)


def decode_instructions(bytecode):
    instructions = []
    index = 0
    size = len(bytecode)
    while index < size:
        offset = index
        op = ord(bytecode[index])
        index += 1
        arg = None
        raw = ''
        if op >= HAVE_ARGUMENT and index + 1 < size:
            raw = bytecode[index:index + 2]
            arg = ord(raw[0]) + (ord(raw[1]) << 8)
            index += 2
        instructions.append((offset, op, arg, raw, index - offset))
    return instructions


def add_bytecode_trampolines(code_bytes, enabled=False, rate=35):
    if not enabled:
        return code_bytes
    rate = max(0, min(100, rate))
    instructions = decode_instructions(code_bytes)
    if not instructions:
        return code_bytes
    insert_at = set()
    for offset, op, arg, _raw, _size in instructions:
        if op in LOOP_TRAMPOLINE_OPS and random.randint(1, 100) <= rate:
            insert_at.add(offset)
    if not insert_at:
        return code_bytes
    prefix_before = {}
    total = 0
    for offset, _op, _arg, _raw, _size in instructions:
        prefix_before[offset] = total
        if offset in insert_at:
            total += 3
    new_offset = dict((offset, offset + prefix_before[offset]) for offset, _op, _arg, _raw, _size in instructions)
    old_offsets = set(new_offset)
    output = []
    for offset, op, arg, raw, size in instructions:
        if offset in insert_at:
            output.append(chr(JUMP_FORWARD_OP) + code_word(0))
        if op < HAVE_ARGUMENT or arg is None:
            output.append(chr(op))
            continue
        adjusted = arg
        old_next = offset + size
        if op in ABSOLUTE_JUMPS:
            if arg in old_offsets:
                adjusted = new_offset[arg]
            elif arg >= offset:
                adjusted = arg + total
        elif op in RELATIVE_JUMPS:
            old_target = old_next + arg
            if old_target in old_offsets:
                adjusted = new_offset[old_target] - (new_offset[offset] + size)
            elif old_target >= offset:
                adjusted = arg + total
        if adjusted < 0 or adjusted > 65535:
            output.append(chr(op) + raw)
        else:
            output.append(chr(op) + code_word(adjusted))
    return ''.join(output)


def add_interleaved_jump_poison(code_bytes, enabled=False, count=0, min_bytes=8, max_bytes=32, aggressive=False):
    if not enabled or count <= 0 or max_bytes <= 0:
        return code_bytes
    instructions = decode_instructions(code_bytes)
    if len(instructions) < 4:
        return code_bytes
    candidates = []
    for offset, op, _arg, _raw, _size in instructions[1:]:
        if op == EXTENDED_ARG_OP:
            continue
        candidates.append(offset)
    if not candidates:
        return code_bytes
    random.shuffle(candidates)
    insert_at = {}
    for offset in candidates[:max(0, min(count, len(candidates)))]:
        poison_size = random.randint(max(0, min_bytes), max(0, max_bytes))
        if poison_size <= 0 or poison_size > 65000:
            continue
        poison = jump_garbage_stream(poison_size, aggressive)
        insert_at[offset] = chr(JUMP_FORWARD_OP) + code_word(len(poison)) + poison
    if not insert_at:
        return code_bytes
    prefix_before = {}
    total = 0
    for offset, _op, _arg, _raw, _size in instructions:
        prefix_before[offset] = total
        total += len(insert_at.get(offset, ''))
    new_offset = dict((offset, offset + prefix_before[offset]) for offset, _op, _arg, _raw, _size in instructions)
    old_offsets = set(new_offset)
    output = []
    for offset, op, arg, raw, size in instructions:
        block = insert_at.get(offset, '')
        if block:
            output.append(block)
        if op < HAVE_ARGUMENT or arg is None:
            output.append(chr(op))
            continue
        adjusted = arg
        old_next = offset + size
        new_instruction_offset = new_offset[offset] + len(block)
        new_next = new_instruction_offset + size
        if op in ABSOLUTE_JUMPS:
            if arg in old_offsets:
                adjusted = new_offset[arg]
            elif arg >= offset:
                adjusted = arg + total
        elif op in RELATIVE_JUMPS:
            old_target = old_next + arg
            if old_target in old_offsets:
                adjusted = new_offset[old_target] - new_next
            elif old_target >= offset:
                adjusted = arg + total
        if adjusted < 0 or adjusted > 65535:
            output.append(chr(op) + raw)
        else:
            output.append(chr(op) + code_word(adjusted))
    return ''.join(output)


def insert_bytecode_blocks(code_bytes, insert_at):
    if not insert_at:
        return code_bytes
    instructions = decode_instructions(code_bytes)
    if not instructions:
        return code_bytes
    prefix_before = {}
    total = 0
    for offset, _op, _arg, _raw, _size in instructions:
        prefix_before[offset] = total
        total += len(insert_at.get(offset, ''))
    new_offset = dict((offset, offset + prefix_before[offset]) for offset, _op, _arg, _raw, _size in instructions)
    old_offsets = set(new_offset)
    output = []
    for offset, op, arg, raw, size in instructions:
        block = insert_at.get(offset, '')
        if block:
            output.append(block)
        if op < HAVE_ARGUMENT or arg is None:
            output.append(chr(op))
            continue
        adjusted = arg
        old_next = offset + size
        new_instruction_offset = new_offset[offset] + len(block)
        new_next = new_instruction_offset + size
        if op in ABSOLUTE_JUMPS:
            if arg in old_offsets:
                adjusted = new_offset[arg]
            elif arg >= offset:
                adjusted = arg + total
        elif op in RELATIVE_JUMPS:
            old_target = old_next + arg
            if old_target in old_offsets:
                adjusted = new_offset[old_target] - new_next
            elif old_target >= offset:
                adjusted = arg + total
        if adjusted < 0 or adjusted > 65535:
            output.append(chr(op) + raw)
        else:
            output.append(chr(op) + code_word(adjusted))
    return ''.join(output)


def add_stack_noise(code_bytes, none_index, rate=0):
    rate = max(0, min(100, rate))
    if rate <= 0 or none_index < 0 or none_index > 65535:
        return code_bytes
    instructions = decode_instructions(code_bytes)
    insert_at = {}
    for offset, op, _arg, _raw, _size in instructions[1:]:
        if op in (EXTENDED_ARG_OP, JUMP_FORWARD_OP, JUMP_ABSOLUTE_OP, 83):
            continue
        if random.randint(1, 100) <= rate:
            insert_at[offset] = chr(LOAD_CONST_OP) + code_word(none_index) + chr(1)
    return insert_bytecode_blocks(code_bytes, insert_at)


def add_extended_arg_noise(code_bytes, rate=0):
    rate = max(0, min(100, rate))
    if rate <= 0:
        return code_bytes
    instructions = decode_instructions(code_bytes)
    insert_at = {}
    skip_ops = ABSOLUTE_JUMPS | RELATIVE_JUMPS | set([EXTENDED_ARG_OP])
    for offset, op, arg, _raw, _size in instructions[1:]:
        if op < HAVE_ARGUMENT or arg is None or op in skip_ops:
            continue
        if random.randint(1, 100) <= rate:
            insert_at[offset] = chr(EXTENDED_ARG_OP) + code_word(0)
    return insert_bytecode_blocks(code_bytes, insert_at)


def add_return_jump_gates(code_bytes, rate=0):
    rate = max(0, min(100, rate))
    if rate <= 0:
        return code_bytes
    instructions = decode_instructions(code_bytes)
    insert_at = {}
    for offset, op, _arg, _raw, _size in instructions:
        if op == 83 and random.randint(1, 100) <= rate:
            noise = ''.join(chr(LOAD_CONST_OP) + code_word(0) + chr(1) for _ in range(random.randint(1, 3)))
            insert_at[offset] = chr(JUMP_FORWARD_OP) + code_word(len(noise)) + noise
    return insert_bytecode_blocks(code_bytes, insert_at)


def jump_garbage_stream(length, aggressive=False):
    ops = [
        '\x09',
        '\x01',
        '\x02',
        chr(100) + code_word(0),
        chr(100) + code_word(0) + '\x01',
    ]
    if aggressive:
        ops.extend([
            chr(60),
            chr(83),
            chr(87),
            chr(88),
            chr(89),
            chr(108) + code_word(random.randint(0, 65535)),
            chr(109) + code_word(random.randint(0, 65535)),
            chr(111) + code_word(random.randint(0, 65535)),
            chr(112) + code_word(random.randint(0, 65535)),
            chr(114) + code_word(random.randint(0, 65535)),
            chr(115) + code_word(random.randint(0, 65535)),
            chr(119) + code_word(random.randint(0, 65535)),
            chr(120) + code_word(random.randint(0, 65535)),
            chr(121) + code_word(random.randint(0, 65535)),
            chr(122) + code_word(random.randint(0, 65535)),
            chr(132) + code_word(random.randint(0, 65535)),
            chr(135) + code_word(random.randint(0, 65535)),
        ])
    chunks = []
    while len(''.join(chunks)) < length:
        chunks.append(random.choice(ops))
    return ''.join(chunks)


def fake_code_object(depth, aggressive_poison_stream=False):
    consts = [None]
    if random.randint(0, 2):
        consts.extend([random.uniform(-9999, 9999), random_raw_bytes(random.randint(8, 48))])
    if depth > 0:
        for _ in range(random.randint(1, 3)):
            consts.append(fake_code_object(depth - 1, aggressive_poison_stream))
    return types.CodeType(
        random.randint(0, 3),
        0,
        random.randint(1, 8),
        67,
        jump_garbage_stream(random.randint(90, 900 if aggressive_poison_stream else 500), aggressive_poison_stream),
        tuple(consts),
        () if random.randint(0, 1) else tuple(random_code_name() for _ in range(random.randint(0, 3))),
        (),
        random_raw_bytes(random.randint(16, 64)),
        random_code_name(),
        -1,
        '',
        (),
        (),
    )


def empty_index_bait_code():
    bait = ''.join([
        chr(JUMP_FORWARD_OP) + code_word(0),
        chr(100) + code_word(0),
        '\x01',
        '\x09',
    ])
    return types.CodeType(
        0,
        0,
        1,
        67,
        bait,
        (None,),
        (),
        (),
        random_raw_bytes(random.randint(16, 64)),
        random_code_name(),
        -1,
        '',
        (),
        (),
    )


def anti_decompile_trap_code():
    trap = ''.join([
        chr(JUMP_FORWARD_OP) + code_word(12),
        chr(100) + code_word(65535),
        chr(124) + code_word(65535),
        chr(125) + code_word(65535),
        chr(JUMP_ABSOLUTE_OP) + code_word(65535),
        chr(100) + code_word(0),
        chr(83),
    ])
    nested = empty_index_bait_code() if random.randint(0, 1) else None
    consts = [None]
    if nested is not None:
        consts.append(nested)
    return types.CodeType(
        0,
        0,
        random.randint(1, 6),
        67,
        trap,
        tuple(consts),
        tuple(random_code_name() for _ in range(random.randint(0, 4))),
        (),
        random_safe_filename(),
        random_code_name(),
        random.randint(1, 9999),
        random_lnotab(),
        (),
        (),
    )


def obf2_poison_stream(min_bytes=120, max_bytes=900, aggressive=False):
    size = random.randint(max(32, min_bytes), max(max_bytes, min_bytes, 32))
    ops = [
        chr(JUMP_ABSOLUTE_OP) + code_word(0),
        chr(JUMP_FORWARD_OP) + code_word(0),
        chr(124) + code_word(random.randint(64, 65535)),
        chr(125) + code_word(random.randint(64, 65535)),
        chr(126) + code_word(random.randint(64, 65535)),
        chr(100) + code_word(random.randint(64, 65535)),
        chr(101) + code_word(random.randint(64, 65535)),
        chr(105) + code_word(random.randint(64, 65535)),
        chr(106) + code_word(random.randint(64, 65535)),
        chr(108) + code_word(random.randint(64, 65535)),
        chr(109) + code_word(random.randint(64, 65535)),
        chr(132) + code_word(random.randint(64, 65535)),
        chr(92) + code_word(random.randint(64, 65535)),
        chr(136) + code_word(random.randint(64, 65535)),
        chr(137) + code_word(random.randint(64, 65535)),
        chr(0),
        chr(9),
        chr(1),
        chr(2),
    ]
    if aggressive:
        ops.extend([
            chr(111) + code_word(random.randint(0, 65535)),
            chr(112) + code_word(random.randint(0, 65535)),
            chr(113) + code_word(random.randint(0, 65535)),
            chr(114) + code_word(random.randint(0, 65535)),
            chr(115) + code_word(random.randint(0, 65535)),
            chr(119) + code_word(random.randint(0, 65535)),
            chr(120) + code_word(random.randint(0, 65535)),
            chr(121) + code_word(random.randint(0, 65535)),
            chr(122) + code_word(random.randint(0, 65535)),
        ])
    chunks = [chr(JUMP_ABSOLUTE_OP) + code_word(0)]
    while len(''.join(chunks)) < size:
        chunks.append(random.choice(ops))
    return ''.join(chunks)


def taunt_variants(taunt_text, count):
    if not taunt_text or count <= 0:
        return []
    variants = []
    suffixes = ['', '!', '!!', '???', '...', random_code_name()]
    for index in range(max(0, count)):
        suffix = suffixes[index % len(suffixes)]
        variants.append(taunt_text + suffix)
    return variants


def obf2_taunt_poison_stream(min_bytes=120, max_bytes=900, aggressive=False):
    size = random.randint(max(32, min_bytes), max(max_bytes, min_bytes, 32))
    taunt_ops = [
        chr(101) + code_word(0),
        chr(106) + code_word(0),
        chr(96) + code_word(0),
        chr(90) + code_word(0),
        chr(91) + code_word(0),
        chr(108) + code_word(0),
        chr(109) + code_word(0),
    ]
    chunks = [chr(JUMP_ABSOLUTE_OP) + code_word(0)]
    while len(''.join(chunks)) < size:
        if random.randint(0, 100) < (55 if aggressive else 35):
            chunks.append(random.choice(taunt_ops))
        else:
            chunks.append(obf2_poison_stream(12, 48, aggressive))
    return ''.join(chunks)


def obf2_fake_code_object(depth, taunt_text=None, min_bytes=120, max_bytes=900, aggressive=False, taunt_repeat=1):
    variants = taunt_variants(taunt_text, taunt_repeat)
    consts = [None, False, random.uniform(-9999, 9999), random_raw_bytes(random.randint(12, 80))]
    consts.extend(variants)
    if variants:
        consts.append(tuple(variants))
    if depth > 0:
        for _ in range(random.randint(1, 3 if aggressive else 2)):
            consts.append(obf2_fake_code_object(depth - 1, taunt_text, max(40, min_bytes // 2), max(80, max_bytes // 2), aggressive, max(1, taunt_repeat // 2)))
    names = list(variants)
    names.extend(random_code_name() for _ in range(random.randint(0, 3)))
    filename = random_raw_bytes(random.randint(24, 96)) if aggressive else random_safe_filename()
    code_stream = obf2_taunt_poison_stream(min_bytes, max_bytes, aggressive) if variants else obf2_poison_stream(min_bytes, max_bytes, aggressive)
    return types.CodeType(
        random.randint(0, 2),
        0,
        random.randint(1, 8),
        67,
        code_stream,
        tuple(consts),
        tuple(names),
        (),
        filename,
        random_raw_bytes(random.randint(8, 40)) if aggressive else random_code_name(),
        -1,
        random_lnotab() if aggressive else '',
        (),
        (),
    )


def add_jump_garbage_prefix(code, min_bytes, max_bytes, aggressive_poison_stream=False):
    if max_bytes <= 0:
        return code.co_code
    size = random.randint(max(0, min_bytes), max(0, max_bytes))
    if size <= 0:
        return code.co_code
    size = min(size, 65000)
    garbage = jump_garbage_stream(size, aggressive_poison_stream)
    prefix = chr(JUMP_FORWARD_OP) + code_word(len(garbage)) + garbage
    return prefix + fix_absolute_jumps(code.co_code, len(prefix))


def add_opaque_jump_gate(code, consts, min_bytes, max_bytes, aggressive_poison_stream=False):
    if max_bytes <= 0:
        return code.co_code, consts
    size = random.randint(max(0, min_bytes), max(0, max_bytes))
    if size <= 0:
        return code.co_code, consts
    consts = list(consts)
    consts.append(True)
    true_index = len(consts) - 1
    if true_index > 65535:
        return code.co_code, consts
    dead = jump_garbage_stream(min(size, 65000), aggressive_poison_stream)
    dead_offset = 9
    prefix = ''.join([
        chr(100) + code_word(true_index),
        chr(114) + code_word(dead_offset),
        chr(JUMP_FORWARD_OP) + code_word(len(dead)),
        dead,
    ])
    return prefix + fix_absolute_jumps(code.co_code, len(prefix)), consts


def poison_code_object(code, count, taunt_text, min_blob=48, max_blob=256, depth=0, jitter=0, dead_stop_tail=0, jump_garbage_min=0, jump_garbage_max=0, fake_code_count=0, bait_code_count=0, metadata_poison=False, aggressive_poison_stream=False, cf_gate_min=0, cf_gate_max=0, cf_gate_count=1, bytecode_trampoline=False, bytecode_trampoline_rate=35, anti_decompile_traps=0, jump_poison_blocks=0, jump_poison_min=8, jump_poison_max=32, obf2_fake_layers=0, obf2_fake_count=0, obf2_fake_min=120, obf2_fake_max=900, inner_taunt_repeat=1, stack_noise_rate=0, extended_arg_noise_rate=0, return_jump_gate_rate=0, depth_density=False):
    actual_count = max(0, count)
    if jitter:
        actual_count += random.randint(0, max(0, jitter)) + min(depth * max(1, jitter // 3), max(0, jitter) * 3)
    consts = []
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            consts.append(poison_code_object(const, count, taunt_text, min_blob, max_blob, depth + 1, jitter, dead_stop_tail, jump_garbage_min, jump_garbage_max, fake_code_count, 0, metadata_poison, aggressive_poison_stream, cf_gate_min, cf_gate_max, cf_gate_count, bytecode_trampoline, bytecode_trampoline_rate, 0, max(0, jump_poison_blocks // 2), jump_poison_min, jump_poison_max, max(0, obf2_fake_layers - 1), max(0, obf2_fake_count // 2), obf2_fake_min, obf2_fake_max, max(1, inner_taunt_repeat // 2), stack_noise_rate, extended_arg_noise_rate, return_jump_gate_rate, depth_density))
        else:
            consts.append(const)
    if actual_count <= 0 and not taunt_text and dead_stop_tail <= 0 and jump_garbage_max <= 0 and stack_noise_rate <= 0 and extended_arg_noise_rate <= 0 and return_jump_gate_rate <= 0:
        return make_code_like(code, consts=consts)
    if taunt_text:
        consts.extend(taunt_variants(taunt_text, max(1, inner_taunt_repeat)))
        if inner_taunt_repeat > 1:
            consts.append(tuple(taunt_variants(taunt_text, max(1, inner_taunt_repeat // 2))))
    for _ in range(actual_count):
        selector = random.randint(0, 5)
        if selector == 0 and taunt_text:
            consts.append(taunt_text + random_bytes_literal(random.randint(4, 24)))
        elif selector == 1:
            consts.append(random_bytes_literal(random.randint(min_blob, max_blob)))
        elif selector == 2:
            consts.append(tuple(random_bytes_literal(random.randint(8, 48)) for _ in range(random.randint(2, 6))))
        elif selector == 3:
            consts.append(random.randint(-2147483648, 2147483647))
        elif selector == 4:
            consts.append(float(random.randint(-999999, 999999)) / random.randint(1, 999))
        else:
            consts.append(None)
    if fake_code_count > 0:
        for _ in range(random.randint(max(0, fake_code_count // 2), max(0, fake_code_count))):
            consts.append(fake_code_object(1, False))
    if depth == 0 and bait_code_count > 0:
        for _ in range(max(0, bait_code_count)):
            consts.append(empty_index_bait_code())
    if depth == 0 and anti_decompile_traps > 0:
        for _ in range(max(0, anti_decompile_traps)):
            consts.append(anti_decompile_trap_code())
    if obf2_fake_count > 0 and obf2_fake_layers > 0:
        local_count = obf2_fake_count if depth == 0 else max(0, obf2_fake_count // 2)
        for _ in range(max(0, local_count)):
            consts.append(obf2_fake_code_object(obf2_fake_layers - 1, taunt_text, obf2_fake_min, obf2_fake_max, aggressive_poison_stream, inner_taunt_repeat))
    rate_mul = 1.0
    if depth_density:
        rate_mul = min(2.5, 1.0 + depth * 0.35)
    local_stack_noise_rate = int(min(100, stack_noise_rate * rate_mul))
    local_extended_arg_noise_rate = int(min(100, extended_arg_noise_rate * rate_mul))
    local_return_jump_gate_rate = int(min(100, return_jump_gate_rate * rate_mul))
    code_bytes = add_jump_garbage_prefix(code, jump_garbage_min, jump_garbage_max, aggressive_poison_stream)
    none_index = None
    for idx, const in enumerate(consts):
        if const is None:
            none_index = idx
            break
    if none_index is None:
        consts.insert(0, None)
        code_bytes = rewrite_bytecode_args(code_bytes, dict((idx, idx + 1) for idx in range(len(consts) - 1)), {}, {})
        none_index = 0
    code_bytes = add_stack_noise(code_bytes, none_index, local_stack_noise_rate)
    code_bytes = add_bytecode_trampolines(code_bytes, bytecode_trampoline, bytecode_trampoline_rate)
    code_bytes = add_interleaved_jump_poison(code_bytes, jump_poison_blocks > 0, jump_poison_blocks, jump_poison_min, jump_poison_max, aggressive_poison_stream)
    code_bytes = add_return_jump_gates(code_bytes, local_return_jump_gate_rate)
    code_bytes = add_extended_arg_noise(code_bytes, local_extended_arg_noise_rate)
    if cf_gate_max > 0:
        for _ in range(max(1, cf_gate_count)):
            code_bytes, consts = add_opaque_jump_gate(make_code_like(code, code_bytes=code_bytes), consts, cf_gate_min, cf_gate_max, aggressive_poison_stream)
    if dead_stop_tail > 0:
        code_bytes += '\x00' * max(0, dead_stop_tail)
    if metadata_poison:
        return make_code_like(
            code,
            code_bytes=code_bytes,
            consts=consts,
            filename=random_safe_filename(),
            lnotab=random_lnotab(),
        )
    return make_code_like(code, code_bytes=code_bytes, consts=consts)


def ast_call(name, args):
    return ast.Call(func=ast.Name(id=name, ctx=ast.Load()), args=args, keywords=[], starargs=None, kwargs=None)


class SafeEquivalentTransformer(ast.NodeTransformer):

    def __init__(self, fold_strings=False, fold_numbers=False, rewrite_boolops=False, flatten_control_flow=False, return_gate=False, exception_gate=False, call_perturb=False, exception_gate_rate=10, call_perturb_rate=8, statement_reorder=False, statement_reorder_rate=30, statement_reorder_window=4, inner_dataflow_noise=False, inner_dataflow_rate=30, inner_dataflow_min=1, inner_dataflow_max=4, call_dispatcher=False, call_dispatcher_rate=8, flatten_control_flow_v2=False, reference_obf=False, reference_obf_rate=8):
        self.fold_strings = fold_strings
        self.fold_numbers = fold_numbers
        self.rewrite_boolops = rewrite_boolops
        self.flatten_control_flow = flatten_control_flow
        self.flatten_control_flow_v2 = flatten_control_flow_v2
        self.return_gate = return_gate
        self.exception_gate = exception_gate
        self.call_perturb = call_perturb
        self.call_dispatcher = call_dispatcher
        self.reference_obf = reference_obf
        self.exception_gate_rate = max(0, min(100, exception_gate_rate))
        self.call_perturb_rate = max(0, min(100, call_perturb_rate))
        self.call_dispatcher_rate = max(0, min(100, call_dispatcher_rate))
        self.reference_obf_rate = max(0, min(100, reference_obf_rate))
        self.statement_reorder = statement_reorder
        self.statement_reorder_rate = max(0, min(100, statement_reorder_rate))
        self.statement_reorder_window = max(2, min(12, statement_reorder_window))
        self.inner_dataflow_noise = inner_dataflow_noise
        self.inner_dataflow_rate = max(0, min(100, inner_dataflow_rate))
        self.inner_dataflow_min = max(0, inner_dataflow_min)
        self.inner_dataflow_max = max(self.inner_dataflow_min, inner_dataflow_max)

    def _has_yield(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Yield):
                return True
        return False

    def _state_test(self, name, value):
        return ast.Compare(
            left=ast.Name(id=name, ctx=ast.Load()),
            ops=[ast.Eq()],
            comparators=[ast.Num(n=value)],
        )

    def _state_set(self, name, value):
        return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=ast.Num(n=value))

    def _opaque_true_test(self):
        seed = random.randint(10, 9999)
        return ast.Compare(
            left=ast.BinOp(left=ast.Num(n=seed), op=ast.BitXor(), right=ast.Num(n=seed)),
            ops=[ast.Eq()],
            comparators=[ast.Num(n=0)],
        )

    def _dead_branch_stmt(self):
        name = random_identifier('rg')
        value = random.randint(1000, 999999)
        return ast.Assign(
            targets=[ast.Name(id=name, ctx=ast.Store())],
            value=ast.BinOp(left=ast.Num(n=value), op=ast.BitXor(), right=ast.Num(n=value ^ random.randint(1, 255))),
        )

    def _dataflow_noise_block(self):
        count = random.randint(self.inner_dataflow_min, self.inner_dataflow_max)
        lines = []
        seed_name = random_identifier('df')
        mix_name = random_identifier('df')
        seed = random.randint(1000, 999999)
        lines.append(ast.Assign(targets=[ast.Name(id=seed_name, ctx=ast.Store())], value=ast.Num(n=seed)))
        lines.append(ast.Assign(
            targets=[ast.Name(id=mix_name, ctx=ast.Store())],
            value=ast.BinOp(
                left=ast.BinOp(left=ast.Name(id=seed_name, ctx=ast.Load()), op=ast.BitXor(), right=ast.Num(n=seed)),
                op=ast.BitAnd(),
                right=ast.Num(n=random.randint(3, 31)),
            ),
        ))
        for _ in range(max(0, count - 2)):
            tmp_name = random_identifier('df')
            lines.append(ast.Assign(
                targets=[ast.Name(id=tmp_name, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Name(id=mix_name, ctx=ast.Load()),
                    op=ast.BitXor(),
                    right=ast.Num(n=random.randint(10, 9999)),
                ),
            ))
            mix_name = tmp_name
        return lines

    def _inject_dataflow_noise(self, body):
        if not self.inner_dataflow_noise or not body:
            return body
        output = []
        for stmt in body:
            if random.randint(1, 100) <= self.inner_dataflow_rate and not isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Global)):
                output.extend(self._dataflow_noise_block())
            output.append(stmt)
        return output

    def _names_read(self, node):
        result = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                result.add(child.id)
        return result

    def _names_written(self, node):
        result = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                result.add(child.id)
        return result

    def _has_unsafe_expr(self, node):
        unsafe = (ast.Call, ast.Yield, ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        for child in ast.walk(node):
            if isinstance(child, unsafe):
                return True
        return False

    def _reorderable_stmt_info(self, stmt):
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1 or self._has_unsafe_expr(stmt.value):
                return None
            target = stmt.targets[0]
            if not isinstance(target, (ast.Name, ast.Tuple, ast.List)):
                return None
            reads = self._names_read(stmt.value)
            writes = self._names_written(target)
            if not writes:
                return None
            return reads, writes
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, (ast.Num, ast.Str, ast.Name, ast.Tuple, ast.List, ast.Dict)):
            return self._names_read(stmt), set()
        return None

    def _can_swap_infos(self, left, right):
        left_reads, left_writes = left
        right_reads, right_writes = right
        if left_writes & right_reads:
            return False
        if right_writes & left_reads:
            return False
        if left_writes & right_writes:
            return False
        return True

    def _shuffle_safe_window(self, window):
        items = [(stmt, self._reorderable_stmt_info(stmt)) for stmt in window]
        if any(info is None for _stmt, info in items):
            return window
        order = list(range(len(items)))
        for _ in range(len(order) * 2):
            index = random.randint(0, len(order) - 2)
            left = order[index]
            right = order[index + 1]
            if self._can_swap_infos(items[left][1], items[right][1]):
                order[index], order[index + 1] = order[index + 1], order[index]
        if order == list(range(len(items))):
            return window
        return [items[index][0] for index in order]

    def _reorder_body(self, body):
        if not self.statement_reorder or len(body) < 3:
            return body
        output = []
        index = 0
        while index < len(body):
            info = self._reorderable_stmt_info(body[index])
            if info is None or random.randint(1, 100) > self.statement_reorder_rate:
                output.append(body[index])
                index += 1
                continue
            window = [body[index]]
            index += 1
            while index < len(body) and len(window) < self.statement_reorder_window:
                if self._reorderable_stmt_info(body[index]) is None:
                    break
                window.append(body[index])
                index += 1
            if len(window) > 1:
                output.extend(self._shuffle_safe_window(window))
            else:
                output.extend(window)
        return output

    def _reorder_nested_bodies(self, node):
        if hasattr(node, 'body'):
            node.body = self._reorder_body(node.body)
        if hasattr(node, 'orelse'):
            node.orelse = self._reorder_body(node.orelse)
        if hasattr(node, 'finalbody'):
            node.finalbody = self._reorder_body(node.finalbody)
        for handler in getattr(node, 'handlers', ()):
            handler.body = self._reorder_body(handler.body)
        return node

    def _inject_return_gates(self, body):
        output = []
        for stmt in body:
            if isinstance(stmt, ast.Return) or isinstance(stmt, ast.Raise):
                output.append(ast.If(test=self._opaque_true_test(), body=[self._dead_branch_stmt()], orelse=[self._dead_branch_stmt()]))
                output.append(stmt)
            elif isinstance(stmt, ast.If):
                stmt.body = self._inject_return_gates(stmt.body)
                stmt.orelse = self._inject_return_gates(stmt.orelse)
                output.append(stmt)
            elif isinstance(stmt, (ast.For, ast.While, ast.TryExcept, ast.TryFinally, ast.With)):
                if hasattr(stmt, 'body'):
                    stmt.body = self._inject_return_gates(stmt.body)
                if hasattr(stmt, 'orelse'):
                    stmt.orelse = self._inject_return_gates(stmt.orelse)
                if hasattr(stmt, 'finalbody'):
                    stmt.finalbody = self._inject_return_gates(stmt.finalbody)
                for handler in getattr(stmt, 'handlers', ()):
                    handler.body = self._inject_return_gates(handler.body)
                output.append(stmt)
            else:
                output.append(stmt)
        return output

    def _wrap_exception_gate(self, node):
        if not self.exception_gate or self._has_yield(node):
            return node
        if random.randint(1, 100) > self.exception_gate_rate:
            return node
        body = list(node.body)
        prefix = []
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Str):
            prefix.append(body.pop(0))
        if not body:
            return node
        final_name = random_identifier('eg')
        final_value = random.randint(1000, 999999)
        final_stmt = ast.Assign(
            targets=[ast.Name(id=final_name, ctx=ast.Store())],
            value=ast.BinOp(left=ast.Num(n=final_value), op=ast.BitXor(), right=ast.Num(n=final_value)),
        )
        node.body = prefix + [ast.TryFinally(body=body, finalbody=[final_stmt])]
        return node

    def _flatten_function_body(self, node):
        if not (self.flatten_control_flow or self.flatten_control_flow_v2) or self._has_yield(node):
            return node
        body = list(node.body)
        prefix = []
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Str):
            prefix.append(body.pop(0))
        if len(body) < 3:
            return node
        state_name = random_identifier('cf')
        states = [random.randint(1000, 9999999) for _ in body]
        seen = set()
        for index, value in enumerate(states):
            while value in seen:
                value = random.randint(1000, 9999999)
            states[index] = value
            seen.add(value)
        cases = []
        terminal = (ast.Return, ast.Raise)
        for index, stmt in enumerate(body):
            block = [stmt]
            if not isinstance(stmt, terminal):
                if index + 1 < len(states):
                    block.append(self._state_set(state_name, states[index + 1]))
                    block.append(ast.Continue())
                else:
                    block.append(ast.Break())
            cases.append(ast.If(test=self._state_test(state_name, states[index]), body=block, orelse=[]))
        if self.flatten_control_flow_v2:
            for _ in range(random.randint(1, 3)):
                decoy_state = random.randint(1000, 9999999)
                while decoy_state in seen:
                    decoy_state = random.randint(1000, 9999999)
                seen.add(decoy_state)
                cases.append(ast.If(
                    test=self._state_test(state_name, decoy_state),
                    body=self._dataflow_noise_block() + [self._state_set(state_name, states[0]), ast.Continue()],
                    orelse=[],
                ))
            random.shuffle(cases)
        loop = ast.While(test=ast.Name(id='True', ctx=ast.Load()), body=cases + [ast.Break()], orelse=[])
        node.body = prefix + [self._state_set(state_name, states[0]), loop]
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node = self._reorder_nested_bodies(node)
        node.body = self._inject_dataflow_noise(node.body)
        if self.return_gate and not self._has_yield(node):
            node.body = self._inject_return_gates(node.body)
        node = self._flatten_function_body(node)
        return self._wrap_exception_gate(node)

    def visit_Str(self, node):
        if not self.fold_strings or len(node.s) < 2:
            return node
        rev = node.s[::-1]
        new_node = ast.Subscript(
            value=ast.Str(s=rev),
            slice=ast.Slice(lower=None, upper=None, step=ast.Num(n=-1)),
            ctx=ast.Load(),
        )
        return ast.copy_location(new_node, node)

    def visit_Num(self, node):
        if not self.fold_numbers or not isinstance(node.n, int) or node.n in (-1, 0, 1):
            return node
        mask = random.randint(7, 255)
        new_node = ast.BinOp(left=ast.Num(n=node.n ^ mask), op=ast.BitXor(), right=ast.Num(n=mask))
        return ast.copy_location(new_node, node)

    def visit_BoolOp(self, node):
        self.generic_visit(node)
        if not self.rewrite_boolops or len(node.values) != 2:
            return node
        left, right = node.values
        if isinstance(node.op, ast.Or):
            new_node = ast.IfExp(test=left, body=left, orelse=right)
            return ast.copy_location(new_node, node)
        if isinstance(node.op, ast.And):
            new_node = ast.IfExp(test=left, body=right, orelse=left)
            return ast.copy_location(new_node, node)
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        if self.reference_obf and isinstance(node.func, ast.Attribute) and random.randint(1, 100) <= self.reference_obf_rate:
            attr = node.func.attr
            if attr and not attr.startswith('__') and attr not in ('func_code', 'func_globals', 'im_func', 'im_self'):
                cut = random.randint(1, len(attr) - 1) if len(attr) > 1 else 1
                attr_expr = ast.BinOp(left=ast.Str(s=attr[:cut]), op=ast.Add(), right=ast.Str(s=attr[cut:]))
                new_func = ast.Call(
                    func=ast.Name(id='getattr', ctx=ast.Load()),
                    args=[node.func.value, attr_expr],
                    keywords=[],
                    starargs=None,
                    kwargs=None,
                )
                node = ast.copy_location(ast.Call(func=new_func, args=node.args, keywords=node.keywords, starargs=node.starargs, kwargs=node.kwargs), node)
        if self.call_dispatcher and random.randint(1, 100) <= self.call_dispatcher_rate and not node.keywords and node.starargs is None and node.kwargs is None:
            table_node = ast.Tuple(elts=[node.func], ctx=ast.Load())
            pick_arg = random_identifier('cd')
            idx_arg = random_identifier('ci')
            picker = ast.Lambda(
                args=ast.arguments(args=[ast.Name(id=pick_arg, ctx=ast.Param()), ast.Name(id=idx_arg, ctx=ast.Param())], vararg=None, kwarg=None, defaults=[]),
                body=ast.Subscript(value=ast.Name(id=pick_arg, ctx=ast.Load()), slice=ast.Index(value=ast.Name(id=idx_arg, ctx=ast.Load())), ctx=ast.Load()),
            )
            new_func = ast.Call(func=picker, args=[table_node, ast.Num(n=0)], keywords=[], starargs=None, kwargs=None)
            return ast.copy_location(ast.Call(func=new_func, args=node.args, keywords=[], starargs=None, kwargs=None), node)
        if not self.call_perturb or random.randint(1, 100) > self.call_perturb_rate:
            return node
        arg_name = random_identifier('cp')
        identity = ast.Lambda(
            args=ast.arguments(args=[ast.Name(id=arg_name, ctx=ast.Param())], vararg=None, kwarg=None, defaults=[]),
            body=ast.Name(id=arg_name, ctx=ast.Load()),
        )
        new_func = ast.Call(func=identity, args=[node.func], keywords=[], starargs=None, kwargs=None)
        new_node = ast.Call(func=new_func, args=node.args, keywords=node.keywords, starargs=node.starargs, kwargs=node.kwargs)
        return ast.copy_location(new_node, node)


class StringEncryptTransformer(ast.NodeTransformer):

    def __init__(self, decoder_name, values):
        self.decoder_name = decoder_name
        self.values = values

    def visit_Str(self, node):
        index = len(self.values)
        self.values.append(node.s)
        new_node = ast.Call(
            func=ast.Name(id=self.decoder_name, ctx=ast.Load()),
            args=[ast.Num(n=index)],
            keywords=[],
            starargs=None,
            kwargs=None,
        )
        return ast.copy_location(new_node, node)


class ConstPoolTransformer(ast.NodeTransformer):

    def __init__(self, pool_name, values, enabled_strings=False, enabled_numbers=False):
        self.pool_name = pool_name
        self.values = values
        self.enabled_strings = enabled_strings
        self.enabled_numbers = enabled_numbers

    def _pool_ref(self, value, node):
        index = len(self.values)
        self.values.append(value)
        new_node = ast.Subscript(
            value=ast.Name(id=self.pool_name, ctx=ast.Load()),
            slice=ast.Index(value=ast.Num(n=index)),
            ctx=ast.Load(),
        )
        return ast.copy_location(new_node, node)

    def visit_Str(self, node):
        if not self.enabled_strings or len(node.s) < 2:
            return node
        return self._pool_ref(node.s, node)

    def visit_Num(self, node):
        if not self.enabled_numbers or not isinstance(node.n, int) or node.n in (-1, 0, 1):
            return node
        return self._pool_ref(node.n, node)


def build_fake_function_defs(count, taunt_text=None):
    result = []
    for _ in range(max(0, count)):
        func_name = random_identifier('fn')
        arg_name = random_identifier('a')
        tmp_name = random_identifier('t')
        seed = random.randint(1000, 999999)
        body = [
            ast.Expr(value=ast.Str(s=(taunt_text or random_code_name()))),
            ast.Assign(
                targets=[ast.Name(id=tmp_name, ctx=ast.Store())],
                value=ast.BinOp(left=ast.Num(n=seed), op=ast.BitXor(), right=ast.Num(n=seed)),
            ),
            ast.If(
                test=ast.Compare(left=ast.Name(id=tmp_name, ctx=ast.Load()), ops=[ast.Eq()], comparators=[ast.Num(n=0)]),
                body=[ast.Return(value=ast.Name(id=arg_name, ctx=ast.Load()))],
                orelse=[ast.Return(value=ast.Num(n=seed))],
            ),
        ]
        result.append(ast.FunctionDef(
            name=func_name,
            args=ast.arguments(args=[ast.Name(id=arg_name, ctx=ast.Param())], vararg=None, kwarg=None, defaults=[]),
            body=body,
            decorator_list=[],
        ))
    return result


def build_fake_class_defs(count, taunt_text=None):
    result = []
    previous_name = None
    for _ in range(max(0, count)):
        class_name = random_identifier('cls')
        method_name = random_identifier('m')
        value_name = random_identifier('v')
        seed = random.randint(1000, 999999)
        bases = [ast.Name(id=previous_name, ctx=ast.Load())] if previous_name and random.randint(0, 1) else []
        body = [
            ast.Expr(value=ast.Str(s=(taunt_text or random_code_name()))),
            ast.Assign(
                targets=[ast.Name(id=value_name, ctx=ast.Store())],
                value=ast.Tuple(elts=[ast.Num(n=seed), ast.Str(s=random_bytes_literal(random.randint(8, 24)))], ctx=ast.Load()),
            ),
            ast.FunctionDef(
                name=method_name,
                args=ast.arguments(args=[ast.Name(id='self', ctx=ast.Param()), ast.Name(id='x', ctx=ast.Param())], vararg=None, kwarg=None, defaults=[ast.Num(n=0)]),
                body=[
                    ast.TryFinally(
                        body=[ast.If(
                            test=ast.Compare(left=ast.BinOp(left=ast.Num(n=seed), op=ast.BitXor(), right=ast.Num(n=seed)), ops=[ast.Eq()], comparators=[ast.Num(n=0)]),
                            body=[ast.Return(value=ast.Name(id='x', ctx=ast.Load()))],
                            orelse=[ast.Return(value=ast.Num(n=seed))],
                        )],
                        finalbody=[ast.Expr(value=ast.Str(s=random_bytes_literal(random.randint(8, 32))))],
                    )
                ],
                decorator_list=[],
            ),
        ]
        result.append(ast.ClassDef(name=class_name, bases=bases, body=body, decorator_list=[]))
        previous_name = class_name
    return result


def _encrypt_one_string(value, chain, key):
    is_unicode = isinstance(value, str)
    data = value.encode('utf-8') if is_unicode else value
    if 'zlib' in chain:
        data = zlib.compress(data, 9)
    if 'xor' in chain:
        data = xor_data(data, key)
    if 'add' in chain:
        data = ''.join(chr((ord(ch) + ord(key[index % len(key)])) & 255) for index, ch in enumerate(data))
    if 'reverse' in chain:
        data = data[::-1]
    return (1 if is_unicode else 0, data)


def build_string_decoder_prelude(decoder_name, table_name, key_name, zlib_name, encrypted, chain, key):
    index_arg = random_identifier('i')
    row_name = random_identifier('row')
    lines = [
        '%s = %r' % (table_name, encrypted),
        '%s = %r' % (key_name, key),
    ]
    if 'zlib' in chain:
        lines.append('import zlib as %s' % zlib_name)
    lines.extend([
        'def %s(%s):' % (decoder_name, index_arg),
        '    %s = %s[%s]' % (row_name, table_name, index_arg),
    ])
    data_name = random_identifier('d')
    key_arg = random_identifier('k')
    pos_arg = random_identifier('p')
    ch_arg = random_identifier('c')
    lines.extend([
        '    %s = %s[1]' % (data_name, row_name),
    ])
    if 'reverse' in chain:
        lines.append('    %s = %s[::-1]' % (data_name, data_name))
    if 'add' in chain:
        lines.extend([
            '    %s = %s' % (key_arg, key_name),
            '    %s = \'\'.join(chr((ord(%s) - ord(%s[%s %% len(%s)])) & 255) for %s, %s in enumerate(%s))' % (
                data_name, ch_arg, key_arg, pos_arg, key_arg, pos_arg, ch_arg, data_name,
            ),
        ])
    if 'xor' in chain:
        lines.extend([
            '    %s = %s' % (key_arg, key_name),
            '    %s = \'\'.join(chr(ord(%s) ^ ord(%s[%s %% len(%s)])) for %s, %s in enumerate(%s))' % (
                data_name, ch_arg, key_arg, pos_arg, key_arg, pos_arg, ch_arg, data_name,
            ),
        ])
    if 'zlib' in chain:
        lines.append('    %s = %s.decompress(%s)' % (data_name, zlib_name, data_name))
    lines.extend([
        '    if %s[0]:' % row_name,
        "        return %s.decode('utf-8')" % data_name,
        '    return %s' % data_name,
    ])
    return '\n'.join(lines) + '\n'


def compile_obfuscated_source(source, filename, string_chain=None, fold_strings=False, fold_numbers=False, rewrite_boolops=False, flatten_control_flow=False, return_gate=False, exception_gate=False, call_perturb=False, exception_gate_rate=10, call_perturb_rate=8, statement_reorder=False, statement_reorder_rate=30, statement_reorder_window=4, inner_dataflow_noise=False, inner_dataflow_rate=30, inner_dataflow_min=1, inner_dataflow_max=4, const_pool_strings=False, const_pool_numbers=False, call_dispatcher=False, call_dispatcher_rate=8, fake_function_count=0, flatten_control_flow_v2=False, taunt_text=None, reference_obf=False, reference_obf_rate=8, fake_class_count=0):
    tree = ast.parse(source, filename)
    if fold_strings or fold_numbers or rewrite_boolops or flatten_control_flow or return_gate or exception_gate or call_perturb or statement_reorder or inner_dataflow_noise or call_dispatcher or flatten_control_flow_v2 or reference_obf:
        tree = SafeEquivalentTransformer(fold_strings, fold_numbers, rewrite_boolops, flatten_control_flow, return_gate, exception_gate, call_perturb, exception_gate_rate, call_perturb_rate, statement_reorder, statement_reorder_rate, statement_reorder_window, inner_dataflow_noise, inner_dataflow_rate, inner_dataflow_min, inner_dataflow_max, call_dispatcher, call_dispatcher_rate, flatten_control_flow_v2, reference_obf, reference_obf_rate).visit(tree)
        ast.fix_missing_locations(tree)
    if const_pool_strings or const_pool_numbers:
        pool_name = random_identifier('pool')
        pool_values = []
        tree = ConstPoolTransformer(pool_name, pool_values, const_pool_strings, const_pool_numbers).visit(tree)
        if pool_values:
            insert_at = 0
            body = tree.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Str):
                insert_at = 1
            while insert_at < len(body) and isinstance(body[insert_at], ast.ImportFrom) and body[insert_at].module == '__future__':
                insert_at += 1
            tree.body = body[:insert_at] + [ast.Assign(targets=[ast.Name(id=pool_name, ctx=ast.Store())], value=ast.Tuple(elts=[ast.Str(s=v) if isinstance(v, str) else ast.Num(n=v) for v in pool_values], ctx=ast.Load()))] + body[insert_at:]
        ast.fix_missing_locations(tree)
    if fake_function_count > 0:
        tree.body.extend(build_fake_function_defs(fake_function_count, taunt_text))
        ast.fix_missing_locations(tree)
    if fake_class_count > 0:
        tree.body.extend(build_fake_class_defs(fake_class_count, taunt_text))
        ast.fix_missing_locations(tree)
    chain = [item for item in (string_chain or ()) if item]
    if not chain:
        return compile(tree, filename, 'exec')
    decoder_name = random_identifier('s')
    table_name = random_identifier('st')
    key_name = random_identifier('sk')
    zlib_name = random_identifier('sz')
    values = []
    tree = StringEncryptTransformer(decoder_name, values).visit(tree)
    ast.fix_missing_locations(tree)
    if not values:
        return compile(tree, filename, 'exec')
    key = os.urandom(max(16, min(64, 24 + len(values) % 23)))
    encrypted = [_encrypt_one_string(value, chain, key) for value in values]
    prelude = ast.parse(build_string_decoder_prelude(decoder_name, table_name, key_name, zlib_name, encrypted, chain, key))
    insert_at = 0
    body = tree.body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Str):
        insert_at = 1
    while insert_at < len(body) and isinstance(body[insert_at], ast.ImportFrom) and body[insert_at].module == '__future__':
        insert_at += 1
    tree.body = body[:insert_at] + prelude.body + body[insert_at:]
    ast.fix_missing_locations(tree)
    return compile(tree, filename, 'exec')


def encrypt_source_strings(source, filename, chain):
    return compile_obfuscated_source(source, filename, chain)


def _old_encrypt_source_strings(source, filename, chain):
    chain = [item for item in chain if item]
    if not chain:
        return compile(source, filename, 'exec', 0, True)
    tree = ast.parse(source, filename)
    decoder_name = random_identifier('s')
    table_name = random_identifier('st')
    key_name = random_identifier('sk')
    zlib_name = random_identifier('sz')
    values = []
    tree = StringEncryptTransformer(decoder_name, values).visit(tree)
    ast.fix_missing_locations(tree)
    if not values:
        return compile(tree, filename, 'exec')
    key = os.urandom(max(16, min(64, 24 + len(values) % 23)))
    encrypted = [_encrypt_one_string(value, chain, key) for value in values]
    prelude = ast.parse(build_string_decoder_prelude(decoder_name, table_name, key_name, zlib_name, encrypted, chain, key))
    insert_at = 0
    body = tree.body
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Str):
        insert_at = 1
    while insert_at < len(body) and isinstance(body[insert_at], ast.ImportFrom) and body[insert_at].module == '__future__':
        insert_at += 1
    tree.body = body[:insert_at] + prelude.body + body[insert_at:]
    ast.fix_missing_locations(tree)
    return compile(tree, filename, 'exec')


def pack_source(source, key, cipher_mode, chacha_level, precompiled_payload=None, mcs_opmap_version=0, op_overrides=None, const_poison_count=0, taunt_text=None, string_chain=None, fold_strings=False, fold_numbers=False, rewrite_boolops=False, flatten_control_flow=False, return_gate=False, exception_gate=False, call_perturb=False, exception_gate_rate=10, call_perturb_rate=8, statement_reorder=False, statement_reorder_rate=30, statement_reorder_window=4, const_poison_jitter=0, dead_stop_tail=0, jump_garbage_min=0, jump_garbage_max=0, fake_code_count=0, bait_code_count=0, metadata_poison=False, aggressive_poison_stream=False, double_code_wrap=False, dump_obf_pyc=None, cf_gate_min=0, cf_gate_max=0, cf_gate_count=1, bytecode_trampoline=False, bytecode_trampoline_rate=35, anti_decompile_traps=0, jump_poison_blocks=0, jump_poison_min=8, jump_poison_max=32, obf2_fake_layers=0, obf2_fake_count=0, obf2_fake_min=120, obf2_fake_max=900, inner_taunt_repeat=1, inner_dataflow_noise=False, inner_dataflow_rate=30, inner_dataflow_min=1, inner_dataflow_max=4, const_pool_strings=False, const_pool_numbers=False, call_dispatcher=False, call_dispatcher_rate=8, fake_function_count=0, flatten_control_flow_v2=False, inner_opcode_tunnel=False, inner_opcode_table=None, shuffle_consts=False, shuffle_names=False, fake_name_count=0, opcode_tunnel_decoys=0, opcode_tunnel_double_map=False, reference_obf=False, reference_obf_rate=8, fake_class_count=0, opcode_tunnel_stages=1, shuffle_varnames=False, line_metadata_poison=False, stack_noise_rate=0, extended_arg_noise_rate=0, return_jump_gate_rate=0, depth_density=False, per_code_opcode_table=False):
    if precompiled_payload:
        raw_payload = read_file(precompiled_payload)
        if dump_obf_pyc:
            write_pyc(dump_obf_pyc, marshal.loads(raw_payload))
    else:
        op_map = None
        if mcs_opmap_version:
            op_map = load_std2mcs_map(mcs_opmap_version)
            op_map.update(op_overrides or {})
        code = compile_obfuscated_source(source, '<payload>', string_chain or (), fold_strings, fold_numbers, rewrite_boolops, flatten_control_flow, return_gate, exception_gate, call_perturb, exception_gate_rate, call_perturb_rate, statement_reorder, statement_reorder_rate, statement_reorder_window, inner_dataflow_noise, inner_dataflow_rate, inner_dataflow_min, inner_dataflow_max, const_pool_strings, const_pool_numbers, call_dispatcher, call_dispatcher_rate, fake_function_count, flatten_control_flow_v2, taunt_text, reference_obf, reference_obf_rate, fake_class_count)
        if shuffle_consts or shuffle_names or shuffle_varnames:
            code = shuffle_code_metadata(code, shuffle_consts, shuffle_names, fake_name_count, taunt_text, shuffle_varnames)
        if line_metadata_poison:
            code = poison_code_object(code, 0, None, metadata_poison=True)
        code = poison_code_object(code, const_poison_count, taunt_text, jitter=const_poison_jitter, dead_stop_tail=dead_stop_tail, jump_garbage_min=jump_garbage_min, jump_garbage_max=jump_garbage_max, fake_code_count=fake_code_count, bait_code_count=bait_code_count, metadata_poison=metadata_poison, aggressive_poison_stream=aggressive_poison_stream, cf_gate_min=cf_gate_min, cf_gate_max=cf_gate_max, cf_gate_count=cf_gate_count, bytecode_trampoline=bytecode_trampoline, bytecode_trampoline_rate=bytecode_trampoline_rate, anti_decompile_traps=anti_decompile_traps, jump_poison_blocks=jump_poison_blocks, jump_poison_min=jump_poison_min, jump_poison_max=jump_poison_max, obf2_fake_layers=obf2_fake_layers, obf2_fake_count=obf2_fake_count, obf2_fake_min=obf2_fake_min, obf2_fake_max=obf2_fake_max, inner_taunt_repeat=inner_taunt_repeat, stack_noise_rate=stack_noise_rate, extended_arg_noise_rate=extended_arg_noise_rate, return_jump_gate_rate=return_jump_gate_rate, depth_density=depth_density)
        if dump_obf_pyc:
            dump_code = code
            if double_code_wrap:
                dump_code = wrap_code_in_double_loader(dump_code, '<payload.cpython.wrap>', max(1, const_poison_count // 2), taunt_text)
            if inner_opcode_tunnel:
                dump_code = wrap_code_in_opcode_tunnel(dump_code, '<payload.cpython.tunnel>', max(1, const_poison_count // 2), taunt_text, 0, op_overrides, True, inner_opcode_table, opcode_tunnel_decoys, opcode_tunnel_double_map, opcode_tunnel_stages, per_code_opcode_table)
            write_pyc(dump_obf_pyc, dump_code)
        if inner_opcode_tunnel:
            code = wrap_code_in_opcode_tunnel(code, '<payload.tunnel>', max(1, const_poison_count // 2), taunt_text, mcs_opmap_version, op_overrides, True, inner_opcode_table, opcode_tunnel_decoys, opcode_tunnel_double_map, opcode_tunnel_stages, per_code_opcode_table)
            raw_payload = marshal.dumps(code)
            raw = zlib.compress(raw_payload, 9)[::-1]
            raw = ''.join(chr(ord(ch) ^ (index % 256)) for index, ch in enumerate(raw))
            if cipher_mode == 'chacha':
                raw = chacha_crypt(raw, key, rounds=chacha_level)
            raw = xor_data(raw, key)
            return base64.b64encode(raw)
        if op_map:
            code = sanitize_code_for_mcs(code)
        if op_map:
            code = remap_code_object(code, op_map)
        if double_code_wrap:
            code = wrap_code_in_double_loader(code, '<payload.wrap>', max(1, const_poison_count // 2), taunt_text)
            if op_map:
                code = remap_code_object(code, op_map)
        raw_payload = marshal.dumps(code)
    raw = zlib.compress(raw_payload, 9)[::-1]
    raw = ''.join(chr(ord(ch) ^ (index % 256)) for index, ch in enumerate(raw))
    if cipher_mode == 'chacha':
        raw = chacha_crypt(raw, key, rounds=chacha_level)
    raw = xor_data(raw, key)
    return base64.b64encode(raw)


def wrap_code_in_double_loader(code, label, poison_count, taunt_text):
    raw = marshal.dumps(code)
    key = os.urandom(24)
    blob = base64.b64encode(xor_data(zlib.compress(raw, 9)[::-1], key))
    loader_source = """# -*- coding: utf-8 -*-
import base64 as _b
import zlib as _z
import marshal as _m
_k = {key!r}
_d = _b.b64decode({blob!r})
_d = ''.join(chr(ord(_c) ^ ord(_k[_i % len(_k)])) for _i, _c in enumerate(_d))
_d = _z.decompress(_d[::-1])
_c = _m.loads(_d)
(lambda: None).__class__(_c, globals())()
""".format(key=key, blob=blob)
    wrapped = compile(loader_source, label, 'exec', 0, True)
    return poison_code_object(wrapped, poison_count, taunt_text)


def wrap_code_in_opcode_tunnel(code, label, poison_count, taunt_text, mcs_opmap_version=0, op_overrides=None, outer_poison=True, inner_opcode_table=None, decoy_count=0, double_map=False, stage_count=1, per_code_table=False):
    std_to_custom, custom_to_std, custom_has_arg = build_inner_custom_opcode_maps(code, inner_opcode_table)
    runtime_map = custom_to_std
    runtime_op_map = None
    if mcs_opmap_version:
        runtime_op_map = load_std2mcs_map(mcs_opmap_version)
        runtime_op_map.update(op_overrides or {})
        runtime_map = dict((custom, runtime_op_map.get(std, std)) for custom, std in list(custom_to_std.items()))
    if per_code_table:
        stored, root_map = remap_code_object_per_code(code, runtime_op_map, inner_opcode_table)
        items = root_map[0]
        custom_has_arg = root_map[1]
    else:
        stored = remap_code_object(code, std_to_custom)
        items = sorted(runtime_map.items())
    raw = marshal.dumps(stored)
    key = os.urandom(24)
    blob = base64.b64encode(xor_data(zlib.compress(raw, 9)[::-1], key))
    if double_map:
        mid_values = list(range(256))
        random.shuffle(mid_values)
        custom_to_mid = []
        mid_to_runtime = []
        for index, (custom, runtime) in enumerate(items):
            mid = mid_values[index]
            custom_to_mid.append((custom, mid))
            mid_to_runtime.append((mid, runtime))
        items = (custom_to_mid, mid_to_runtime)
    map_key = os.urandom(23)
    map_raw = marshal.dumps((items, custom_has_arg))
    map_blob = base64.b64encode(xor_data(zlib.compress(map_raw, 9)[::-1], map_key))
    map_chunks = []
    chunk_size = random.randint(18, 42)
    for chunk_index, start in enumerate(range(0, len(map_blob), chunk_size)):
        map_chunks.append((chunk_index, map_blob[start:start + chunk_size]))
    random.shuffle(map_chunks)
    blob_items = [(0, blob)]
    for decoy_index in range(max(0, decoy_count)):
        fake_source = "x = %d\ny = %d\n" % (random.randint(10, 9999), random.randint(10, 9999))
        fake_code = compile(fake_source, '<decoy.%d>' % decoy_index, 'exec', 0, True)
        fake_code = poison_code_object(fake_code, max(1, poison_count // 2), taunt_text)
        fake_raw = marshal.dumps(remap_code_object(fake_code, std_to_custom))
        fake_key = os.urandom(24)
        fake_blob = base64.b64encode(xor_data(zlib.compress(fake_raw, 9)[::-1], fake_key))
        blob_items.append((decoy_index + 1, fake_blob))
    random.shuffle(blob_items)
    map_name = random_identifier('om')
    hasarg_name = random_identifier('oh')
    map_key_name = random_identifier('okey')
    map_blob_name = random_identifier('oblob')
    map_chunks_name = random_identifier('ochunks')
    map_pair_name = random_identifier('opair')
    blob_items_name = random_identifier('oblobs')
    blob_pick_name = random_identifier('opick')
    fix_name = random_identifier('of')
    remap_name = random_identifier('or')
    code_name = random_identifier('oc')
    const_name = random_identifier('ok')
    out_name = random_identifier('oo')
    idx_name = random_identifier('oi')
    op_name = random_identifier('op')
    custom_name = random_identifier('ou')
    raw_name = random_identifier('od')
    key_name = random_identifier('oy')
    decode_map_name = random_identifier('dm')
    decode_blob_name = random_identifier('db')
    run_name = random_identifier('rn')
    stage_count = max(1, min(3, int(stage_count or 1)))
    if stage_count > 1:
        prelude = """def {decode_map_name}():
    {map_chunks_name}.sort()
    {map_blob_name} = _b.b64decode(''.join(_x[1] for _x in {map_chunks_name}))
    {map_blob_name} = ''.join(chr(ord(_c) ^ ord({map_key_name}[_i % len({map_key_name})])) for _i, _c in enumerate({map_blob_name}))
    {map_blob_name} = _z.decompress({map_blob_name}[::-1])
    {map_pair_name} = _m.loads({map_blob_name})
    if isinstance({map_pair_name}[0], tuple):
        return dict((k, dict({map_pair_name}[0][1]).get(v, v)) for k, v in dict({map_pair_name}[0][0]).items()), set({map_pair_name}[1])
    return dict({map_pair_name}[0]), set({map_pair_name}[1])
{map_name}, {hasarg_name} = {decode_map_name}()
"""
        if stage_count > 2:
            blob_stage = """def {decode_blob_name}():
    {key_name} = ''.join(chr(ord(_c) ^ ((_i * 17 + len({map_name}) + len({hasarg_name})) & 255)) for _i, _c in enumerate({masked_key!r}))
    {blob_items_name} = {blob_items!r}
    {blob_pick_name} = [v for k, v in {blob_items_name} if ((k ^ len({map_name})) == len({map_name}))][0]
    {raw_name} = _b.b64decode({blob_pick_name})
    {raw_name} = ''.join(chr(ord(_c) ^ ord({key_name}[_i % len({key_name})])) for _i, _c in enumerate({raw_name}))
    return _z.decompress({raw_name}[::-1])
"""
            final_stage = """{remap_name} = {fix_name}(_m.loads({decode_blob_name}()))
(lambda: None).__class__({remap_name}, globals())()
"""
        else:
            blob_stage = ""
            final_stage = """{key_name} = ''.join(chr(ord(_c) ^ ((_i * 17 + len({map_name}) + len({hasarg_name})) & 255)) for _i, _c in enumerate({masked_key!r}))
{blob_items_name} = {blob_items!r}
{blob_pick_name} = [v for k, v in {blob_items_name} if ((k ^ len({map_name})) == len({map_name}))][0]
{raw_name} = _b.b64decode({blob_pick_name})
{raw_name} = ''.join(chr(ord(_c) ^ ord({key_name}[_i % len({key_name})])) for _i, _c in enumerate({raw_name}))
{raw_name} = _z.decompress({raw_name}[::-1])
{remap_name} = {fix_name}(_m.loads({raw_name}))
(lambda: None).__class__({remap_name}, globals())()
"""
    else:
        prelude = """{map_chunks_name}.sort()
{map_blob_name} = _b.b64decode(''.join(_x[1] for _x in {map_chunks_name}))
{map_blob_name} = ''.join(chr(ord(_c) ^ ord({map_key_name}[_i % len({map_key_name})])) for _i, _c in enumerate({map_blob_name}))
{map_blob_name} = _z.decompress({map_blob_name}[::-1])
{map_pair_name} = _m.loads({map_blob_name})
if isinstance({map_pair_name}[0], tuple):
    {map_name} = dict((k, dict({map_pair_name}[0][1]).get(v, v)) for k, v in dict({map_pair_name}[0][0]).items())
else:
    {map_name} = dict({map_pair_name}[0])
{hasarg_name} = set({map_pair_name}[1])
"""
        blob_stage = ""
        final_stage = """{key_name} = ''.join(chr(ord(_c) ^ ((_i * 17 + len({map_name}) + len({hasarg_name})) & 255)) for _i, _c in enumerate({masked_key!r}))
{blob_items_name} = {blob_items!r}
{blob_pick_name} = [v for k, v in {blob_items_name} if ((k ^ len({map_name})) == len({map_name}))][0]
{raw_name} = _b.b64decode({blob_pick_name})
{raw_name} = ''.join(chr(ord(_c) ^ ord({key_name}[_i % len({key_name})])) for _i, _c in enumerate({raw_name}))
{raw_name} = _z.decompress({raw_name}[::-1])
{remap_name} = {fix_name}(_m.loads({raw_name}))
(lambda: None).__class__({remap_name}, globals())()
"""
    stage_values = dict(
        decode_map_name=decode_map_name,
        decode_blob_name=decode_blob_name,
        map_chunks_name=map_chunks_name,
        map_blob_name=map_blob_name,
        map_key_name=map_key_name,
        map_pair_name=map_pair_name,
        map_name=map_name,
        hasarg_name=hasarg_name,
        key_name=key_name,
        masked_key=''.join(chr(ord(ch) ^ ((index * 17 + len(runtime_map) + len(custom_has_arg)) & 255)) for index, ch in enumerate(key)),
        blob_items_name=blob_items_name,
        blob_items=blob_items,
        blob_pick_name=blob_pick_name,
        raw_name=raw_name,
        remap_name=remap_name,
        fix_name=fix_name,
    )
    prelude = prelude.format(**stage_values)
    blob_stage = blob_stage.format(**stage_values)
    final_stage = final_stage.format(**stage_values)
    loader_source = """# -*- coding: utf-8 -*-
import base64 as _b
import zlib as _z
import marshal as _m
{map_key_name} = {map_key!r}
{map_chunks_name} = {map_chunks!r}
{prelude}
def {fix_name}({code_name}):
    _lm = {map_name}
    _lh = {hasarg_name}
    _cc = list({code_name}.co_consts)
    if _cc and isinstance(_cc[-1], tuple) and len(_cc[-1]) == 3:
        _mi = _cc.pop()
        _lm = dict(_mi[0])
        _lh = set(_mi[1])
    {const_name} = []
    for _v in _cc:
        if getattr(_v, 'co_code', None) is not None:
            {const_name}.append({fix_name}(_v))
        else:
            {const_name}.append(_v)
    {out_name} = []
    {idx_name} = 0
    while {idx_name} < len({code_name}.co_code):
        {custom_name} = ord({code_name}.co_code[{idx_name}])
        {op_name} = _lm.get({custom_name}, {custom_name})
        {out_name}.append(chr({op_name}))
        {idx_name} += 1
        if {custom_name} in _lh and {idx_name} + 1 < len({code_name}.co_code):
            {out_name}.append({code_name}.co_code[{idx_name}])
            {out_name}.append({code_name}.co_code[{idx_name} + 1])
            {idx_name} += 2
    return (lambda: None).func_code.__class__(
        {code_name}.co_argcount, {code_name}.co_nlocals, {code_name}.co_stacksize,
        {code_name}.co_flags, ''.join({out_name}), tuple({const_name}),
        {code_name}.co_names, {code_name}.co_varnames, {code_name}.co_filename,
        {code_name}.co_name, {code_name}.co_firstlineno, {code_name}.co_lnotab,
        {code_name}.co_freevars, {code_name}.co_cellvars)
{blob_stage}
{final_stage}
""".format(
        map_name=map_name,
        hasarg_name=hasarg_name,
        fix_name=fix_name,
        remap_name=remap_name,
        code_name=code_name,
        const_name=const_name,
        map_key_name=map_key_name,
        map_blob_name=map_blob_name,
        map_chunks_name=map_chunks_name,
        map_pair_name=map_pair_name,
        blob_items_name=blob_items_name,
        blob_pick_name=blob_pick_name,
        out_name=out_name,
        idx_name=idx_name,
        op_name=op_name,
        custom_name=custom_name,
        raw_name=raw_name,
        key_name=key_name,
        decode_map_name=decode_map_name,
        decode_blob_name=decode_blob_name,
        run_name=run_name,
        prelude=prelude,
        blob_stage=blob_stage,
        final_stage=final_stage,
        map_key=map_key,
        map_chunks=map_chunks,
        masked_key=''.join(chr(ord(ch) ^ ((index * 17 + len(runtime_map) + len(custom_has_arg)) & 255)) for index, ch in enumerate(key)),
        blob_items=blob_items,
    )
    wrapper = compile(loader_source, label, 'exec', 0, True)
    if outer_poison:
        wrapper = poison_code_object(wrapper, poison_count, taunt_text)
    if mcs_opmap_version:
        wrapper = sanitize_code_for_mcs(wrapper)
        wrapper = remap_code_object(wrapper, runtime_op_map)
    return wrapper


def cipher_decode_block(cipher_mode, names):
    indent = '    '
    if cipher_mode == 'chacha':
        return (
            indent + 'import _chacha as {chacha_name}\n' +
            indent + '{chacha_owner} = type({chacha_owner_label}, (object,), {{}})()\n' +
            indent + '{chacha_handle} = {chacha_name}.create({chacha_owner}, ({chacha_level}).__hash__(), {key_var})\n' +
            indent + 'try:\n' +
            indent + '    {blob_var} = {chacha_name}.get_encrypted_text({chacha_handle}, {blob_var}, len({blob_var}))\n' +
            indent + 'finally:\n' +
            indent + '    try:\n' +
            indent + '        {chacha_name}.destroy({chacha_handle})\n' +
            indent + '    except Exception:\n' +
            indent + '        pass\n' +
            indent + '{blob_var} = {xor_name}({blob_var}, {key_var})'
        ).format(**names)
    return indent + '{blob_var} = {xor_name}({blob_var}, {key_var})'.format(**names)


def write_file(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, 'wb') as handle:
        handle.write(data)


def read_file(path):
    with open(path, 'rb') as handle:
        return handle.read()


def write_pyc(path, code, timestamp=None):
    if timestamp is None:
        timestamp = time.time()
    write_file(path, build_timestamp_pyc(code, timestamp))


def read_json_config(path):
    if not path:
        return {}
    data = read_file(path)
    if not data.strip():
        return {}
    return json.loads(data)


def normalize_config_key(key):
    return key.replace('-', '_')


def apply_config_defaults(parser, config):
    if not config:
        return
    action_dests = set(action.dest for action in parser._actions)
    defaults = {}
    for key, value in list(config.items()):
        dest = normalize_config_key(key)
        if dest in action_dests:
            defaults[dest] = value
    if defaults:
        parser.set_defaults(**defaults)


def require_args(args, names):
    missing = [name for name in names if not getattr(args, name, None)]
    if missing:
        raise SystemExit('error: missing required arguments: %s' % ', '.join('--' + name.replace('_', '-') for name in missing))


def module_path_from_class(class_path):
    return class_path.rsplit('.', 1)[0]


def source_file_for_module(root, module_name):
    rel = module_name.replace('.', os.sep) + '.py'
    direct = os.path.join(root, rel)
    if os.path.isfile(direct):
        return direct
    base = os.path.basename(rel)
    fallback = os.path.join(root, base)
    if os.path.isfile(fallback):
        return fallback
    raise IOError('cannot find source for module %s under %s' % (module_name, root))


def is_ui_path(path):
    parts = [part.lower() for part in path.replace('\\', '/').split('/')]
    name = os.path.basename(path).lower()
    return 'ui' in parts or 'uis' in parts or name.endswith('ui.py') or '_ui' in name or 'screen' in name


def is_client_only_module(module_name):
    parts = [part.lower() for part in module_name.split('.')]
    joined = '.'.join(parts)
    filename = parts[-1] if parts else ''
    if 'client' in parts or 'ui' in parts or 'uis' in parts or 'uiscript' in parts:
        return True
    if filename.endswith('ui') or filename.endswith('_ui') or 'screen' in filename:
        return True
    return '.client.' in joined or '.uiscript.' in joined


def is_server_only_module(module_name):
    parts = [part.lower() for part in module_name.split('.')]
    joined = '.'.join(parts)
    return 'server' in parts or '.server.' in joined


def should_skip_generated_file(filename):
    if filename == 'modMain.py':
        return True
    if filename == '_payload_source.py':
        return True
    if filename.startswith('modMain_'):
        return True
    if filename.startswith('payload_'):
        return True
    return False


def module_name_for_file(root, namespace, path):
    rel = os.path.relpath(path, root)
    rel = os.path.splitext(rel)[0]
    parts = rel.replace('\\', '/').split('/')
    if parts[-1] == '__init__':
        parts = parts[:-1]
    if not parts:
        return namespace
    return namespace + '.' + '.'.join(parts)


def scan_package_sources(root, namespace, include_ui=False):
    modules = {}
    aliases = {}
    for base, dirs, files in os.walk(root):
        if not include_ui:
            dirs[:] = [d for d in dirs if d.lower() not in ('ui', 'uis')]
        for filename in files:
            if not filename.endswith('.py') or should_skip_generated_file(filename):
                continue
            path = os.path.join(base, filename)
            if not include_ui and is_ui_path(path):
                continue
            module_name = module_name_for_file(root, namespace, path)
            source = read_file(path)
            modules[module_name] = source
            short_name = os.path.splitext(filename)[0]
            if short_name != '__init__':
                aliases.setdefault(module_name, set()).add(short_name)
    return modules, aliases


def parse_imports(source, namespace):
    imports = set()
    try:
        tree = ast.parse(source)
    except Exception:
        return imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == namespace or alias.name.startswith(namespace + '.'):
                    imports.add(alias.name)
                else:
                    imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                if node.module == namespace or node.module.startswith(namespace + '.'):
                    imports.add(node.module)
                else:
                    imports.add(node.module)
                    for alias in node.names:
                        if alias.name != '*':
                            imports.add(node.module + '.' + alias.name)
    return imports


def dependency_closure(modules, seeds, namespace):
    available = set(modules)
    short_to_full = {}
    for name in available:
        short_to_full.setdefault(name.rsplit('.', 1)[-1], name)
    resolved = []
    seen = set()
    stack = list(seeds)
    while stack:
        name = stack.pop()
        if name in short_to_full:
            name = short_to_full[name]
        if name not in available or name in seen:
            continue
        seen.add(name)
        resolved.append(name)
        for dep in parse_imports(modules[name], namespace):
            if dep in available:
                stack.append(dep)
            elif dep in short_to_full:
                stack.append(short_to_full[dep])
    return resolved


def ordered_modules(modules, selected, namespace):
    selected = set(selected)
    ordered = []
    temp = set()
    done = set()
    short_to_full = dict((name.rsplit('.', 1)[-1], name) for name in modules)

    def visit(name):
        if name in done or name not in selected or name in temp:
            return
        temp.add(name)
        for dep in parse_imports(modules[name], namespace):
            dep_name = dep if dep in modules else short_to_full.get(dep)
            if dep_name in selected:
                visit(dep_name)
        temp.remove(name)
        done.add(name)
        ordered.append(name)

    for item in selected:
        visit(item)
    return ordered


def normalize_aliases(aliases, selected=None):
    if selected is not None:
        selected = set(selected)
    reserved = set(['mod', 'server', 'client'])
    result = {}
    for key, value in list(aliases.items()):
        if selected is not None and key not in selected:
            continue
        result[key] = tuple(sorted(item for item in value if item not in reserved))
    return result


def compile_module_blobs(sources, mcs_opmap_version, op_overrides, module_opmap_versions=None, const_poison_count=0, taunt_text=None, string_chain=None, fold_strings=False, fold_numbers=False, rewrite_boolops=False, flatten_control_flow=False, return_gate=False, exception_gate=False, call_perturb=False, exception_gate_rate=10, call_perturb_rate=8, statement_reorder=False, statement_reorder_rate=30, statement_reorder_window=4, const_poison_jitter=0, dead_stop_tail=0, jump_garbage_min=0, jump_garbage_max=0, fake_code_count=0, bait_code_count=0, metadata_poison=False, aggressive_poison_stream=False, double_code_wrap=False, cf_gate_min=0, cf_gate_max=0, cf_gate_count=1, bytecode_trampoline=False, bytecode_trampoline_rate=35, anti_decompile_traps=0, jump_poison_blocks=0, jump_poison_min=8, jump_poison_max=32, obf2_fake_layers=0, obf2_fake_count=0, obf2_fake_min=120, obf2_fake_max=900, inner_taunt_repeat=1, inner_dataflow_noise=False, inner_dataflow_rate=30, inner_dataflow_min=1, inner_dataflow_max=4, const_pool_strings=False, const_pool_numbers=False, call_dispatcher=False, call_dispatcher_rate=8, fake_function_count=0, flatten_control_flow_v2=False, inner_opcode_tunnel=False, inner_opcode_table=None, shuffle_consts=False, shuffle_names=False, fake_name_count=0, opcode_tunnel_decoys=0, opcode_tunnel_double_map=False, reference_obf=False, reference_obf_rate=8, fake_class_count=0, opcode_tunnel_stages=1, shuffle_varnames=False, line_metadata_poison=False, stack_noise_rate=0, extended_arg_noise_rate=0, return_jump_gate_rate=0, depth_density=False, per_code_opcode_table=False):
    op_map_cache = {}

    def get_op_map(module_name):
        version = mcs_opmap_version
        if module_opmap_versions is not None:
            version = module_opmap_versions.get(module_name, 0)
        if not version:
            return None
        if version not in op_map_cache:
            item = load_std2mcs_map(version)
            item.update(op_overrides or {})
            op_map_cache[version] = item
        return op_map_cache[version]

    blobs = {}
    for name, source in list(sources.items()):
        op_map = get_op_map(name)
        code = compile_obfuscated_source(source, '<' + name + '>', string_chain or (), fold_strings, fold_numbers, rewrite_boolops, flatten_control_flow, return_gate, exception_gate, call_perturb, exception_gate_rate, call_perturb_rate, statement_reorder, statement_reorder_rate, statement_reorder_window, inner_dataflow_noise, inner_dataflow_rate, inner_dataflow_min, inner_dataflow_max, const_pool_strings, const_pool_numbers, call_dispatcher, call_dispatcher_rate, fake_function_count, flatten_control_flow_v2, taunt_text, reference_obf, reference_obf_rate, fake_class_count)
        if shuffle_consts or shuffle_names or shuffle_varnames:
            code = shuffle_code_metadata(code, shuffle_consts, shuffle_names, fake_name_count, taunt_text, shuffle_varnames)
        if line_metadata_poison:
            code = poison_code_object(code, 0, None, metadata_poison=True)
        code = poison_code_object(code, const_poison_count, taunt_text, jitter=const_poison_jitter, dead_stop_tail=dead_stop_tail, jump_garbage_min=jump_garbage_min, jump_garbage_max=jump_garbage_max, fake_code_count=fake_code_count, bait_code_count=bait_code_count, metadata_poison=metadata_poison, aggressive_poison_stream=aggressive_poison_stream, cf_gate_min=cf_gate_min, cf_gate_max=cf_gate_max, cf_gate_count=cf_gate_count, bytecode_trampoline=bytecode_trampoline, bytecode_trampoline_rate=bytecode_trampoline_rate, anti_decompile_traps=anti_decompile_traps, jump_poison_blocks=jump_poison_blocks, jump_poison_min=jump_poison_min, jump_poison_max=jump_poison_max, obf2_fake_layers=obf2_fake_layers, obf2_fake_count=obf2_fake_count, obf2_fake_min=obf2_fake_min, obf2_fake_max=obf2_fake_max, inner_taunt_repeat=inner_taunt_repeat, stack_noise_rate=stack_noise_rate, extended_arg_noise_rate=extended_arg_noise_rate, return_jump_gate_rate=return_jump_gate_rate, depth_density=depth_density)
        if inner_opcode_tunnel:
            version = module_opmap_versions.get(name, 0) if module_opmap_versions is not None else mcs_opmap_version
            code = wrap_code_in_opcode_tunnel(code, '<' + name + '.tunnel>', max(1, const_poison_count // 2), taunt_text, version, op_overrides, True, inner_opcode_table, opcode_tunnel_decoys, opcode_tunnel_double_map, opcode_tunnel_stages, per_code_opcode_table)
            blobs[name] = marshal.dumps(code)
            continue
        if op_map:
            code = sanitize_code_for_mcs(code)
        if op_map:
            code = remap_code_object(code, op_map)
        if double_code_wrap:
            code = wrap_code_in_double_loader(code, '<' + name + '.wrap>', max(1, const_poison_count // 2), taunt_text)
            if op_map:
                code = remap_code_object(code, op_map)
        blobs[name] = marshal.dumps(code)
    return blobs


def class_exports_for_modules(module_names, class_paths):
    result = {}
    for class_path in class_paths:
        module_name, class_name = split_class_path(class_path)
        if module_name in module_names:
            result.setdefault(module_name, set()).add(class_name)
    return dict((key, tuple(sorted(value))) for key, value in list(result.items()))


def external_short_aliases(modules, selected, namespace):
    selected = set(selected)
    result = {}
    reserved = set(['mod', 'server', 'client'])
    for module_name in modules:
        if module_name in selected:
            continue
        if not module_name.startswith(namespace + '.'):
            continue
        short_name = module_name.rsplit('.', 1)[-1]
        if short_name and short_name != '__init__' and short_name not in reserved:
            result.setdefault(short_name, module_name)
    return result


def netease_common_external_aliases():
    return {
        'server': 'mod.server',
        'server.extraServerApi': 'mod.server.extraServerApi',
        'client': 'mod.client',
        'client.extraClientApi': 'mod.client.extraClientApi',
    }


def ordered_external_aliases(aliases):
    result = []
    for name in ('server', 'server.extraServerApi', 'client', 'client.extraClientApi'):
        if name in aliases:
            result.append(name)
    for name in sorted(aliases):
        if name not in result:
            result.append(name)
    return result


def build_class_check_block(class_path):
    module_name, class_name = split_class_path(class_path)
    sys_name = random_identifier('sys')
    mod_name = random_identifier('m')
    return '\n'.join([
        "%s = %s" % (sys_name, import_sys_expr()),
        "%s = %s.modules.get(%r)" % (mod_name, sys_name, module_name),
        "if %s is None or not hasattr(%s, %r):" % (mod_name, mod_name, class_name),
        "    raise AttributeError(%r)" % ('missing class after install: ' + class_path,),
    ])


def indent_block(lines, spaces):
    prefix = ' ' * spaces
    return '\n'.join(prefix + line if line else line for line in lines)


def split_class_path(class_path):
    module_name, class_name = class_path.rsplit('.', 1)
    return module_name, class_name


def parse_system_specs(primary_system, primary_class, extra_specs):
    specs = []
    if primary_system and primary_class:
        specs.append((primary_system, primary_class))
    for item in extra_specs or []:
        if '=' not in item:
            raise SystemExit('error: system spec expects NAME=module.Class')
        system_name, class_path = item.split('=', 1)
        system_name = system_name.strip()
        class_path = class_path.strip()
        if system_name and class_path:
            specs.append((system_name, class_path))
    seen = set()
    result = []
    for spec in specs:
        if spec in seen:
            continue
        seen.add(spec)
        result.append(spec)
    return result


def class_paths_from_specs(specs):
    return tuple(class_path for _system_name, class_path in specs)


def build_register_block(api_name, namespace, specs, indent):
    lines = []
    last_name = random_identifier('ret')
    if not specs:
        lines.append('%s%s = None' % (indent, last_name))
    for system_name, class_path in specs:
        lines.append('%s%s = %s.RegisterSystem(%r, %r, %r)' % (
            indent, last_name, api_name, namespace, system_name, class_path
        ))
    lines.append('%sreturn %s' % (indent, last_name))
    return '\n'.join(lines)


def normalize_target_side(value):
    value = (value or 'both').strip().lower()
    aliases = {
        'all': 'both',
        'dual': 'both',
        'both': 'both',
        'server': 'server',
        'server_only': 'server',
        'server-only': 'server',
        'client': 'client',
        'client_only': 'client',
        'client-only': 'client',
    }
    if value not in aliases:
        raise SystemExit('error: target_side must be one of both/client/server')
    return aliases[value]


def target_has_server(target_side):
    return normalize_target_side(target_side) in ('both', 'server')


def target_has_client(target_side):
    return normalize_target_side(target_side) in ('both', 'client')


def build_direct_register_block(api_name, namespace, specs, indent):
    lines = []
    result_name = random_identifier('ret')
    if not specs:
        lines.append('%s%s = None' % (indent, result_name))
    for system_name, class_path in specs:
        lines.append('%s%s = %s.RegisterSystem(%r, %r, %r)' % (
            indent, result_name, api_name, namespace, system_name, class_path
        ))
    lines.append('%sreturn %s' % (indent, result_name))
    return '\n'.join(lines)


def build_direct_lifecycle_init(args, names, side, specs, method_name, api_module, api_name, decorator_attr, decorator_value, outer_noise_var, outer_noise_seed):
    return LIFECYCLE_DIRECT_INIT_TEMPLATE.format(
        method_name=method_name,
        method_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        control_block=build_outer_control_block(args.outer_control_noise, args.outer_control_count, '        '),
        api_module=api_module,
        api_name=api_name,
        register_block=build_direct_register_block(api_name, args.namespace, specs, '            '),
        outer_exc_name=names['outer_exc_name'],
        outer_noise_var=outer_noise_var,
        outer_noise_seed=outer_noise_seed,
        decorator_attr=decorator_attr,
        decorator_value=decorator_value,
    )


def build_direct_lifecycle_destroy(args, names, method_name, decorator_attr, decorator_value, outer_noise_var, outer_noise_seed):
    return LIFECYCLE_DIRECT_DESTROY_TEMPLATE.format(
        method_name=method_name,
        method_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        control_block=build_outer_control_block(args.outer_control_noise, args.outer_control_count, '        '),
        outer_exc_name=names['outer_exc_name'],
        outer_noise_var=outer_noise_var,
        outer_noise_seed=outer_noise_seed,
        decorator_attr=decorator_attr,
        decorator_value=decorator_value,
    )


def build_lifecycle_methods(args, names, server_obj, client_obj, server_init, server_destroy, client_init, client_destroy, server_specs=None, client_specs=None):
    target_side = normalize_target_side(getattr(args, 'target_side', 'both'))
    server_specs = server_specs or []
    client_specs = client_specs or []
    fuse_server = target_side in ('both', 'server') and bool(server_specs)
    fuse_client = target_side in ('both', 'client') and bool(client_specs)
    blocks = []
    items = []
    if server_specs and not fuse_server:
        blocks.append(build_direct_lifecycle_init(
            args, names, 'server', server_specs, names['init_server_name'],
            'mod.server.extraServerApi', random_identifier('serverApi'), 'InitServer', 'initServer',
            names['outer_noise_b'], names['outer_noise_seed_b']
        ))
        blocks.append(build_direct_lifecycle_destroy(
            args, names, names['destroy_server_name'], 'DestroyServer', 'destroyServer',
            names['outer_noise_c'], names['outer_noise_seed_c']
        ))
    if fuse_server:
        items.append(dict(
            side='server',
            method_name=names['init_server_name'],
            method_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
            control_block=build_outer_control_block(args.outer_control_noise, args.outer_control_count, '        '),
            side_obj_name=server_obj,
            side_method_name=server_init,
            decorator_attr='InitServer',
            decorator_value='initServer',
            outer_noise_var=names['outer_noise_b'],
            outer_noise_seed=names['outer_noise_seed_b'],
        ))
        items.append(dict(
            side='server',
            method_name=names['destroy_server_name'],
            method_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
            control_block=build_outer_control_block(args.outer_control_noise, args.outer_control_count, '        '),
            side_obj_name=server_obj,
            side_method_name=server_destroy,
            decorator_attr='DestroyServer',
            decorator_value='destroyServer',
            outer_noise_var=names['outer_noise_c'],
            outer_noise_seed=names['outer_noise_seed_c'],
        ))
    if client_specs and not fuse_client:
        blocks.append(build_direct_lifecycle_init(
            args, names, 'client', client_specs, names['init_client_name'],
            'mod.client.extraClientApi', random_identifier('clientApi'), 'InitClient', 'initClient',
            names['outer_noise_d'], names['outer_noise_seed_d']
        ))
        blocks.append(build_direct_lifecycle_destroy(
            args, names, names['destroy_client_name'], 'DestroyClient', 'destroyClient',
            names['outer_noise_e'], names['outer_noise_seed_e']
        ))
    if fuse_client:
        items.append(dict(
            side='client',
            method_name=names['init_client_name'],
            method_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
            control_block=build_outer_control_block(args.outer_control_noise, args.outer_control_count, '        '),
            side_obj_name=client_obj,
            side_method_name=client_init,
            decorator_attr='InitClient',
            decorator_value='initClient',
            outer_noise_var=names['outer_noise_d'],
            outer_noise_seed=names['outer_noise_seed_d'],
        ))
        items.append(dict(
            side='client',
            method_name=names['destroy_client_name'],
            method_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
            control_block=build_outer_control_block(args.outer_control_noise, args.outer_control_count, '        '),
            side_obj_name=client_obj,
            side_method_name=client_destroy,
            decorator_attr='DestroyClient',
            decorator_value='destroyClient',
            outer_noise_var=names['outer_noise_e'],
            outer_noise_seed=names['outer_noise_seed_e'],
        ))
    for item in items:
        if getattr(args, 'lifecycle_dispatcher', False):
            item['lifecycle_call'] = "getattr(%s.%s, %r)()" % (names['module_var'], item['side_obj_name'], item['side_method_name'])
        else:
            item['lifecycle_call'] = "%s.%s.%s()" % (names['module_var'], item['side_obj_name'], item['side_method_name'])
        item.update(dict(
            load_name=names['load_name'],
            module_var=names['module_var'],
            outer_exc_name=names['outer_exc_name'],
        ))
        blocks.append(LIFECYCLE_METHOD_TEMPLATE.format(**item))
    return ''.join(blocks)


def import_sys_expr():
    imp = "chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95)"
    modname = "chr(109)+chr(111)+chr(100)+chr(46)+chr(99)+chr(111)+chr(109)+chr(109)+chr(111)+chr(110)+chr(46)+chr(109)+chr(105)+chr(110)+chr(101)+chr(99)+chr(114)+chr(97)+chr(102)+chr(116)+chr(77)+chr(111)+chr(100)"
    sysname = "chr(115)+chr(121)+chr(115)"
    return "getattr(__builtins__[%s](%s, globals(), locals(), [chr(120)]), %s)" % (imp, modname, sysname)


def parent_name_expr(var_name):
    return "'.'.join(%s.split('.')[:-1])" % var_name


def leaf_name_expr(var_name):
    return "%s.split('.')[-1]" % var_name


def build_ladder_source(args, names, level):
    server_module, server_class_name = split_class_path(args.server_class)
    client_module, client_class_name = split_class_path(args.client_class)
    extra = []
    server_init_lines = ["print '[%s] ladder InitServer level %s'" % (args.namespace, level)]
    client_init_lines = ["print '[%s] ladder InitClient level %s'" % (args.namespace, level)]

    if level >= 2:
        extra.append("%s(%r)" % (names['make_module_name'], args.namespace + '.ladder_dummy'))
        server_init_lines.append("%s(%r)" % (names['make_module_name'], args.namespace + '.ladder_server_runtime'))
        client_init_lines.append("%s(%r)" % (names['make_module_name'], args.namespace + '.ladder_client_runtime'))

    if level >= 3:
        extra.extend([
            "def %s():" % names['install_server_stub'],
            "    import mod.server.extraServerApi as %s" % names['server_api'],
            "    %s = %s.GetServerSystemCls()" % (names['server_base'], names['server_api']),
            "    %s = %s(%r)" % (names['server_module_var'], names['make_module_name'], server_module),
            "    if hasattr(%s, %r):" % (names['server_module_var'], server_class_name),
            "        return %s" % names['server_module_var'],
            "    class %s(%s):" % (server_class_name, names['server_base']),
            "        def __init__(self, namespace, systemName):",
            "            %s.__init__(self, namespace, systemName)" % names['server_base'],
            "            print '[%s] ladder server system instance'" % args.namespace,
            "        def Destroy(self):",
            "            print '[%s] ladder server system destroy'" % args.namespace,
            "    %s.%s = %s" % (names['server_module_var'], server_class_name, server_class_name),
            "    return %s" % names['server_module_var'],
            "def %s():" % names['install_client_stub'],
            "    import mod.client.extraClientApi as %s" % names['client_api'],
            "    %s = %s.GetClientSystemCls()" % (names['client_base'], names['client_api']),
            "    %s = %s(%r)" % (names['client_module_var'], names['make_module_name'], client_module),
            "    if hasattr(%s, %r):" % (names['client_module_var'], client_class_name),
            "        return %s" % names['client_module_var'],
            "    class %s(%s):" % (client_class_name, names['client_base']),
            "        def __init__(self, namespace, systemName):",
            "            %s.__init__(self, namespace, systemName)" % names['client_base'],
            "            print '[%s] ladder client system instance'" % args.namespace,
            "        def Destroy(self):",
            "            print '[%s] ladder client system destroy'" % args.namespace,
            "    %s.%s = %s" % (names['client_module_var'], client_class_name, client_class_name),
            "    return %s" % names['client_module_var'],
        ])
        server_init_lines.append("%s()" % names['install_server_stub'])
        client_init_lines.append("%s()" % names['install_client_stub'])

    if level >= 4:
        server_init_lines.extend([
            "import mod.server.extraServerApi as %s" % names['server_api'],
            "return %s.RegisterSystem(%r, %r, %r)" % (
                names['server_api'], args.namespace, args.server_system, args.server_class
            ),
        ])
        client_init_lines.extend([
            "import mod.client.extraClientApi as %s" % names['client_api'],
            "return %s.RegisterSystem(%r, %r, %r)" % (
                names['client_api'], args.namespace, args.client_system, args.client_class
            ),
        ])
    else:
        server_init_lines.append('return None')
        client_init_lines.append('return None')

    return LADDER_PAYLOAD_TEMPLATE.format(
        banner="print '[%s] ladder payload loaded level %s'" % (args.namespace, level),
        make_module_name=names['make_module_name'],
        module_name_arg=random_identifier('mn'),
        random_api=random_identifier('rnd'),
        sys_api=random_identifier('sys'),
        import_sys_expr=import_sys_expr(),
        module_var=random_identifier('module'),
        old_module_var=random_identifier('oldmodule'),
        extra_body='\n'.join(extra),
        server_holder_cls=names['server_cls'],
        client_holder_cls=names['client_cls'],
        server_init=names['server_init'],
        server_destroy=names['server_destroy'],
        client_init=names['client_init'],
        client_destroy=names['client_destroy'],
        server_init_body=indent_block(server_init_lines, 8),
        client_init_body=indent_block(client_init_lines, 8),
        namespace=args.namespace,
        server_obj=names['server_obj'],
        client_obj=names['client_obj'],
    )


def build_modmain(args):
    cipher_mode = 'chacha' if getattr(args, 'cipher', 'auto') == 'chacha' else 'xor'
    key = os.urandom(32 if cipher_mode == 'chacha' else args.key_len)
    server_cls = random_identifier('srvcls')
    client_cls = random_identifier('clicls')
    server_obj = random_identifier('srv')
    client_obj = random_identifier('cli')
    server_init = random_identifier('initS')
    server_destroy = random_identifier('dstS')
    client_init = random_identifier('initC')
    client_destroy = random_identifier('dstC')
    shared_names = dict(
        server_cls=server_cls,
        client_cls=client_cls,
        server_obj=server_obj,
        client_obj=client_obj,
        server_init=server_init,
        server_destroy=server_destroy,
        client_init=client_init,
        client_destroy=client_destroy,
        make_module_name=random_identifier('mkmod'),
        server_module_var=random_identifier('srvmod'),
        client_module_var=random_identifier('climod'),
        server_api=random_identifier('serverApi'),
        client_api=random_identifier('clientApi'),
        server_base=random_identifier('serverBase'),
        client_base=random_identifier('clientBase'),
        install_server_stub=random_identifier('installServerStub'),
        install_client_stub=random_identifier('installClientStub'),
    )
    target_side = normalize_target_side(getattr(args, 'target_side', 'both'))
    server_specs = parse_system_specs(args.server_system, args.server_class, args.extra_server_system)
    client_specs = parse_system_specs(args.client_system, args.client_class, args.extra_client_system)
    inner_opcode_table = load_inner_opcode_table(getattr(args, 'inner_opcode_table', None))
    fuse_server = target_side in ('both', 'server') and bool(server_specs)
    fuse_client = target_side in ('both', 'client') and bool(client_specs)
    if args.ladder_level:
        inner_source = build_ladder_source(args, shared_names, args.ladder_level)
    else:
        string_chain = string_encrypt_chain(args)
        server_class_paths = class_paths_from_specs(server_specs)
        client_class_paths = class_paths_from_specs(client_specs)
        server_seed_modules = [module_path_from_class(class_path) for class_path in server_class_paths]
        client_seed_modules = [module_path_from_class(class_path) for class_path in client_class_paths]
        modules, aliases = scan_package_sources(args.script_root, args.namespace, args.include_ui)
        for server_module in server_seed_modules:
            if server_module not in modules:
                modules[server_module] = read_file(source_file_for_module(args.script_root, server_module))
        for client_module in client_seed_modules:
            if client_module not in modules:
                modules[client_module] = read_file(source_file_for_module(args.script_root, client_module))
        if args.no_dependency_closure:
            server_modules = ordered_modules(modules, server_seed_modules, args.namespace) if fuse_server else []
            client_modules = ordered_modules(modules, client_seed_modules, args.namespace) if fuse_client else []
        else:
            server_modules = ordered_modules(
                modules, dependency_closure(modules, server_seed_modules, args.namespace), args.namespace
            ) if fuse_server else []
            client_modules = ordered_modules(
                modules, dependency_closure(modules, client_seed_modules, args.namespace), args.namespace
            ) if fuse_client else []
        if args.full_integrate_py:
            if target_side == 'both':
                all_modules = ordered_modules(modules, sorted(modules), args.namespace)
                server_modules = [name for name in all_modules if not is_client_only_module(name)] if fuse_server else []
                client_modules = [name for name in all_modules if not is_server_only_module(name)] if fuse_client else []
            else:
                server_modules = ordered_modules(
                    modules, dependency_closure(modules, server_seed_modules, args.namespace), args.namespace
                ) if fuse_server else []
                client_modules = ordered_modules(
                    modules, dependency_closure(modules, client_seed_modules, args.namespace), args.namespace
                ) if fuse_client else []
        selected = sorted(set(server_modules + client_modules))
        op_overrides = parse_opcode_overrides(args.mcs_op_override)
        server_opmap_version = args.mcs_opmap_version if getattr(args, 'server_mcs_opmap', True) else 0
        client_opmap_version = args.mcs_opmap_version if getattr(args, 'client_mcs_opmap', True) else 0
        server_sources = compile_module_blobs(
            dict((name, modules[name]) for name in server_modules),
            server_opmap_version,
            op_overrides,
            None,
            args.const_poison_per_module,
            args.taunt_text,
            string_chain if args.string_encrypt_modules else (),
            args.fold_string_consts,
            args.fold_number_consts,
            args.rewrite_boolops,
            args.flatten_control_flow,
            args.return_gate,
            args.exception_gate,
            args.call_perturb,
            args.exception_gate_rate,
            args.call_perturb_rate,
            args.statement_reorder,
            args.statement_reorder_rate,
            args.statement_reorder_window,
            args.const_poison_jitter,
            args.dead_stop_tail,
            args.jump_garbage_min,
            args.jump_garbage_max,
            args.fake_code_count,
            args.bait_code_count,
            args.metadata_poison,
            args.aggressive_poison_stream,
            args.double_code_wrap,
            args.cf_gate_min,
            args.cf_gate_max,
            args.cf_gate_count,
            args.bytecode_trampoline,
            args.bytecode_trampoline_rate,
            args.anti_decompile_traps,
            args.jump_poison_blocks,
            args.jump_poison_min,
            args.jump_poison_max,
            args.obf2_fake_layers,
            args.obf2_fake_count,
            args.obf2_fake_min,
            args.obf2_fake_max,
            args.inner_taunt_repeat,
            args.inner_dataflow_noise,
            args.inner_dataflow_rate,
            args.inner_dataflow_min,
            args.inner_dataflow_max,
            args.const_pool_strings,
            args.const_pool_numbers,
            args.call_dispatcher,
            args.call_dispatcher_rate,
            args.fake_function_count,
            args.flatten_control_flow_v2,
            args.inner_opcode_tunnel,
            inner_opcode_table,
            args.shuffle_consts,
            args.shuffle_names,
            args.fake_name_count,
            args.opcode_tunnel_decoys,
            args.opcode_tunnel_double_map,
            args.reference_obf,
            args.reference_obf_rate,
            args.fake_class_count,
            args.opcode_tunnel_stages,
            args.shuffle_varnames,
            args.line_metadata_poison,
            args.stack_noise_rate,
            args.extended_arg_noise_rate,
            args.return_jump_gate_rate,
            args.depth_density,
            args.per_code_opcode_table,
        )
        if target_side == 'client':
            client_opcode_modules = list(client_modules)
        else:
            client_opcode_modules = [name for name in client_modules if is_client_only_module(name)]
        client_sources = compile_module_blobs(
            dict((name, modules[name]) for name in client_opcode_modules),
            client_opmap_version,
            op_overrides,
            None,
            args.const_poison_per_module,
            args.taunt_text,
            string_chain if args.string_encrypt_modules else (),
            args.fold_string_consts,
            args.fold_number_consts,
            args.rewrite_boolops,
            args.flatten_control_flow,
            args.return_gate,
            args.exception_gate,
            args.call_perturb,
            args.exception_gate_rate,
            args.call_perturb_rate,
            args.statement_reorder,
            args.statement_reorder_rate,
            args.statement_reorder_window,
            args.const_poison_jitter,
            args.dead_stop_tail,
            args.jump_garbage_min,
            args.jump_garbage_max,
            args.fake_code_count,
            args.bait_code_count,
            args.metadata_poison,
            args.aggressive_poison_stream,
            args.double_code_wrap,
            args.cf_gate_min,
            args.cf_gate_max,
            args.cf_gate_count,
            args.bytecode_trampoline,
            args.bytecode_trampoline_rate,
            args.anti_decompile_traps,
            args.jump_poison_blocks,
            args.jump_poison_min,
            args.jump_poison_max,
            args.obf2_fake_layers,
            args.obf2_fake_count,
            args.obf2_fake_min,
            args.obf2_fake_max,
            args.inner_taunt_repeat,
            args.inner_dataflow_noise,
            args.inner_dataflow_rate,
            args.inner_dataflow_min,
            args.inner_dataflow_max,
            args.const_pool_strings,
            args.const_pool_numbers,
            args.call_dispatcher,
            args.call_dispatcher_rate,
            args.fake_function_count,
            args.flatten_control_flow_v2,
            args.inner_opcode_tunnel,
            inner_opcode_table,
            args.shuffle_consts,
            args.shuffle_names,
            args.fake_name_count,
            args.opcode_tunnel_decoys,
            args.opcode_tunnel_double_map,
            args.reference_obf,
            args.reference_obf_rate,
            args.fake_class_count,
            args.opcode_tunnel_stages,
            args.shuffle_varnames,
            args.line_metadata_poison,
            args.stack_noise_rate,
            args.extended_arg_noise_rate,
            args.return_jump_gate_rate,
            args.depth_density,
            args.per_code_opcode_table,
        )
        external_aliases = netease_common_external_aliases()
        if args.no_dependency_closure:
            external_aliases.update(external_short_aliases(modules, selected, args.namespace))
        inner_source = INNER_MODULE_TEMPLATE.format(
            server_sources_name=random_identifier('srvsrc'),
            server_sources=server_sources,
            client_sources_name=random_identifier('clisrc'),
            client_sources=client_sources,
            aliases_name=random_identifier('als'),
            aliases=normalize_aliases(aliases, selected),
            exports_name=random_identifier('exports'),
            exports=class_exports_for_modules(selected, server_class_paths + client_class_paths),
            external_aliases_name=random_identifier('xals'),
            external_aliases=external_aliases,
            external_alias_order_name=random_identifier('xord'),
            external_alias_order=ordered_external_aliases(external_aliases),
            server_modules_name=random_identifier('srvmods'),
            server_modules=server_modules,
            client_modules_name=random_identifier('climods'),
            client_modules=client_modules,
            ensure_pkg_name=random_identifier('pkg'),
            ensure_parent_name=random_identifier('parent'),
            split_name_func=random_identifier('split'),
            install_name=random_identifier('install'),
            install_many_name=random_identifier('installMany'),
            mod_name_arg=random_identifier('mn'),
            source_arg=random_identifier('srcarg'),
            stub_arg=random_identifier('stub'),
            parts_var=random_identifier('parts'),
            part_var=random_identifier('part'),
            parent_var=random_identifier('parentMod'),
            parent_mod=random_identifier('parent'),
            prefix_var=random_identifier('prefix'),
            limit_var=random_identifier('limit'),
            pos_var=random_identifier('pos'),
            leaf_var=random_identifier('leaf'),
            parent_name_var=random_identifier('parentName'),
            leaf_name_var=random_identifier('leafName'),
            leaf_parts_var=random_identifier('leafParts'),
            code_var=random_identifier('co'),
            names_arg=random_identifier('names'),
            side_arg=random_identifier('side'),
            sources_ref_name=random_identifier('srcref'),
            item_arg=random_identifier('item'),
            src_name=random_identifier('srcv'),
            alias_arg=random_identifier('alias'),
            alias_src_name=random_identifier('aliasSrc'),
            ensure_aliases_name=random_identifier('ensureAlias'),
            export_arg=random_identifier('export'),
            export_obj=random_identifier('exportObj'),
            random_api=random_identifier('rnd'),
            sys_api=random_identifier('sys'),
            import_sys_expr=import_sys_expr(),
            marshal_api=random_identifier('marshal'),
            pkg_name=random_identifier('pkgname'),
            pkg_mod=random_identifier('pkgmod'),
            new_mod=random_identifier('newmod'),
            old_mod=random_identifier('oldmod'),
            server_cls=server_cls,
            client_cls=client_cls,
            server_init=server_init,
            server_destroy=server_destroy,
            client_init=client_init,
            client_destroy=client_destroy,
            server_api=shared_names['server_api'],
            client_api=shared_names['client_api'],
            server_check_block=indent_block(build_class_check_block(server_class_paths[0]).splitlines(), 8) if server_class_paths else '',
            client_check_block=indent_block(build_class_check_block(client_class_paths[0]).splitlines(), 8) if client_class_paths else '',
            namespace=args.namespace,
            server_system=args.server_system,
            server_class=args.server_class,
            client_system=args.client_system,
            client_class=args.client_class,
            server_register_block=build_register_block(shared_names['server_api'], args.namespace, server_specs, '        '),
            client_register_block=build_register_block(shared_names['client_api'], args.namespace, client_specs, '        '),
            server_obj=server_obj,
            client_obj=client_obj,
        )
    if args.dump_payload_source:
        write_file(args.dump_payload_source, inner_source)
    server_payload_opmap_version = args.mcs_opmap_version if getattr(args, 'server_mcs_opmap', True) else 0
    client_payload_opmap_version = args.mcs_opmap_version if getattr(args, 'client_mcs_opmap', True) else 0
    server_payload = None
    client_payload = None
    if fuse_server:
        server_payload = pack_source(
        inner_source,
        key,
        cipher_mode,
        args.chacha_level,
        args.precompiled_payload,
        server_payload_opmap_version,
        parse_opcode_overrides(args.mcs_op_override),
        args.const_poison_payload,
        args.taunt_text,
        string_encrypt_chain(args) if args.string_encrypt_payload else (),
        args.fold_string_consts,
        args.fold_number_consts,
        args.rewrite_boolops,
        args.flatten_control_flow,
        args.return_gate,
        args.exception_gate,
        args.call_perturb,
        args.exception_gate_rate,
        args.call_perturb_rate,
        args.statement_reorder,
        args.statement_reorder_rate,
        args.statement_reorder_window,
        args.const_poison_jitter,
        args.dead_stop_tail,
        args.jump_garbage_min,
        args.jump_garbage_max,
        args.fake_code_count,
        args.bait_code_count,
        args.metadata_poison,
        args.aggressive_poison_stream,
        args.double_code_wrap,
        args.dump_obf_pyc,
        args.cf_gate_min,
        args.cf_gate_max,
        args.cf_gate_count,
        args.bytecode_trampoline,
        args.bytecode_trampoline_rate,
        args.anti_decompile_traps,
        args.jump_poison_blocks,
        args.jump_poison_min,
        args.jump_poison_max,
        args.obf2_fake_layers,
        args.obf2_fake_count,
        args.obf2_fake_min,
        args.obf2_fake_max,
        args.inner_taunt_repeat,
        args.inner_dataflow_noise,
        args.inner_dataflow_rate,
        args.inner_dataflow_min,
        args.inner_dataflow_max,
        args.const_pool_strings,
        args.const_pool_numbers,
        args.call_dispatcher,
        args.call_dispatcher_rate,
        args.fake_function_count,
        args.flatten_control_flow_v2,
        args.inner_opcode_tunnel,
        inner_opcode_table,
        args.shuffle_consts,
        args.shuffle_names,
        args.fake_name_count,
        args.opcode_tunnel_decoys,
        args.opcode_tunnel_double_map,
        args.reference_obf,
        args.reference_obf_rate,
        args.fake_class_count,
        args.opcode_tunnel_stages,
        args.shuffle_varnames,
        args.line_metadata_poison,
        args.stack_noise_rate,
        args.extended_arg_noise_rate,
        args.return_jump_gate_rate,
        args.depth_density,
        args.per_code_opcode_table,
        )
    if fuse_client:
        if server_payload is not None and client_payload_opmap_version == server_payload_opmap_version:
            client_payload = server_payload
        else:
            client_payload = pack_source(
                inner_source,
                key,
                cipher_mode,
                args.chacha_level,
                args.precompiled_payload,
                client_payload_opmap_version,
                parse_opcode_overrides(args.mcs_op_override),
                args.const_poison_payload,
                args.taunt_text,
                string_encrypt_chain(args) if args.string_encrypt_payload else (),
                args.fold_string_consts,
                args.fold_number_consts,
                args.rewrite_boolops,
                args.flatten_control_flow,
                args.return_gate,
                args.exception_gate,
                args.call_perturb,
                args.exception_gate_rate,
                args.call_perturb_rate,
                args.statement_reorder,
                args.statement_reorder_rate,
                args.statement_reorder_window,
                args.const_poison_jitter,
                args.dead_stop_tail,
                args.jump_garbage_min,
                args.jump_garbage_max,
                args.fake_code_count,
                args.bait_code_count,
                args.metadata_poison,
                args.aggressive_poison_stream,
                args.double_code_wrap,
                None if server_payload is not None else args.dump_obf_pyc,
                args.cf_gate_min,
                args.cf_gate_max,
                args.cf_gate_count,
                args.bytecode_trampoline,
                args.bytecode_trampoline_rate,
                args.anti_decompile_traps,
                args.jump_poison_blocks,
                args.jump_poison_min,
                args.jump_poison_max,
                args.obf2_fake_layers,
                args.obf2_fake_count,
                args.obf2_fake_min,
                args.obf2_fake_max,
                args.inner_taunt_repeat,
                args.inner_dataflow_noise,
                args.inner_dataflow_rate,
                args.inner_dataflow_min,
                args.inner_dataflow_max,
                args.const_pool_strings,
                args.const_pool_numbers,
                args.call_dispatcher,
                args.call_dispatcher_rate,
                args.fake_function_count,
                args.flatten_control_flow_v2,
                args.inner_opcode_tunnel,
                inner_opcode_table,
                args.shuffle_consts,
                args.shuffle_names,
                args.fake_name_count,
                args.opcode_tunnel_decoys,
                args.opcode_tunnel_double_map,
                args.reference_obf,
                args.reference_obf_rate,
                args.fake_class_count,
                args.opcode_tunnel_stages,
                args.shuffle_varnames,
                args.line_metadata_poison,
                args.stack_noise_rate,
                args.extended_arg_noise_rate,
                args.return_jump_gate_rate,
                args.depth_density,
                args.per_code_opcode_table,
            )
    if server_payload is None:
        server_payload = ''
    if client_payload is None:
        client_payload = ''
    binding_cls = random_plain_name() if args.obfuscate_binding else args.binding_class
    split_literals = args.split_literals or args.netease_max
    noise_count = args.noise_chunks
    if args.netease_max and noise_count < 48:
        noise_count = 48
    random_var_name = random_identifier('rnd')
    sys_var_name = random_identifier('sys')
    outer_names = dict(
        module_var=random_identifier('m'),
        load_name=random_identifier('load'),
        outer_exc_name=random_identifier('exc'),
        init_server_name=random_identifier('InitServer'),
        destroy_server_name=random_identifier('DestroyServer'),
        init_client_name=random_identifier('InitClient'),
        destroy_client_name=random_identifier('DestroyClient'),
        outer_noise_b=random_identifier('og'),
        outer_noise_c=random_identifier('og'),
        outer_noise_d=random_identifier('og'),
        outer_noise_e=random_identifier('og'),
        outer_noise_seed_b=random.randint(1000, 999999),
        outer_noise_seed_c=random.randint(1000, 999999),
        outer_noise_seed_d=random.randint(1000, 999999),
        outer_noise_seed_e=random.randint(1000, 999999),
    )
    format_names = dict(
        bloat_head=build_bloat_block(args.bloat_lines // 2, args.bloat_kb // 2, args.bloat_style),
        bloat_tail=build_bloat_block(args.bloat_lines - (args.bloat_lines // 2), args.bloat_kb - (args.bloat_kb // 2), args.bloat_style),
        outer_lambda_block=build_outer_lambda_block(args.outer_lambda_noise, args.outer_lambda_count, args.outer_taunt_text, args.outer_taunt_repeat),
        outer_control_block=build_outer_control_block(args.outer_control_noise, args.outer_control_count),
        fake_module_block=build_fake_module_block(args.fake_module_count, sys_var_name, random_var_name),
        load_control_block=build_outer_control_block(args.outer_control_noise, max(1, args.outer_control_count // 2), '    '),
        init_server_control_block=build_outer_control_block(args.outer_control_noise, 1, '        '),
        destroy_server_control_block=build_outer_control_block(args.outer_control_noise, 1, '        '),
        init_client_control_block=build_outer_control_block(args.outer_control_noise, 1, '        '),
        destroy_client_control_block=build_outer_control_block(args.outer_control_noise, 1, '        '),
        key=key,
        module_label=random_plain_name(),
        module_var=outer_names['module_var'],
        random_var=random_var_name,
        load_name=outer_names['load_name'],
        loaded_attr=random_identifier('loaded'),
        loaded_key_var=random_identifier('lk'),
        module_arg=random_identifier('mod'),
        side_arg=random_identifier('side'),
        blob_var=random_identifier('blob'),
        key_var=random_identifier('k'),
        xor_name=random_identifier('x'),
        data_arg=random_identifier('d'),
        key_arg=random_identifier('ka'),
        ch_arg=random_identifier('ch'),
        idx_arg=random_identifier('i'),
        b64_name=random_identifier('b64'),
        zlib_name=random_identifier('z'),
        marshal_name=random_identifier('ma'),
        roll_name=random_identifier('roll'),
        arr_var=random_identifier('arr'),
        cipher_mode=cipher_mode,
        chacha_level=args.chacha_level,
        chacha_name=random_identifier('chacha'),
        chacha_handle=random_identifier('handle'),
        chacha_owner=random_identifier('owner'),
        chacha_owner_label=repr(random_identifier('ChaChaOwner')),
        ccreate_name=random_identifier('cc'),
        ccrypt_name=random_identifier('ce'),
        cdestroy_name=random_identifier('cd'),
        handle_var=random_identifier('h'),
        code_var=random_identifier('co'),
        outer_exc_name=outer_names['outer_exc_name'],
        outer_noise_a=random_identifier('og'),
        outer_noise_b=outer_names['outer_noise_b'],
        outer_noise_c=outer_names['outer_noise_c'],
        outer_noise_d=outer_names['outer_noise_d'],
        outer_noise_e=outer_names['outer_noise_e'],
        outer_noise_seed_a=random.randint(1000, 999999),
        outer_noise_seed_b=outer_names['outer_noise_seed_b'],
        outer_noise_seed_c=outer_names['outer_noise_seed_c'],
        outer_noise_seed_d=outer_names['outer_noise_seed_d'],
        outer_noise_seed_e=outer_names['outer_noise_seed_e'],
        sys_var=sys_var_name,
        bridge_var=random_identifier('bridge'),
        mod_name_var=random_identifier('modname'),
        mod_api_var=random_identifier('modapi'),
        mod_var=random_identifier('mod'),
        binding_name=args.binding_name or args.namespace,
        version=args.version,
        binding_cls=binding_cls,
        init_server_name=outer_names['init_server_name'],
        destroy_server_name=outer_names['destroy_server_name'],
        init_client_name=outer_names['init_client_name'],
        destroy_client_name=outer_names['destroy_client_name'],
        load_doc=build_docstring(args.outer_doc_lines, '    ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        xor_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        roll_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        init_server_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        destroy_server_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        init_client_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        destroy_client_doc=build_docstring(args.outer_doc_lines, '        ', args.outer_doc_min_bytes, args.outer_doc_max_bytes),
        server_obj_name=server_obj,
        client_obj_name=client_obj,
        server_init_name=server_init,
        server_destroy_name=server_destroy,
        client_init_name=client_init,
        client_destroy_name=client_destroy,
    )
    format_names['lifecycle_methods'] = build_lifecycle_methods(
        args, outer_names, server_obj, client_obj, server_init, server_destroy, client_init, client_destroy,
        server_specs, client_specs
    )
    format_names['server_payload_block'] = build_payload_block(
        format_names['blob_var'], server_payload, split_literals, noise_count, '        ', args.payload_fragments
    )
    format_names['client_payload_block'] = build_payload_block(
        format_names['blob_var'], client_payload, split_literals, noise_count, '        ', args.payload_fragments
    )
    format_names['key_block'] = build_key_block(
        format_names['key_var'], key, split_literals, max(8, noise_count // 4), '    ', args.mask_key
    )
    format_names['cipher_decode_block'] = cipher_decode_block(cipher_mode, format_names)
    # Older fuser templates used readable implementation locals such as
    # ``_co``, ``_names`` and ``_consts``.  They are not part of the payload
    # API, so normalize them in the final generated source as well.
    return obfuscate_reserved_generated_identifiers(
        MODMAIN_TEMPLATE.format(**format_names))


def main(argv=None):
    require_py27()
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--config', default=None, help='JSON config file; CLI arguments override config values')
    pre_args, remaining = pre_parser.parse_known_args(argv)

    parser = argparse.ArgumentParser(description='Generate fused NetEase Minecraft modMain.py shell.')
    parser.add_argument('--config', default=None, help='JSON config file; CLI arguments override config values')
    parser.add_argument('-o', '--output', default='modMain.py')
    parser.add_argument('--mod-name', default=None)
    parser.add_argument('--binding-name', default=None, help='MOD_NAME stored on the outer binding class; default: namespace')
    parser.add_argument('--version', default='1.0.0')
    parser.add_argument('--namespace', default=None)
    parser.add_argument('--binding-class', default='ModEntry')
    parser.add_argument('--target-side', choices=('both', 'client', 'server'), default='both', help='generate lifecycle and packed modules for both/client/server')
    parser.add_argument('--server-system', default=None)
    parser.add_argument('--server-class', default=None)
    parser.add_argument('--extra-server-system', action='append', default=[], help='extra server RegisterSystem entry NAME=module.Class')
    parser.add_argument('--client-system', default=None)
    parser.add_argument('--client-class', default=None)
    parser.add_argument('--extra-client-system', action='append', default=[], help='extra client RegisterSystem entry NAME=module.Class')
    parser.add_argument('--script-root', default=None, help='folder containing mod scripts')
    parser.add_argument('--include-ui', action='store_true', help='also pack UI/screen scripts; default skips them')
    parser.add_argument('--no-dependency-closure', action='store_true', help='pack only registered system modules; leave other imports to normal files')
    parser.add_argument('--full-integrate-py', action='store_true', help='pack all discovered package .py modules into modMain payload')
    parser.add_argument('--cipher', choices=('auto', 'xor', 'chacha'), default='auto', help='payload cipher; chacha uses NetEase _chacha')
    parser.add_argument('--chacha-level', type=int, choices=(8, 12, 20), default=8, help='native _chacha round level')
    parser.add_argument('--dump-payload-source', default=None, help='write inner payload source for target-side compilation')
    parser.add_argument('--dump-obf-pyc', default=None, help='write CPython 2.7 obfuscated payload .pyc before NetEase opcode remap/encryption')
    parser.add_argument('--precompiled-payload', default=None, help='target-runtime marshal.dumps(code) payload to embed')
    parser.add_argument('--mcs-opmap-version', type=int, default=0, help='remap standard py27 opcodes to MCS opcode map version')
    parser.add_argument('--server-mcs-opmap', action='store_true', help='enable MCS opcode remap for packed server modules')
    parser.add_argument('--no-server-mcs-opmap', action='store_false', dest='server_mcs_opmap', help='disable MCS opcode remap for packed server modules')
    parser.add_argument('--client-mcs-opmap', action='store_true', help='enable MCS opcode remap for packed client modules')
    parser.add_argument('--no-client-mcs-opmap', action='store_false', dest='client_mcs_opmap', help='disable MCS opcode remap for packed client modules')
    parser.add_argument('--mcs-op-override', action='append', default=[], help='override one opcode mapping, e.g. STORE_SUBSCR=0x4F')
    parser.add_argument('--ladder-level', type=int, choices=(0, 1, 2, 3, 4), default=0, help='emit minimal payload for crash isolation')
    parser.add_argument('--key-len', type=int, default=24)
    parser.add_argument('--split-literals', action='store_true', help='split payload/key literals into tagged chunks')
    parser.add_argument('--string-encrypt-modules', action='store_true', help='encrypt string constants inside packed user modules')
    parser.add_argument('--string-encrypt-payload', action='store_true', help='encrypt string constants inside inner payload loader')
    parser.add_argument('--string-enc-zlib', action='store_true', help='enable zlib step for string encryption')
    parser.add_argument('--string-enc-xor', action='store_true', help='enable xor step for string encryption')
    parser.add_argument('--string-enc-add', action='store_true', help='enable add/sub rolling-key step for string encryption')
    parser.add_argument('--string-enc-reverse', action='store_true', help='enable reverse step for string encryption')
    parser.add_argument('--noise-chunks', type=int, default=0, help='fake tagged chunks added when literals are split')
    parser.add_argument('--bloat-lines', type=int, default=0, help='append inert source bloat lines')
    parser.add_argument('--bloat-kb', type=int, default=0, help='append inert source bloat until approximate KB size is reached')
    parser.add_argument('--bloat-style', choices=('dead', 'strings'), default='strings', help='source bloat style')
    parser.add_argument('--const-poison-payload', type=int, default=0, help='append inert constants to outer payload code object')
    parser.add_argument('--const-poison-per-module', type=int, default=0, help='append inert constants to each packed module code object')
    parser.add_argument('--const-poison-jitter', type=int, default=0, help='add recursive per-code-object poison jitter')
    parser.add_argument('--dead-stop-tail', type=int, default=0, help='append unreachable STOP_CODE bytes at code tails')
    parser.add_argument('--jump-garbage-min', type=int, default=0, help='minimum skipped bytecode garbage bytes prefixed to each code object')
    parser.add_argument('--jump-garbage-max', type=int, default=0, help='maximum skipped bytecode garbage bytes prefixed to each code object')
    parser.add_argument('--fake-code-count', type=int, default=0, help='append fake nested code objects to constants')
    parser.add_argument('--bait-code-count', type=int, default=0, help='append top-level empty-index bait code objects')
    parser.add_argument('--metadata-poison', action='store_true', help='poison co_name/co_filename/co_lnotab metadata')
    parser.add_argument('--aggressive-poison-stream', action='store_true', help='use more hostile skipped bytecode garbage stream')
    parser.add_argument('--cf-gate-min', type=int, default=0, help='minimum opaque bytecode gate dead-block bytes')
    parser.add_argument('--cf-gate-max', type=int, default=0, help='maximum opaque bytecode gate dead-block bytes')
    parser.add_argument('--cf-gate-count', type=int, default=1, help='opaque bytecode gate layers per code object')
    parser.add_argument('--bytecode-trampoline', action='store_true', help='insert harmless JUMP_FORWARD trampolines before loop/try bytecode jumps')
    parser.add_argument('--bytecode-trampoline-rate', type=int, default=35, help='percentage of loop/try jump sites receiving trampolines')
    parser.add_argument('--anti-decompile-traps', type=int, default=0, help='append unreachable fake code objects with hostile indexes for decompilers')
    parser.add_argument('--jump-poison-blocks', type=int, default=0, help='insert JUMP_FORWARD-skipped poisoned bytecode blocks inside code objects')
    parser.add_argument('--jump-poison-min', type=int, default=8, help='minimum bytes per skipped poison block')
    parser.add_argument('--jump-poison-max', type=int, default=32, help='maximum bytes per skipped poison block')
    parser.add_argument('--obf2-fake-layers', type=int, default=0, help='append obf_2-style nested fake code-object layers')
    parser.add_argument('--obf2-fake-count', type=int, default=0, help='number of obf_2-style fake code objects per code object')
    parser.add_argument('--obf2-fake-min', type=int, default=120, help='minimum byte length of each obf_2 fake code stream')
    parser.add_argument('--obf2-fake-max', type=int, default=900, help='maximum byte length of each obf_2 fake code stream')
    parser.add_argument('--mask-key', action='store_true', help='split and mask payload key literal in outer loader')
    parser.add_argument('--double-code-wrap', action='store_true', help='wrap payload and packed modules in a second marshalled code loader')
    parser.add_argument('--fold-string-consts', action='store_true', help='rewrite string constants into equivalent runtime expressions')
    parser.add_argument('--fold-number-consts', action='store_true', help='rewrite integer constants into equivalent runtime expressions')
    parser.add_argument('--rewrite-boolops', action='store_true', help='rewrite simple and/or expressions into equivalent conditional expressions')
    parser.add_argument('--flatten-control-flow', action='store_true', help='rewrite function bodies into state-machine while/continue dispatchers')
    parser.add_argument('--return-gate', action='store_true', help='insert opaque branches before return/raise statements')
    parser.add_argument('--exception-gate', action='store_true', help='wrap function bodies in harmless try/finally noise')
    parser.add_argument('--call-perturb', action='store_true', help='wrap some call targets with identity lambda calls')
    parser.add_argument('--exception-gate-rate', type=int, default=10, help='percentage of functions wrapped by exception gate')
    parser.add_argument('--call-perturb-rate', type=int, default=8, help='percentage of call targets perturbed')
    parser.add_argument('--statement-reorder', action='store_true', help='safely reorder independent simple statements inside function bodies')
    parser.add_argument('--statement-reorder-rate', type=int, default=30, help='percentage of eligible windows considered for statement reorder')
    parser.add_argument('--statement-reorder-window', type=int, default=4, help='maximum simple-statement window size for reorder')
    parser.add_argument('--inner-dataflow-noise', action='store_true', help='inject harmless data-flow noise inside real function bodies')
    parser.add_argument('--inner-dataflow-rate', type=int, default=30, help='percentage of statements preceded by data-flow noise')
    parser.add_argument('--inner-dataflow-min', type=int, default=1, help='minimum statements per data-flow noise block')
    parser.add_argument('--inner-dataflow-max', type=int, default=4, help='maximum statements per data-flow noise block')
    parser.add_argument('--const-pool-strings', action='store_true', help='move string literals into a module-level constant pool')
    parser.add_argument('--const-pool-numbers', action='store_true', help='move integer literals into a module-level constant pool')
    parser.add_argument('--call-dispatcher', action='store_true', help='wrap simple calls through a local dispatcher expression')
    parser.add_argument('--call-dispatcher-rate', type=int, default=8, help='percentage of simple calls routed through dispatcher')
    parser.add_argument('--fake-function-count', type=int, default=0, help='append fake module-level functions into inner sources')
    parser.add_argument('--flatten-control-flow-v2', action='store_true', help='add decoy states and shuffled state checks to function flattening')
    parser.add_argument('--inner-opcode-tunnel', action='store_true', help='experimental: store real inner code under custom opcode map, restore at runtime, and obfuscate both layers')
    parser.add_argument('--inner-opcode-table', default=None, help='optional custom std->custom opcode table path for --inner-opcode-tunnel')
    parser.add_argument('--shuffle-consts', action='store_true', help='shuffle co_consts indexes recursively and fix LOAD_CONST')
    parser.add_argument('--shuffle-names', action='store_true', help='shuffle co_names indexes recursively and fix name references')
    parser.add_argument('--fake-name-count', type=int, default=0, help='append fake co_names before shuffling names')
    parser.add_argument('--opcode-tunnel-decoys', type=int, default=0, help='add encrypted decoy payload blobs inside opcode tunnel')
    parser.add_argument('--opcode-tunnel-double-map', action='store_true', help='split opcode tunnel map into custom->mid and mid->runtime maps')
    parser.add_argument('--opcode-tunnel-stages', type=int, default=1, help='split opcode tunnel loader into 1..3 runtime stages')
    parser.add_argument('--reference-obf', action='store_true', help='rewrite eligible obj.attr(...) calls into getattr(obj, split_attr)(...)')
    parser.add_argument('--reference-obf-rate', type=int, default=8, help='percentage of eligible attribute calls rewritten')
    parser.add_argument('--fake-class-count', type=int, default=0, help='append fake class forest into inner sources')
    parser.add_argument('--shuffle-varnames', action='store_true', help='shuffle non-argument co_varnames indexes recursively and fix fast locals')
    parser.add_argument('--payload-fragments', type=int, default=0, help='split outer payload literal into ordered fragments with fake fragments')
    parser.add_argument('--lifecycle-dispatcher', action='store_true', help='route outer lifecycle calls through getattr dispatcher')
    parser.add_argument('--fake-module-count', type=int, default=0, help='create fake outer module containers in sys.modules')
    parser.add_argument('--line-metadata-poison', action='store_true', help='apply ASCII-safe co_filename/co_name/co_lnotab metadata poison')
    parser.add_argument('--stack-noise-rate', type=int, default=0, help='insert LOAD_CONST None/POP_TOP stack noise at this percentage')
    parser.add_argument('--extended-arg-noise-rate', type=int, default=0, help='insert EXTENDED_ARG 0 before safe argument opcodes')
    parser.add_argument('--return-jump-gate-rate', type=int, default=0, help='insert skipped junk gates before RETURN_VALUE')
    parser.add_argument('--depth-density', action='store_true', help='increase bytecode noise rates for nested code objects')
    parser.add_argument('--per-code-opcode-table', action='store_true', help='use independent opcode tunnel maps for each nested code object')
    parser.add_argument('--taunt-text', default=DEFAULT_TAUNT_TEXT, help='taunt text injected into inert bytecode constants')
    parser.add_argument('--inner-taunt-repeat', type=int, default=1, help='repeat taunt text in inner co_consts and fake co_names')
    parser.add_argument('--outer-taunt-text', default=DEFAULT_OUTER_TAUNT_TEXT, help='taunt text emitted in outer lambda noise')
    parser.add_argument('--outer-lambda-noise', action='store_true', help='emit deobf_1.py-like outer lambda taunt expressions')
    parser.add_argument('--outer-lambda-count', type=int, default=1, help='number of outer lambda noise expressions')
    parser.add_argument('--outer-taunt-repeat', type=int, default=3, help='taunt repetitions inside each outer lambda string')
    parser.add_argument('--outer-control-noise', action='store_true', help='emit harmless top-level if/try control-flow noise')
    parser.add_argument('--outer-control-count', type=int, default=2, help='number of outer control-flow noise blocks')
    parser.add_argument('--outer-doc-lines', type=int, default=0, help='insert hex-escaped multiline docstrings into outer functions')
    parser.add_argument('--outer-doc-min-bytes', type=int, default=24, help='minimum random bytes per outer docstring line')
    parser.add_argument('--outer-doc-max-bytes', type=int, default=54, help='maximum random bytes per outer docstring line')
    parser.add_argument('--check-policy', action='store_true', help='scan generated files for NetEase policy-sensitive code')
    parser.add_argument('--netease-max', action='store_true', help='enable strongest stable NetEase-safe obfuscation preset')
    parser.add_argument('--keep-binding-name', action='store_false', dest='obfuscate_binding', help='do not obfuscate outer binding class name')
    parser.set_defaults(obfuscate_binding=True)
    parser.set_defaults(server_mcs_opmap=True, client_mcs_opmap=True)
    apply_config_defaults(parser, read_json_config(pre_args.config))
    args = parser.parse_args(argv)
    required = ['mod_name', 'namespace']
    if normalize_target_side(args.target_side) in ('both', 'server'):
        required.extend(['server_system', 'server_class'])
    if normalize_target_side(args.target_side) in ('both', 'client'):
        required.extend(['client_system', 'client_class'])
    require_args(args, tuple(required))
    if args.script_root is None:
        args.script_root = os.path.dirname(os.path.abspath(args.output)) or os.getcwd()
    if args.netease_max:
        args.key_len = max(args.key_len, 64)
        args.split_literals = True
        args.mcs_opmap_version = args.mcs_opmap_version or 1
        args.string_encrypt_modules = True
        args.string_encrypt_payload = True
        args.string_enc_zlib = True
        args.string_enc_xor = True
        args.string_enc_add = True
        args.string_enc_reverse = True
        args.const_poison_jitter = max(args.const_poison_jitter, 8)
        args.jump_garbage_min = max(args.jump_garbage_min, 8)
        args.jump_garbage_max = max(args.jump_garbage_max, 32)
        args.mask_key = True
        args.fold_string_consts = True
        args.fold_number_consts = True
        args.rewrite_boolops = True
        args.inner_opcode_tunnel = True
        args.shuffle_consts = True
        args.shuffle_names = True
        args.fake_name_count = max(args.fake_name_count, 12)
        args.opcode_tunnel_decoys = max(args.opcode_tunnel_decoys, 3)
        args.opcode_tunnel_double_map = True
        args.opcode_tunnel_stages = max(args.opcode_tunnel_stages, 3)
        args.reference_obf = True
        args.reference_obf_rate = max(args.reference_obf_rate, 10)
        args.fake_class_count = max(args.fake_class_count, 4)
        args.shuffle_varnames = True
        args.payload_fragments = max(args.payload_fragments, 8)
        args.lifecycle_dispatcher = True
        args.fake_module_count = max(args.fake_module_count, 3)
        args.line_metadata_poison = True
        args.stack_noise_rate = max(args.stack_noise_rate, 8)
        args.extended_arg_noise_rate = max(args.extended_arg_noise_rate, 4)
        args.return_jump_gate_rate = max(args.return_jump_gate_rate, 15)
        args.depth_density = True
        args.per_code_opcode_table = True
    if (args.string_encrypt_modules or args.string_encrypt_payload) and not string_encrypt_chain(args):
        args.string_enc_zlib = True
        args.string_enc_xor = True
        args.string_enc_reverse = True

    random.seed(time.time())
    write_file(args.output, build_modmain(args))
    print('wrote %s' % args.output)
    if args.check_policy:
        paths = [args.output]
        issues = []
        for path in paths:
            issues.extend(netease_policy_checker.scan_path(path))
        print(netease_policy_checker.format_issues(issues))
        if issues:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
