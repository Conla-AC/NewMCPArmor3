# -*- coding: utf-8 -*-
"""CPython and NetEase opcode map conversion."""


from MCP_Armor_Src.core import py27_opcode as opcode
import random
import types

from MCP_Armor_Src.bytecode_obf.model import (
    rebuild_code,
)

from MCP_Armor_Src.core.constants import (
    HAVE_ARGUMENT,
)

from MCP_Armor_Src.utils.encoding import (
    byte_char, byte_value,
    random_ident,
)


def remap_code_bytes(code_bytes, mapping):
    out = []
    pos = 0
    size = len(code_bytes)
    while pos < size:
        opv = byte_value(code_bytes[pos])
        out.append(byte_char(mapping.get(opv, opv)))
        pos += 1
        if opv >= HAVE_ARGUMENT and pos + 1 < size:
            out.append(code_bytes[pos])
            out.append(code_bytes[pos + 1])
            pos += 2
    return b''.join(out)


def remap_code_object(co, mapping):
    consts = []
    for const in co.co_consts:
        if isinstance(const, types.CodeType):
            const = remap_code_object(const, mapping)
        consts.append(const)
    return rebuild_code(co, consts, remap_code_bytes(co.co_code, mapping))


def make_same_category_opcode_map():
    noarg = [value for value in sorted(set(opcode.opmap.values())) if value < HAVE_ARGUMENT]
    hasarg = [value for value in sorted(set(opcode.opmap.values())) if value >= HAVE_ARGUMENT]
    noarg_shuffled = list(noarg)
    hasarg_shuffled = list(hasarg)
    random.shuffle(noarg_shuffled)
    random.shuffle(hasarg_shuffled)
    mapping = {}
    for src, dst in zip(noarg, noarg_shuffled):
        mapping[src] = dst
    for src, dst in zip(hasarg, hasarg_shuffled):
        mapping[src] = dst
    return mapping


def load_mcs_opcode_map(version):
    try:
        from MCP_Armor_Src.netease import modmain_fuser
        return modmain_fuser.load_std2mcs_map(version)
    except Exception as exc:
        raise SystemExit('cannot load NetEase opcode map version %s: %s' % (version, exc))


def invert_opcode_map(mapping):
    return dict((target, source) for source, target in list(mapping.items()))


def runtime_table_to_stored_std(runtime_table, target_to_std):
    if not runtime_table:
        return {}
    is_per_code = any(isinstance(value, dict) for value in list(runtime_table.values()))
    if is_per_code:
        output = {}
        for code_id, table in list(runtime_table.items()):
            output[code_id] = dict((stored, target_to_std.get(target, target))
                                   for stored, target in list(table.items()))
        return output
    return dict((stored, target_to_std.get(target, target))
                for stored, target in list(runtime_table.items()))


def _load_runtime_opcode_map(runtime, mcs_version):
    if runtime == 'std':
        return dict((value, value) for value in range(256))
    if runtime == 'mcs':
        return load_mcs_opcode_map(mcs_version)
    raise SystemExit('bad opcode runtime: %s' % runtime)


def build_per_code_runtime_opcode_layer(co, mcs_version, runtime='mcs'):
    std_to_runtime = _load_runtime_opcode_map(runtime, mcs_version)
    maps = {}
    counter = [0]

    def walk(item):
        code_id = counter[0]
        counter[0] += 1
        std_to_custom = make_same_category_opcode_map()
        custom_to_runtime = {}
        for std_op, custom_op in list(std_to_custom.items()):
            custom_to_runtime[custom_op] = std_to_runtime.get(std_op, std_op)
        maps[code_id] = custom_to_runtime
        consts = []
        for const in item.co_consts:
            if isinstance(const, types.CodeType):
                const = walk(const)
            consts.append(const)
        return rebuild_code(item, consts, remap_code_bytes(item.co_code, std_to_custom))

    return walk(co), maps


def build_runtime_opcode_layer(co, mcs_version, runtime='mcs'):
    std_to_custom = make_same_category_opcode_map()
    stored = remap_code_object(co, std_to_custom)
    std_to_runtime = _load_runtime_opcode_map(runtime, mcs_version)
    custom_to_runtime = {}
    for std_op, custom_op in list(std_to_custom.items()):
        custom_to_runtime[custom_op] = std_to_runtime.get(std_op, std_op)
    return stored, custom_to_runtime


def encode_runtime_opcode_rows(table, decoys):
    rows = []
    tag = random_ident('rtop')
    salt = random.randint(1, 255)
    is_per_code = False
    for _k, _v in list(table.items()):
        if isinstance(_v, dict):
            is_per_code = True
            break
    if is_per_code:
        for code_id, op_table in sorted(table.items()):
            for custom_op, target_op in sorted(op_table.items()):
                row_key = random.randint(1, 255)
                rows.append((tag, (custom_op ^ row_key ^ salt) & 255, (target_op ^ ((row_key + salt) & 255)) & 255, row_key, code_id ^ ((row_key + salt + 17) & 255)))
    else:
        for custom_op, target_op in sorted(table.items()):
            row_key = random.randint(1, 255)
            rows.append((tag, (custom_op ^ row_key ^ salt) & 255, (target_op ^ ((row_key + salt) & 255)) & 255, row_key))
    for _ in range(max(0, decoys)):
        if is_per_code:
            rows.append((random_ident('rof'), random.randint(0, 255), random.randint(0, 255), random.randint(1, 255), random.randint(0, 255)))
        else:
            rows.append((random_ident('rof'), random.randint(0, 255), random.randint(0, 255), random.randint(1, 255)))
    random.shuffle(rows)
    return rows, tag, salt


def tunnel_code_object(co, runtime, mcs_version):
    std_to_custom = make_same_category_opcode_map()
    stored = remap_code_object(co, std_to_custom)
    if runtime == 'std':
        std_to_runtime = dict((value, value) for value in range(256))
    elif runtime == 'mcs':
        std_to_runtime = load_mcs_opcode_map(mcs_version)
    else:
        raise SystemExit('bad opcode runtime: %s' % runtime)
    custom_to_runtime = {}
    for std_op, custom_op in list(std_to_custom.items()):
        custom_to_runtime[custom_op] = std_to_runtime.get(std_op, std_op)
    return stored, custom_to_runtime


def encode_opcode_table(table, fake_count):
    salt = random.randint(1, 255)
    tag = random_ident('otag')
    rows = []
    for custom_op, target_op in sorted(table.items()):
        rows.append((tag, (custom_op ^ salt) & 255, (target_op ^ ((salt * 3) & 255)) & 255))
    for _ in range(fake_count):
        rows.append((random_ident('fake'), random.randint(0, 255), random.randint(0, 255)))
    random.shuffle(rows)
    return rows, tag, salt
