# -*- coding: utf-8 -*-
"""Instruction-level bytecode decoding and transformations."""


from MCP_Armor_Src.core import py27_opcode as opcode
from MCP_Armor_Src.utils.encoding import byte_char, byte_value
import os
import random
import types
import zlib

from MCP_Armor_Src.core.constants import (
    BINARY_SUBSCR,
    COMPARE_OP,
    CO_VARARGS,
    CO_VARKEYWORDS,
    DELETE_FAST,
    EXTENDED_ARG,
    FAST_INDEX_OPS,
    HAVE_ARGUMENT,
    JUMP_ABSOLUTE,
    JUMP_FORWARD,
    LOAD_CONST,
    LOAD_FAST,
    NAME_INDEX_OPS,
    NOP,
    POP_JUMP_IF_FALSE,
    POP_JUMP_IF_TRUE,
    POP_TOP,
    RETURN_VALUE,
    STORE_FAST,
)


def read_oparg(code_bytes, pos):
    return byte_value(code_bytes[pos + 1]) | (byte_value(code_bytes[pos + 2]) << 8)


def write_oparg(value):
    return byte_char(value & 255) + byte_char((value >> 8) & 255)


def force_changed_shuffle(values):
    shuffled = list(values)
    random.shuffle(shuffled)
    if len(shuffled) > 1 and shuffled == list(values):
        shuffled = shuffled[1:] + shuffled[:1]
    return shuffled


def shuffle_index_pool(items, start=0):
    items = list(items)
    mapping = dict((idx, idx) for idx in range(len(items)))
    if len(items) - start < 2:
        return items, mapping
    old_positions = list(range(start, len(items)))
    new_positions = force_changed_shuffle(old_positions)
    original = list(items)
    for old_idx, new_idx in zip(old_positions, new_positions):
        items[new_idx] = original[old_idx]
        mapping[old_idx] = new_idx
    return items, mapping


def make_index_pool_mirrors(consts, names, mirror_count):
    mirror_count = max(0, mirror_count)
    if mirror_count <= 0:
        return consts, names
    const_sources = [value for value in consts[1:]
                     if not isinstance(value, types.CodeType)]
    name_sources = list(names)
    for idx in range(mirror_count):
        if const_sources:
            consts.append(random.choice(const_sources))
        else:
            consts.append('_const_mirror_%08x' % random.randint(0, 0xffffffff))
        if name_sources:
            names.append(random.choice(name_sources))
        else:
            names.append('_name_mirror_%08x' % random.randint(0, 0xffffffff))
    return consts, names


def safe_varname_shuffle_start(co):
    if co.co_cellvars or co.co_freevars:
        return None
    start = co.co_argcount
    if co.co_flags & CO_VARARGS:
        start += 1
    if co.co_flags & CO_VARKEYWORDS:
        start += 1
    return start


def remap_pool_index_opargs(code_bytes, const_map, name_map, fast_map):
    if EXTENDED_ARG is not None and byte_char(EXTENDED_ARG) in code_bytes:
        return code_bytes
    out = []
    pos = 0
    size = len(code_bytes)
    while pos < size:
        opv = byte_value(code_bytes[pos])
        out.append(byte_char(opv))
        pos += 1
        if opv >= HAVE_ARGUMENT and pos + 1 < size:
            arg = byte_value(code_bytes[pos]) | (byte_value(code_bytes[pos + 1]) << 8)
            if opv == LOAD_CONST and arg in const_map:
                arg = const_map[arg]
            elif opv in NAME_INDEX_OPS and arg in name_map:
                arg = name_map[arg]
            elif opv in FAST_INDEX_OPS and arg in fast_map:
                arg = fast_map[arg]
            out.append(write_oparg(arg))
            pos += 2
    return b''.join(out)


def apply_index_pool_shuffle(co, code_bytes, consts, names, varnames):
    if EXTENDED_ARG is not None and byte_char(EXTENDED_ARG) in code_bytes:
        return consts, names, varnames, code_bytes
    consts, const_map = shuffle_index_pool(consts, 1)
    names, name_map = shuffle_index_pool(names, 0)
    fast_map = dict((idx, idx) for idx in range(len(varnames)))
    var_start = safe_varname_shuffle_start(co)
    if var_start is not None:
        varnames, fast_map = shuffle_index_pool(varnames, var_start)
    code_bytes = remap_pool_index_opargs(code_bytes, const_map, name_map, fast_map)
    return consts, names, varnames, code_bytes


def split_bytecode_units(code_bytes):
    units = []
    pos = 0
    size = len(code_bytes)
    while pos < size:
        opv = byte_value(code_bytes[pos])
        length = 3 if opv >= HAVE_ARGUMENT and pos + 2 < size else 1
        units.append((pos, code_bytes[pos:pos + length]))
        pos += length
    return units


def is_relative_jump_op(opv):
    name = opcode.opname[opv] if opv < len(opcode.opname) else ''
    return opv in opcode.hasjrel or name in ('SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH')


def is_absolute_jump_op(opv):
    return opv in opcode.hasjabs


def is_control_flow_op(opv):
    name = opcode.opname[opv] if opv < len(opcode.opname) else ''
    return (is_relative_jump_op(opv) or is_absolute_jump_op(opv) or
            name.startswith('RETURN') or name.startswith('RAISE') or
            name in ('BREAK_LOOP', 'CONTINUE_LOOP', 'YIELD_VALUE', 'END_FINALLY'))


def make_split_gate_payload(index, bad_units, nop_bloat, taunt_text):
    payload = []
    small = max(0, min(12, nop_bloat))
    for _ in range(small):
        payload.append(byte_char(NOP))
    if taunt_text and index % 3 == 0:
        payload.append(byte_char(LOAD_CONST))
        payload.append(write_oparg(0))
        payload.append(byte_char(POP_TOP))
    bad_ops = [255, 254, 251, 250, 249, 248, 247]
    for _ in range(max(0, min(8, bad_units))):
        payload.append(byte_char(random.choice(bad_ops)))
        payload.append(byte_char(random.randint(0, 255)))
        payload.append(byte_char(random.randint(0, 255)))
    return b''.join(payload)


def is_loop_shadow_op(opv):
    name = opcode.opname[opv] if opv < len(opcode.opname) else ''
    return name in ('FOR_ITER', 'JUMP_ABSOLUTE', 'SETUP_LOOP', 'CONTINUE_LOOP')


def bytecode_split_gates(code_bytes, interval=18, bad_units=2, nop_bloat=2, taunt_text=None, adaptive=False, shadow_loops=False):
    if not interval or interval <= 0 or JUMP_FORWARD is None:
        return code_bytes
    units = split_bytecode_units(code_bytes)
    if len(units) < interval + 4:
        return code_bytes
    if adaptive:
        if len(units) > 900:
            interval = max(5, interval // 3)
        elif len(units) > 350:
            interval = max(7, interval // 2)
        elif len(units) < 80:
            interval = max(interval, 28)
    selected = set()
    for idx in range(interval, len(units) - 2, interval):
        old_pos = units[idx][0]
        selected.add(old_pos)
    if shadow_loops:
        for idx, (old_pos, unit) in enumerate(units):
            if idx + 2 < len(units) and is_loop_shadow_op(byte_value(unit[0])):
                selected.add(old_pos)
    inserts = {}
    added = 0
    for idx, (old_pos, _unit) in enumerate(units):
        if old_pos in selected:
            payload = make_split_gate_payload(idx, bad_units, nop_bloat, taunt_text)
            if payload and len(payload) <= 65535:
                gate = byte_char(JUMP_FORWARD) + write_oparg(len(payload)) + payload
                inserts[old_pos] = gate
                added += len(gate)
    if not inserts:
        return code_bytes

    new_pos = {}
    cursor = 0
    for old_pos, unit in units:
        new_pos[old_pos] = cursor
        if old_pos in inserts:
            cursor += len(inserts[old_pos])
        cursor += len(unit)
    old_end = len(code_bytes)
    new_end = old_end + added

    out = []
    for old_pos, unit in units:
        if old_pos in inserts:
            out.append(inserts[old_pos])
        opv = byte_value(unit[0])
        if len(unit) == 3 and opv != EXTENDED_ARG:
            arg = read_oparg(unit, 0)
            if is_relative_jump_op(opv):
                old_target = old_pos + 3 + arg
                mapped_from = new_pos[old_pos] + (len(inserts.get(old_pos, ''))) + 3
                mapped_target = new_pos.get(old_target, new_end if old_target == old_end else None)
                if mapped_target is not None:
                    new_arg = mapped_target - mapped_from
                    if 0 <= new_arg <= 65535:
                        unit = byte_char(byte_value(unit[0])) + write_oparg(new_arg)
                    else:
                        return code_bytes
            elif is_absolute_jump_op(opv):
                mapped_target = new_pos.get(arg, new_end if arg == old_end else None)
                if mapped_target is not None and 0 <= mapped_target <= 65535:
                    unit = byte_char(byte_value(unit[0])) + write_oparg(mapped_target)
                elif mapped_target is not None:
                    return code_bytes
        out.append(unit)
    transformed = b''.join(out)
    try:
        from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import build_control_flow_graph
        graph = build_control_flow_graph(transformed)
    except (IndexError, KeyError, TypeError, ValueError):
        return code_bytes
    if not graph.stack_safe:
        return code_bytes
    return transformed


def bytecode_reorder_linear_blocks(code_bytes, min_units=3, max_units=8, limit=3):
    """Deprecated unsafe linear-unit permutation.

    The legacy layout emitted ``jump A; B; jump A; A`` without an ``A -> B``
    continuation.  That made B unreachable and silently removed part of an
    expression stack (for example the owner of ``BINARY_SUBSCR``).  Physical
    relocation is now exclusively handled by ``apply_basic_block_shuffle``,
    which rebuilds CFG targets and verifies stack depths after rendering.
    """
    return code_bytes

    # Retained below as historical reference for old configuration files;
    # execution intentionally never enters this implementation.
    if JUMP_FORWARD is None or JUMP_ABSOLUTE is None:
        return code_bytes
    if not code_bytes or len(code_bytes) > 6000:
        return code_bytes
    units = split_bytecode_units(code_bytes)
    if len(units) < (min_units * 2 + 2):
        return code_bytes
    if any(is_control_flow_op(byte_value(unit[1][0])) and byte_value(unit[1][0]) != RETURN_VALUE for unit in units):
        return code_bytes
    if sum(1 for unit in units if byte_value(unit[1][0]) == RETURN_VALUE) != 1:
        return code_bytes
    if byte_value(units[-1][1][0]) != RETURN_VALUE:
        return code_bytes
    body_units = units[:-1]
    return_unit = units[-1][1]
    out = []
    idx = 0
    changed = 0
    min_units = max(1, min_units)
    max_units = max(min_units, max_units)

    def unit_has_control(unit):
        return is_control_flow_op(byte_value(unit[0])) or byte_value(unit[0]) == EXTENDED_ARG

    while idx < len(body_units):
        if changed >= limit or idx + (min_units * 2) >= len(body_units):
            out.extend([u[1] for u in body_units[idx:]])
            break
        a_len = random.randint(min_units, max_units)
        b_len = random.randint(min_units, max_units)
        if idx + a_len + b_len >= len(body_units):
            out.append(body_units[idx][1])
            idx += 1
            continue
        block_a = [u[1] for u in body_units[idx:idx + a_len]]
        block_b = [u[1] for u in body_units[idx + a_len:idx + a_len + b_len]]
        if any(unit_has_control(u) for u in block_a + block_b):
            out.append(body_units[idx][1])
            idx += 1
            continue
        a = b''.join(block_a)
        b = b''.join(block_b)
        if len(a) > 65535 or len(b) + 3 > 65535:
            out.append(units[idx][1])
            idx += 1
            continue
        base = sum(len(x) for x in out)
        a_start = base + 3 + len(b) + 3
        entry = len(b) + 3
        out.append(byte_char(JUMP_FORWARD) + write_oparg(entry))
        out.append(b)
        out.append(byte_char(JUMP_ABSOLUTE) + write_oparg(a_start))
        out.append(a)
        changed += 1
        idx += a_len + b_len
    out.append(return_unit)
    return b''.join(out)


def build_legal_junk_payload(width=3, true_const_index=0, junk_local_index=None, include_oparg_poison=False):
    payload = []
    for _ in range(max(1, width)):
        choice = random.randint(0, 5)
        if choice == 0:
            payload.append(byte_char(NOP))
        elif choice == 1:
            payload.append(byte_char(LOAD_CONST))
            payload.append(write_oparg(true_const_index))
            payload.append(byte_char(POP_TOP))
        elif choice == 2 and junk_local_index is not None and STORE_FAST is not None and DELETE_FAST is not None:
            payload.append(byte_char(LOAD_CONST))
            payload.append(write_oparg(true_const_index))
            payload.append(byte_char(STORE_FAST))
            payload.append(write_oparg(junk_local_index))
            payload.append(byte_char(DELETE_FAST))
            payload.append(write_oparg(junk_local_index))
        elif choice == 3 and JUMP_FORWARD is not None:
            payload.append(byte_char(JUMP_FORWARD))
            payload.append(write_oparg(0))
        elif choice == 4 and include_oparg_poison:
            payload.append(byte_char(LOAD_CONST))
            payload.append(write_oparg(65535))
        else:
            payload.append(byte_char(LOAD_CONST))
            payload.append(write_oparg(true_const_index))
            payload.append(byte_char(POP_TOP))
    return b''.join(payload)


def build_safe_jump_block(width=3, true_const_index=0, junk_local_index=None, include_oparg_poison=False):
    if JUMP_FORWARD is None:
        return ''
    payload = build_legal_junk_payload(width, true_const_index, junk_local_index, include_oparg_poison)
    if not payload or len(payload) > 65535:
        return ''
    return byte_char(JUMP_FORWARD) + write_oparg(len(payload)) + payload


def build_taken_jump_poison_payload(units=6):
    """Build fixed-width poison instructions for a never-entered branch.

    Every record is three bytes so both the normal and NetEase opcode walkers
    keep instruction boundaries deterministic even though execution always
    jumps over this region.
    """
    units = max(1, min(64, int(units or 1)))
    unknown_ops = [255, 254, 251, 250, 249, 248, 247]
    arg_names = (
        'LOAD_CONST', 'LOAD_FAST', 'STORE_FAST', 'DELETE_FAST',
        'LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_ATTR', 'IMPORT_FROM',
        'CALL_FUNCTION', 'MAKE_FUNCTION', 'UNPACK_SEQUENCE',
        'SETUP_FINALLY', 'SETUP_EXCEPT', 'JUMP_ABSOLUTE',
    )
    arg_ops = [opcode.opmap[name] for name in arg_names
               if name in opcode.opmap]
    rows = []
    for index in range(units):
        mode = index % 4
        if mode == 0:
            opv = random.choice(unknown_ops)
            arg = random.randint(0, 65535)
        elif mode == 1 and arg_ops:
            opv = random.choice(arg_ops)
            arg = random.randint(0xff00, 65535)
        elif mode == 2 and JUMP_ABSOLUTE is not None:
            opv = JUMP_ABSOLUTE
            arg = random.randint(0xff00, 65535)
        else:
            opv = random.choice(unknown_ops)
            arg = ((index + 1) * random.randint(257, 4095)) & 65535
        rows.append(byte_char(opv) + write_oparg(arg))
    return b''.join(rows)


def bytecode_taken_jump_poison(code_bytes, interval=20, units=6, limit=6,
                               true_const_index=0):
    """Insert ``if True: jump real`` gates followed by unreachable poison."""
    if POP_JUMP_IF_TRUE is None or true_const_index < 0 or true_const_index > 65535:
        return code_bytes
    interval = max(4, int(interval or 20))
    limit = max(0, min(64, int(limit or 0)))
    units_list = split_bytecode_units(code_bytes)
    if limit <= 0 or len(units_list) < interval + 4:
        return code_bytes
    selected = []
    for index in range(interval, len(units_list) - 2, interval):
        if len(selected) >= limit:
            break
        old_pos, unit = units_list[index]
        if byte_value(unit[0]) != EXTENDED_ARG:
            selected.append(old_pos)
    if not selected:
        return code_bytes

    payloads = dict((pos, build_taken_jump_poison_payload(units))
                    for pos in selected)
    insert_lengths = dict((pos, 6 + len(payload))
                          for pos, payload in list(payloads.items()))
    old_end = len(code_bytes)
    if old_end + sum(insert_lengths.values()) > 65535:
        return code_bytes

    def map_offset(offset):
        extra = 0
        for insert_pos, insert_len in list(insert_lengths.items()):
            if insert_pos < offset:
                extra += insert_len
        return offset + extra

    new_pos = {}
    cursor = 0
    for old_pos, unit in units_list:
        new_pos[old_pos] = cursor
        cursor += insert_lengths.get(old_pos, 0) + len(unit)

    out = []
    for old_pos, unit in units_list:
        if old_pos in payloads:
            payload = payloads[old_pos]
            real_target = new_pos[old_pos] + insert_lengths[old_pos]
            gate = b''.join((
                byte_char(LOAD_CONST), write_oparg(true_const_index),
                byte_char(POP_JUMP_IF_TRUE), write_oparg(real_target),
                payload,
            ))
            out.append(gate)
        opv = byte_value(unit[0])
        if len(unit) == 3 and opv != EXTENDED_ARG:
            arg = read_oparg(unit, 0)
            if is_relative_jump_op(opv):
                old_target = old_pos + 3 + arg
                mapped_from = (new_pos[old_pos] +
                               insert_lengths.get(old_pos, 0) + 3)
                mapped_target = (map_offset(old_target)
                                 if 0 <= old_target <= old_end else None)
                if mapped_target is not None:
                    new_arg = mapped_target - mapped_from
                    if 0 <= new_arg <= 65535:
                        unit = byte_char(byte_value(unit[0])) + write_oparg(new_arg)
            elif is_absolute_jump_op(opv):
                mapped_target = (map_offset(arg)
                                 if 0 <= arg <= old_end else None)
                if mapped_target is not None and mapped_target <= 65535:
                    unit = byte_char(byte_value(unit[0])) + write_oparg(mapped_target)
        out.append(unit)
    return b''.join(out)


def build_exception_decoy_block(true_const_index=0):
    setup_finally = opcode.opmap.get('SETUP_FINALLY')
    pop_block = opcode.opmap.get('POP_BLOCK')
    end_finally = opcode.opmap.get('END_FINALLY')
    if JUMP_FORWARD is None or setup_finally is None or pop_block is None or end_finally is None:
        return ''
    body = b''.join([
        byte_char(LOAD_CONST), write_oparg(true_const_index),
        byte_char(POP_TOP),
        byte_char(pop_block),
    ])
    handler = b''.join([
        byte_char(LOAD_CONST), write_oparg(true_const_index),
        byte_char(POP_TOP),
        byte_char(end_finally),
    ])
    body = body + byte_char(JUMP_FORWARD) + write_oparg(len(handler))
    protected = byte_char(setup_finally) + write_oparg(len(body)) + body + handler
    if len(protected) > 65535:
        return ''
    return byte_char(JUMP_FORWARD) + write_oparg(len(protected)) + protected


def prepend_exception_decoys(code_bytes, count=0, true_const_index=0):
    if count <= 0:
        return code_bytes
    blocks = []
    for _ in range(max(0, min(8, int(count)))):
        block = build_exception_decoy_block(true_const_index)
        if block:
            blocks.append(block)
    payload = b''.join(blocks)
    if not payload:
        return code_bytes
    return insert_bytecode_blocks(code_bytes, {0: payload})


def prepend_legal_entry_noise(code_bytes, count=0, true_const_index=0, junk_local_index=None):
    if count <= 0:
        return code_bytes
    count = max(0, min(64, int(count)))
    block = byte_char(NOP) * count
    if not block:
        return code_bytes
    return insert_bytecode_blocks(code_bytes, {0: block})


def bytecode_safe_dead_blocks(code_bytes, interval=20, width=4, limit=6, true_const_index=0, junk_local_index=None, include_oparg_poison=False):
    if include_oparg_poison:
        return bytecode_taken_jump_poison(
            code_bytes, interval, width, limit, true_const_index)
    units = split_bytecode_units(code_bytes)
    if len(units) < interval + 4:
        return code_bytes
    selected = []
    for idx in range(interval, len(units) - 2, max(1, interval)):
        if len(selected) >= limit:
            break
        if byte_value(units[idx][1][0]) != EXTENDED_ARG:
            selected.append(units[idx][0])
    if not selected:
        return code_bytes
    inserts = {}
    for old_pos in selected:
        block = build_safe_jump_block(width, true_const_index, junk_local_index, include_oparg_poison)
        if block:
            inserts[old_pos] = block
    return insert_bytecode_blocks(code_bytes, inserts)


def bytecode_opaque_predicates(code_bytes, interval=28, width=3, limit=4,
                               true_const_index=0, junk_local_index=None,
                               predicate_local_index=None):
    if POP_JUMP_IF_FALSE is None or JUMP_FORWARD is None:
        return code_bytes
    units = split_bytecode_units(code_bytes)
    if len(units) < interval + 4:
        return code_bytes
    block_specs = {}
    made = 0
    for idx in range(interval, len(units) - 2, max(1, interval)):
        if made >= limit:
            break
        old_pos = units[idx][0]
        if byte_value(units[idx][1][0]) == EXTENDED_ARG:
            continue
        false_payload = build_legal_junk_payload(width, true_const_index, junk_local_index, False)
        true_payload = build_legal_junk_payload(max(1, width // 2), true_const_index, junk_local_index, False)
        if len(false_payload) > 65535 or len(true_payload) > 65535:
            continue
        block_specs[old_pos] = (true_payload, false_payload)
        made += 1
    if not block_specs:
        return code_bytes
    # Prefer an identity predicate over a literal True when a parameter slot
    # is available.  ``arg is arg`` is stable for every Python object type,
    # but cannot be folded without tracking the function's runtime frame.
    # Callers may pass None to retain the literal predicate for zero-argument
    # functions.
    compare_is = None
    if predicate_local_index is not None and LOAD_FAST is not None:
        try:
            compare_is = opcode.cmp_op.index('is')
        except (AttributeError, ValueError):
            compare_is = 8
        if predicate_local_index < 0 or predicate_local_index > 65535:
            predicate_local_index = None
    predicate_prefix_len = 12 if predicate_local_index is not None else 6
    insert_lengths = {}
    for old_pos, spec in list(block_specs.items()):
        true_payload, false_payload = spec
        insert_lengths[old_pos] = predicate_prefix_len + len(true_payload) + 3 + len(false_payload)
    old_end = len(code_bytes)

    def map_offset(offset):
        extra = 0
        for insert_pos, insert_len in list(insert_lengths.items()):
            if insert_pos < offset:
                extra += insert_len
        return offset + extra

    new_pos = {}
    cursor = 0
    for old_pos, unit in units:
        new_pos[old_pos] = cursor
        if old_pos in insert_lengths:
            cursor += insert_lengths[old_pos]
        cursor += len(unit)
    out = []
    for old_pos, unit in units:
        if old_pos in block_specs:
            true_payload, false_payload = block_specs[old_pos]
            block_start = new_pos[old_pos]
            false_start = block_start + predicate_prefix_len + len(true_payload) + 3
            block = []
            if predicate_local_index is not None:
                block.append(byte_char(LOAD_FAST))
                block.append(write_oparg(predicate_local_index))
                block.append(byte_char(LOAD_FAST))
                block.append(write_oparg(predicate_local_index))
                block.append(byte_char(COMPARE_OP))
                block.append(write_oparg(compare_is))
            else:
                block.append(byte_char(LOAD_CONST))
                block.append(write_oparg(true_const_index))
            block.append(byte_char(POP_JUMP_IF_FALSE))
            block.append(write_oparg(false_start))
            block.append(true_payload)
            block.append(byte_char(JUMP_FORWARD))
            block.append(write_oparg(len(false_payload)))
            block.append(false_payload)
            out.append(b''.join(block))
        opv = byte_value(unit[0])
        if len(unit) == 3 and opv != EXTENDED_ARG:
            arg = read_oparg(unit, 0)
            if is_relative_jump_op(opv):
                old_target = old_pos + 3 + arg
                mapped_from = new_pos[old_pos] + insert_lengths.get(old_pos, 0) + 3
                mapped_target = map_offset(old_target) if 0 <= old_target <= old_end else None
                if mapped_target is not None:
                    new_arg = mapped_target - mapped_from
                    if 0 <= new_arg <= 65535:
                        unit = byte_char(byte_value(unit[0])) + write_oparg(new_arg)
            elif is_absolute_jump_op(opv):
                mapped_target = map_offset(arg) if 0 <= arg <= old_end else None
                if mapped_target is not None and 0 <= mapped_target <= 65535:
                    unit = byte_char(byte_value(unit[0])) + write_oparg(mapped_target)
        out.append(unit)
    return b''.join(out)


def can_apply_bytecode_opaque_predicates(co, code_bytes):
    if getattr(co, 'co_name', None) in ('__init__', 'InitClient', 'InitServer', 'DestroyClient', 'DestroyServer', 'Update', 'Destroy'):
        return False
    if not code_bytes or len(code_bytes) > 1200:
        return False
    units = split_bytecode_units(code_bytes)
    if len(units) < 10:
        return False
    return_count = 0
    for _old_pos, unit in units:
        opv = byte_value(unit[0])
        if opv == RETURN_VALUE:
            return_count += 1
            continue
        if is_control_flow_op(opv):
            return False
    return return_count == 1 and byte_value(units[-1][1][0]) == RETURN_VALUE


def insert_bytecode_blocks(code_bytes, inserts):
    if not inserts:
        return code_bytes
    units = split_bytecode_units(code_bytes)
    insert_lengths = dict((old_pos, len(block)) for old_pos, block in list(inserts.items()))
    old_end = len(code_bytes)

    def map_offset(offset):
        extra = 0
        for insert_pos, insert_len in list(insert_lengths.items()):
            if insert_pos < offset:
                extra += insert_len
        return offset + extra

    new_pos = {}
    cursor = 0
    for old_pos, unit in units:
        new_pos[old_pos] = cursor
        if old_pos in insert_lengths:
            cursor += insert_lengths[old_pos]
        cursor += len(unit)
    out = []
    for old_pos, unit in units:
        if old_pos in inserts:
            out.append(inserts[old_pos])
        opv = byte_value(unit[0])
        if len(unit) == 3 and opv != EXTENDED_ARG:
            arg = read_oparg(unit, 0)
            if is_relative_jump_op(opv):
                old_target = old_pos + 3 + arg
                mapped_from = new_pos[old_pos] + insert_lengths.get(old_pos, 0) + 3
                mapped_target = map_offset(old_target) if 0 <= old_target <= old_end else None
                if mapped_target is not None:
                    new_arg = mapped_target - mapped_from
                    if 0 <= new_arg <= 65535:
                        unit = byte_char(byte_value(unit[0])) + write_oparg(new_arg)
            elif is_absolute_jump_op(opv):
                mapped_target = map_offset(arg) if 0 <= arg <= old_end else None
                if mapped_target is not None and 0 <= mapped_target <= 65535:
                    unit = byte_char(byte_value(unit[0])) + write_oparg(mapped_target)
        out.append(unit)
    return b''.join(out)


def bytecode_stack_equivalent_noise(code_bytes, interval=18, limit=6, true_const_index=0):
    interval = max(4, int(interval or 18))
    limit = max(0, min(64, int(limit or 0)))
    if limit <= 0 or true_const_index < 0 or true_const_index > 65535:
        return code_bytes
    if EXTENDED_ARG is not None and byte_char(EXTENDED_ARG) in code_bytes:
        return code_bytes
    units = split_bytecode_units(code_bytes)
    if len(units) < interval + 4:
        return code_bytes
    payload = byte_char(LOAD_CONST) + write_oparg(true_const_index) + byte_char(POP_TOP)
    inserts = {}
    made = 0
    for idx in range(interval, len(units) - 2, interval):
        if made >= limit:
            break
        old_pos, unit = units[idx]
        prev_op = byte_value(units[idx - 1][1][0])
        opv = byte_value(unit[0])
        if old_pos <= 0 or opv == EXTENDED_ARG or prev_op == EXTENDED_ARG:
            continue
        if is_control_flow_op(opv) or is_control_flow_op(prev_op):
            continue
        inserts[old_pos] = payload
        made += 1
    return insert_bytecode_blocks(code_bytes, inserts)


def bytecode_conditional_jump_inversion(code_bytes, limit=4):
    limit = max(0, min(64, int(limit or 0)))
    if limit <= 0 or JUMP_ABSOLUTE is None or POP_JUMP_IF_FALSE is None or POP_JUMP_IF_TRUE is None:
        return code_bytes
    if EXTENDED_ARG is not None and byte_char(EXTENDED_ARG) in code_bytes:
        return code_bytes
    units = split_bytecode_units(code_bytes)
    old_end = len(code_bytes)
    boundaries = set([old_pos for old_pos, _unit in units])
    boundaries.add(old_end)
    candidates = []
    for idx, (old_pos, unit) in enumerate(units):
        if idx + 1 >= len(units) or len(unit) != 3:
            continue
        opv = byte_value(unit[0])
        if opv not in (POP_JUMP_IF_FALSE, POP_JUMP_IF_TRUE):
            continue
        target = read_oparg(unit, 0)
        fallthrough = old_pos + 3
        if target not in boundaries or fallthrough not in boundaries:
            continue
        candidates.append(old_pos)
    if not candidates:
        return code_bytes
    if len(candidates) > limit:
        candidates = sorted(random.sample(candidates, limit))
    selected = set(candidates)
    new_pos = {}
    cursor = 0
    for old_pos, unit in units:
        new_pos[old_pos] = cursor
        cursor += 6 if old_pos in selected else len(unit)
    new_end = cursor
    if new_end > 65535:
        return code_bytes

    def map_target(target):
        if target == old_end:
            return new_end
        return new_pos.get(target)

    out = []
    for old_pos, unit in units:
        opv = byte_value(unit[0])
        if old_pos in selected:
            old_target = read_oparg(unit, 0)
            mapped_target = map_target(old_target)
            mapped_fallthrough = map_target(old_pos + 3)
            if mapped_target is None or mapped_fallthrough is None:
                return code_bytes
            inverted = POP_JUMP_IF_TRUE if opv == POP_JUMP_IF_FALSE else POP_JUMP_IF_FALSE
            out.append(byte_char(inverted) + write_oparg(mapped_fallthrough))
            out.append(byte_char(JUMP_ABSOLUTE) + write_oparg(mapped_target))
            continue
        if len(unit) == 3 and opv != EXTENDED_ARG:
            arg = read_oparg(unit, 0)
            if is_relative_jump_op(opv):
                old_target = old_pos + 3 + arg
                mapped_target = map_target(old_target)
                if mapped_target is not None:
                    new_arg = mapped_target - (new_pos[old_pos] + 3)
                    if not (0 <= new_arg <= 65535):
                        return code_bytes
                    unit = byte_char(byte_value(unit[0])) + write_oparg(new_arg)
            elif is_absolute_jump_op(opv):
                mapped_target = map_target(arg)
                if mapped_target is not None:
                    unit = byte_char(byte_value(unit[0])) + write_oparg(mapped_target)
        out.append(unit)
    return b''.join(out)


def bytecode_jump_trampoline_chains(code_bytes, limit=4, candidate_end=None):
    limit = max(0, min(64, int(limit or 0)))
    if limit <= 0 or JUMP_ABSOLUTE is None or JUMP_FORWARD is None:
        return code_bytes
    if EXTENDED_ARG is not None and byte_char(EXTENDED_ARG) in code_bytes:
        return code_bytes
    units = split_bytecode_units(code_bytes)
    old_end = len(code_bytes)
    if candidate_end is None:
        candidate_end = old_end
    candidate_end = max(0, min(old_end, int(candidate_end)))
    boundaries = set([old_pos for old_pos, _unit in units])
    boundaries.add(old_end)
    candidates = []
    conditional_ops = set(op for op in (POP_JUMP_IF_FALSE, POP_JUMP_IF_TRUE)
                           if op is not None)
    for old_pos, unit in units:
        if old_pos <= 3 or old_pos >= candidate_end or len(unit) != 3:
            continue
        opv = byte_value(unit[0])
        if opv not in (JUMP_ABSOLUTE, JUMP_FORWARD) and opv not in conditional_ops:
            continue
        arg = read_oparg(unit, 0)
        target = (arg if opv in (JUMP_ABSOLUTE,) or opv in conditional_ops
                  else old_pos + 3 + arg)
        if target not in boundaries:
            continue
        candidates.append(old_pos)
    if not candidates:
        return code_bytes
    if len(candidates) > limit:
        candidates = sorted(random.sample(candidates, limit))
    selected = set(candidates)
    conditional_positions = dict(
        (old_pos, byte_value(unit[0]) in conditional_ops)
        for old_pos, unit in units if old_pos in selected)
    new_pos = {}
    cursor = 0
    for old_pos, unit in units:
        new_pos[old_pos] = cursor
        if old_pos in selected and conditional_positions.get(old_pos):
            cursor += 9
        else:
            cursor += 6 if old_pos in selected else len(unit)
    new_end = cursor
    if new_end > 65535:
        return code_bytes

    def map_target(target):
        if target == old_end:
            return new_end
        return new_pos.get(target)

    out = []
    for old_pos, unit in units:
        opv = byte_value(unit[0])
        if old_pos in selected:
            arg = read_oparg(unit, 0)
            is_conditional = opv in conditional_ops
            old_target = (arg if opv == JUMP_ABSOLUTE or is_conditional
                          else old_pos + 3 + arg)
            mapped_target = map_target(old_target)
            trampoline = (new_pos[old_pos] + 6
                          if is_conditional else new_pos[old_pos] + 3)
            if mapped_target is None or trampoline > 65535:
                return code_bytes
            if is_conditional:
                # Preserve the original taken/not-taken edge and only route
                # the taken branch through the second-stage jump. The
                # fallthrough skip keeps the two paths separate.
                out.append(byte_char(opv) + write_oparg(trampoline))
                out.append(byte_char(JUMP_FORWARD) + write_oparg(3))
            else:
                # Map the goto-like first hop to CPython's forward jump.  A
                # zero-distance JUMP_FORWARD lands on the adjacent absolute
                # target hop, preserving semantics while exposing the same
                # two-stage shape as the reference Flow transformer.
                out.append(byte_char(JUMP_FORWARD) + write_oparg(0))
            out.append(byte_char(JUMP_ABSOLUTE) + write_oparg(mapped_target))
            continue
        if len(unit) == 3 and opv != EXTENDED_ARG:
            arg = read_oparg(unit, 0)
            if is_relative_jump_op(opv):
                old_target = old_pos + 3 + arg
                mapped_target = map_target(old_target)
                if mapped_target is not None:
                    new_arg = mapped_target - (new_pos[old_pos] + 3)
                    if not (0 <= new_arg <= 65535):
                        return code_bytes
                    unit = byte_char(byte_value(unit[0])) + write_oparg(new_arg)
            elif is_absolute_jump_op(opv):
                mapped_target = map_target(arg)
                if mapped_target is not None:
                    unit = byte_char(byte_value(unit[0])) + write_oparg(mapped_target)
        out.append(unit)
    transformed = b''.join(out)
    try:
        from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import build_control_flow_graph
        graph = build_control_flow_graph(transformed)
    except (IndexError, KeyError, TypeError, ValueError):
        return code_bytes
    if not graph.validate() or not graph.stack_safe:
        return code_bytes
    return transformed


def bytecode_strategy_variant(co, depth=0, seed=0, variant_count=4):
    variant_count = max(1, int(variant_count or 1))
    token = repr((getattr(co, 'co_name', ''), os.path.basename(getattr(co, 'co_filename', '')),
                  int(depth), len(getattr(co, 'co_code', '')), int(seed or 0)))
    # Python 2's zlib.crc32 requires a byte string.  Code metadata may be a
    # unicode value (especially after filename/name poisoning), so normalize
    # the deterministic strategy token explicitly on both runtimes.
    if not isinstance(token, bytes):
        token = token.encode('utf-8')
    return (zlib.crc32(token) & 0xffffffff) % variant_count


def bytecode_has_exception_control_flow(code_bytes):
    risky = set()
    for op_name in ('SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH', 'WITH_CLEANUP', 'END_FINALLY'):
        opv = opcode.opmap.get(op_name)
        if opv is not None:
            risky.add(opv)
    if not risky:
        return False
    for _pos, unit in split_bytecode_units(code_bytes):
        if unit and byte_value(unit[0]) in risky:
            return True
    return False


def is_safe_delayed_const(value, depth=0):
    if isinstance(value, types.CodeType) or value is None or value is True or value is False:
        return False
    if isinstance(value, (int, float, complex, str)):
        return True
    if isinstance(value, tuple) and depth < 2 and len(value) <= 12:
        return all(is_safe_delayed_const(item, depth + 1) for item in value)
    return False


def bytecode_delayed_constant_access(code_bytes, consts, limit=3, candidate_end=None):
    limit = max(0, min(32, int(limit or 0)))
    if limit <= 0 or BINARY_SUBSCR is None:
        return code_bytes, consts, 0
    if EXTENDED_ARG is not None and byte_char(EXTENDED_ARG) in code_bytes:
        return code_bytes, consts, 0
    units = split_bytecode_units(code_bytes)
    old_end = len(code_bytes)
    if candidate_end is None:
        candidate_end = old_end
    candidate_end = max(0, min(old_end, int(candidate_end)))
    candidates = []
    for old_pos, unit in units:
        if old_pos < 12 or old_pos >= candidate_end or len(unit) != 3 or byte_value(unit[0]) != LOAD_CONST:
            continue
        const_index = read_oparg(unit, 0)
        if const_index < 0 or const_index >= len(consts):
            continue
        if not is_safe_delayed_const(consts[const_index]):
            continue
        candidates.append((old_pos, const_index))
    if not candidates:
        return code_bytes, consts, 0
    if len(candidates) > limit:
        candidates = random.sample(candidates, limit)
    selected = dict(candidates)
    new_consts = list(consts)
    zero_index = None
    for idx, value in enumerate(new_consts):
        if type(value) is int and value == 0:
            zero_index = idx
            break
    if zero_index is None:
        zero_index = len(new_consts)
        new_consts.append(0)
    wrapper_indexes = {}
    for _old_pos, const_index in candidates:
        if const_index not in wrapper_indexes:
            wrapper_indexes[const_index] = len(new_consts)
            new_consts.append((new_consts[const_index],))
    if len(new_consts) > 65535:
        return code_bytes, consts, 0
    new_pos = {}
    cursor = 0
    for old_pos, unit in units:
        new_pos[old_pos] = cursor
        cursor += 7 if old_pos in selected else len(unit)
    new_end = cursor
    if new_end > 65535:
        return code_bytes, consts, 0

    def map_target(target):
        if target == old_end:
            return new_end
        return new_pos.get(target)

    out = []
    for old_pos, unit in units:
        opv = byte_value(unit[0])
        if old_pos in selected:
            wrapper_index = wrapper_indexes[selected[old_pos]]
            out.append(byte_char(LOAD_CONST) + write_oparg(wrapper_index))
            out.append(byte_char(LOAD_CONST) + write_oparg(zero_index))
            out.append(byte_char(BINARY_SUBSCR))
            continue
        if len(unit) == 3 and opv != EXTENDED_ARG:
            arg = read_oparg(unit, 0)
            if is_relative_jump_op(opv):
                old_target = old_pos + 3 + arg
                mapped_target = map_target(old_target)
                if mapped_target is not None:
                    new_arg = mapped_target - (new_pos[old_pos] + 3)
                    if not (0 <= new_arg <= 65535):
                        return code_bytes, consts, 0
                    unit = unit[0] + write_oparg(new_arg)
            elif is_absolute_jump_op(opv):
                mapped_target = map_target(arg)
                if mapped_target is not None:
                    unit = unit[0] + write_oparg(mapped_target)
        out.append(unit)
    return b''.join(out), new_consts, len(selected)


def bytecode_extended_arg_prefixes(code_bytes, interval=11, limit=6):
    interval = max(2, int(interval or 11))
    limit = max(0, min(64, int(limit or 0)))
    if limit <= 0 or EXTENDED_ARG is None:
        return code_bytes
    units = split_bytecode_units(code_bytes)
    # Only inspect opcode positions. Searching the raw byte string would also
    # match an ordinary argument byte whose numeric value happens to be 145.
    if any(byte_value(unit[0]) == EXTENDED_ARG for _old_pos, unit in units):
        return code_bytes
    candidates = []
    for index, (old_pos, unit) in enumerate(units):
        if index < 2 or len(unit) != 3:
            continue
        opv = byte_value(unit[0])
        if opv == EXTENDED_ARG or is_relative_jump_op(opv) or is_absolute_jump_op(opv):
            continue
        if is_control_flow_op(opv):
            continue
        candidates.append((index, old_pos))
    selected = [old_pos for index, old_pos in candidates if index % interval == 0]
    if len(selected) < limit:
        remaining = [old_pos for _index, old_pos in candidates if old_pos not in selected]
        random.shuffle(remaining)
        selected.extend(remaining[:limit - len(selected)])
    selected = selected[:limit]
    if not selected:
        return code_bytes
    prefix = byte_char(EXTENDED_ARG) + '\x00\x00'
    return insert_bytecode_blocks(code_bytes, dict((old_pos, prefix) for old_pos in selected))\n