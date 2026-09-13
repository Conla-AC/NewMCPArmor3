# -*- coding: utf-8 -*-
"""Frame-proved stack templates for straight-line binary expressions."""

import random

from MCP_Armor_Src.core import py27_opcode as opcode
from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import (
    build_control_flow_graph, decode_instructions,
)
from MCP_Armor_Src.bytecode_obf.bytecode_flow.abstract_frame import (
    frame_analysis_gate,
)
from MCP_Armor_Src.bytecode_obf.bytecode_flow.relocator import encode_oparg
from MCP_Armor_Src.utils.encoding import random_ident


LOAD_FAST = opcode.opmap['LOAD_FAST']
LOAD_CONST = opcode.opmap['LOAD_CONST']
STORE_FAST = opcode.opmap['STORE_FAST']
EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')

_BINARY_TEMPLATE_NAMES = set(
    name for name in opcode.opmap
    if name.startswith('BINARY_') and name not in (
        'BINARY_SUBSCR', 'BINARY_DIVIDE', 'BINARY_TRUE_DIVIDE'))


def _patch_arg(output, position, argument):
    encoded = encode_oparg(output[position], argument)
    output[position:position + 3] = encoded


def apply_semantic_templates(co, code_bytes, consts, varnames,
                             limit=4, seed=0):
    """Expand selected ``load, load, binary, store`` idioms.

    The transform only touches straight-line four-instruction windows whose
    operands are fast locals/constants. A temporary local is introduced once,
    jump targets are relocated globally, and both pre/post Frame proofs gate
    the transaction. Unsupported or introspection-sensitive code is returned
    byte-for-byte unchanged.
    """
    original_varnames = list(varnames)
    if (not code_bytes or not original_varnames or
            int(getattr(co, 'co_flags', 0) or 0) & 0x20 or
            getattr(co, 'co_freevars', ()) or getattr(co, 'co_cellvars', ())):
        return code_bytes, varnames, 0
    if set(('locals', 'vars', 'eval', 'exec', 'inspect',
            'currentframe', 'getouterframes', '_getframe',
            'f_locals')).intersection(set(getattr(co, 'co_names', ()) or ())):
        return code_bytes, varnames, 0
    budget = max(0, min(32, int(limit or 0)))
    if budget <= 0:
        return code_bytes, varnames, 0
    allowed, _result = frame_analysis_gate(co, code_bytes, consts, varnames)
    if not allowed:
        return code_bytes, varnames, 0
    try:
        graph = build_control_flow_graph(code_bytes)
        instructions = decode_instructions(code_bytes)
    except (IndexError, KeyError, TypeError, ValueError):
        return code_bytes, varnames, 0
    if any(item.size not in (1, 3) or item.opcode == EXTENDED_ARG
           for item in instructions):
        return code_bytes, varnames, 0
    jump_targets = set(item.target for item in instructions
                       if item.target is not None)
    by_offset = dict((item.offset, item) for item in instructions)
    candidates = []
    for index in range(0, len(instructions) - 3):
        first, second, operation, store = instructions[index:index + 4]
        if (first.next_offset != second.offset or
                second.next_offset != operation.offset or
                operation.next_offset != store.offset or
                first.size != 3 or second.size != 3 or
                operation.size != 1 or store.size != 3 or
                opcode.opname[first.opcode] not in ('LOAD_FAST', 'LOAD_CONST') or
                opcode.opname[second.opcode] not in ('LOAD_FAST', 'LOAD_CONST') or
                opcode.opname[operation.opcode] not in _BINARY_TEMPLATE_NAMES or
                opcode.opname[store.opcode] != 'STORE_FAST' or
                first.offset in jump_targets or
                second.offset in jump_targets or
                operation.offset in jump_targets or
                store.offset in jump_targets):
            continue
        candidates.append((first, second, operation, store))
    if not candidates:
        return code_bytes, varnames, 0
    rng = random.Random(int(seed or 0) ^ len(code_bytes))
    rng.shuffle(candidates)
    selected = []
    occupied = set()
    for row in candidates:
        offsets = set(item.offset for item in row)
        if occupied.intersection(offsets):
            continue
        selected.append(row)
        occupied.update(offsets)
        if len(selected) >= budget:
            break
    if not selected:
        return code_bytes, varnames, 0
    temp_name = random_ident('tmp')
    while temp_name in original_varnames:
        temp_name = random_ident('tmp')
    temp_index = len(original_varnames)
    new_varnames = original_varnames + [temp_name]
    replacement = {}
    consumed = set()
    for first, second, operation, store in selected:
        replacement[first.offset] = (
            encode_oparg(first.opcode, first.argument) +
            encode_oparg(STORE_FAST, temp_index) +
            encode_oparg(LOAD_FAST, temp_index) +
            encode_oparg(second.opcode, second.argument) +
            operation.raw +
            encode_oparg(store.opcode, store.argument))
        consumed.update((second.offset, operation.offset, store.offset))
    new_offsets = {}
    cursor = 0
    for item in instructions:
        new_offsets[item.offset] = cursor
        if item.offset in replacement:
            cursor += len(replacement[item.offset])
        elif item.offset in consumed:
            continue
        else:
            cursor += item.size
    new_size = cursor
    output = []
    try:
        for item in instructions:
            if item.offset in consumed:
                continue
            if item.offset in replacement:
                output.append(replacement[item.offset])
                continue
            raw = item.raw
            if item.target is not None:
                target = new_size if item.target == len(code_bytes) \
                    else new_offsets[item.target]
                argument = (target - (new_offsets[item.offset] + item.size)
                            if item.opcode in opcode.hasjrel else target)
                raw = encode_oparg(item.opcode, argument)
            output.append(raw)
        transformed = b''.join(output)
        verified = build_control_flow_graph(transformed)
    except (IndexError, KeyError, TypeError, ValueError):
        return code_bytes, varnames, 0
    if not verified.stack_safe:
        return code_bytes, varnames, 0
    allowed, _result = frame_analysis_gate(
        co, transformed, consts, new_varnames)
    if not allowed:
        return code_bytes, varnames, 0
    return transformed, tuple(new_varnames), len(selected)\n