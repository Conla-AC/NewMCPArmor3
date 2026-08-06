# -*- coding: utf-8 -*-
"""Verified state-dispatch CFG rewriting for ordinary Python 2.7 functions."""
from __future__ import absolute_import

import opcode
import random

from MCP_Armor_Src.bytecode_obf.cfg.builder import build_control_flow_graph
from MCP_Armor_Src.bytecode_obf.cfg.relocator import encode_oparg
from MCP_Armor_Src.utils.encoding import random_ident


LOAD_CONST = opcode.opmap['LOAD_CONST']
LOAD_FAST = opcode.opmap['LOAD_FAST']
STORE_FAST = opcode.opmap['STORE_FAST']
BINARY_XOR = opcode.opmap['BINARY_XOR']
BINARY_ADD = opcode.opmap['BINARY_ADD']
BINARY_SUBTRACT = opcode.opmap['BINARY_SUBTRACT']
COMPARE_OP = opcode.opmap['COMPARE_OP']
POP_JUMP_IF_FALSE = opcode.opmap['POP_JUMP_IF_FALSE']
JUMP_ABSOLUTE = opcode.opmap['JUMP_ABSOLUTE']
RAISE_VARARGS = opcode.opmap['RAISE_VARARGS']
EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')

CONDITIONAL_NAMES = set(('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE'))
UNCONDITIONAL_NAMES = set(('JUMP_ABSOLUTE', 'JUMP_FORWARD'))
TERMINAL_NAMES = set(('RETURN_VALUE', 'RAISE_VARARGS', 'BREAK_LOOP', 'STOP_CODE'))
UNSUPPORTED_NAMES = set((
    'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'FOR_ITER',
    'SETUP_LOOP', 'POP_BLOCK', 'BREAK_LOOP', 'CONTINUE_LOOP',
    'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH', 'WITH_CLEANUP',
    'END_FINALLY'))
HOT_NAME_MARKERS = (
    'tick', 'update', 'timer', 'frame', 'render', 'callback',
    'listen', 'notify', 'destroy')


def _random_word(used):
    value = random.randint(1, 0x7fffffff)
    while value in used:
        value = random.randint(1, 0x7fffffff)
    used.add(value)
    return value


def _emit(output, data):
    position = len(output)
    output.extend(data)
    return position


def _emit_jump(output, opvalue):
    return _emit(output, encode_oparg(opvalue, 0))


def _patch_arg(output, position, argument):
    encoded = encode_oparg(ord(output[position]), argument)
    output[position:position + 3] = list(encoded)


def _transition(output, state_index, transition_spec):
    left_const, right_const, operation = transition_spec
    _emit(output, encode_oparg(LOAD_CONST, left_const))
    _emit(output, encode_oparg(LOAD_CONST, right_const))
    _emit(output, chr(operation))
    _emit(output, encode_oparg(STORE_FAST, state_index))
    jump = _emit_jump(output, JUMP_ABSOLUTE)
    return jump


def apply_state_dispatcher(co, code_bytes, consts, varnames,
                           ratio=25, max_blocks=32):
    """Route eligible ordinary blocks through an encoded state dispatcher.

    The transform intentionally excludes exception regions, generators,
    extended arguments and stack-sensitive conditional opcodes. Any failed
    verification returns the original bytecode and metadata unchanged.
    """
    ratio = max(0, min(100, int(ratio or 0)))
    max_blocks = max(2, min(128, int(max_blocks or 0)))
    original_consts = list(consts)
    original_varnames = list(varnames)
    if ratio <= 0 or not code_bytes or len(code_bytes) > 48000:
        return code_bytes, consts, varnames, 0
    if random.randint(1, 100) > ratio:
        return code_bytes, consts, varnames, 0
    if not (co.co_flags & 0x0001) or not (co.co_flags & 0x0002):
        return code_bytes, consts, varnames, 0
    if co.co_flags & 0x0020 or co.co_freevars or co.co_cellvars:
        return code_bytes, consts, varnames, 0
    function_name = (co.co_name or '').lower()
    if ((function_name.startswith('__') and function_name.endswith('__')) or
            any(marker in function_name for marker in HOT_NAME_MARKERS)):
        return code_bytes, consts, varnames, 0
    try:
        graph = build_control_flow_graph(code_bytes)
    except (KeyError, TypeError, ValueError):
        return code_bytes, consts, varnames, 0
    if (not graph.stack_safe or graph.has_exception_flow or
            len(graph.blocks) > max_blocks):
        return code_bytes, consts, varnames, 0
    if any(item.opcode == EXTENDED_ARG for item in graph.instructions):
        return code_bytes, consts, varnames, 0
    if any(opcode.opname[item.opcode] in UNSUPPORTED_NAMES
           for item in graph.instructions):
        return code_bytes, consts, varnames, 0
    if any(block.start not in graph.stack_depths for block in graph.blocks):
        return code_bytes, consts, varnames, 0

    # Split ordinary blocks only where the evaluation stack has returned to
    # the block's incoming depth. This exposes additional states without
    # spilling Python stack values into dispatcher code.
    split_candidates = []
    existing = set(block.start for block in graph.blocks)
    for block in graph.blocks:
        incoming = graph.stack_depths[block.start]
        for item in block.instructions[1:-1]:
            if (item.offset not in existing and
                    graph.stack_depths.get(item.offset) == incoming):
                split_candidates.append(item.offset)
    capacity = max_blocks - len(graph.blocks)
    needed = max(0, 3 - len(graph.blocks))
    if needed and len(split_candidates) < needed:
        return code_bytes, consts, varnames, 0
    if split_candidates and capacity > 0:
        random.shuffle(split_candidates)
        upper = min(capacity, max(needed, max(1, len(split_candidates) // 2)))
        split_count = random.randint(max(needed, 1), upper)
        try:
            graph = build_control_flow_graph(
                code_bytes, split_candidates[:split_count])
        except (KeyError, TypeError, ValueError):
            return code_bytes, consts, varnames, 0
    if len(graph.blocks) < 3 or len(graph.blocks) > max_blocks:
        return code_bytes, consts, varnames, 0

    edge_by_kind = {}
    for edge in graph.edges:
        edge_by_kind[(edge.source.start, edge.kind)] = edge
    for block in graph.blocks:
        name = opcode.opname[block.terminator.opcode]
        if name in CONDITIONAL_NAMES:
            if (edge_by_kind.get((block.start, 'taken')) is None or
                    edge_by_kind.get((block.start, 'fallthrough')) is None):
                return code_bytes, original_consts, original_varnames, 0
        elif name in UNCONDITIONAL_NAMES:
            if edge_by_kind.get((block.start, 'jump')) is None:
                return code_bytes, original_consts, original_varnames, 0
        elif name not in TERMINAL_NAMES and block.successors:
            if len(block.successors) != 1 or block.successors[0].kind != 'fallthrough':
                return code_bytes, original_consts, original_varnames, 0

    consts = list(consts)
    varnames = list(varnames)
    if len(consts) + (len(graph.blocks) * 4) + 2 > 65535:
        return code_bytes, original_consts, original_varnames, 0
    if len(varnames) >= 65535:
        return code_bytes, original_consts, original_varnames, 0

    state_name = random_ident('dispatch')
    while state_name in varnames:
        state_name = random_ident('dispatch')
    state_index = len(varnames)
    varnames.append(state_name)

    used = set()
    block_starts = [block.start for block in graph.blocks]
    state_values = dict((start, _random_word(used)) for start in block_starts)
    state_keys = dict((start, _random_word(used)) for start in block_starts)
    state_ops = dict((start, random.randrange(3)) for start in block_starts)
    state_expected = {}
    for start in block_starts:
        if state_ops[start] == 0:
            expected = state_values[start] ^ state_keys[start]
        elif state_ops[start] == 1:
            expected = state_values[start] + state_keys[start]
        else:
            expected = state_values[start] - state_keys[start]
        state_expected[start] = expected
    transition_specs = {}
    for start in block_starts:
        operation_index = random.randrange(3)
        left = _random_word(used)
        if operation_index == 0:
            right = left ^ state_values[start]
        elif operation_index == 1:
            right = state_values[start] - left
        else:
            right = left - state_values[start]
        left_index = len(consts)
        consts.append(left)
        right_index = len(consts)
        consts.append(right)
        transition_specs[start] = (
            left_index, right_index,
            (BINARY_XOR, BINARY_ADD, BINARY_SUBTRACT)[operation_index])
    key_constants = dict(
        (start, len(consts) + index)
        for index, start in enumerate(block_starts))
    consts.extend(state_keys[start] for start in block_starts)
    expected_constants = dict(
        (start, len(consts) + index)
        for index, start in enumerate(block_starts))
    consts.extend(state_expected[start] for start in block_starts)
    failure_const = len(consts)
    consts.append('invalid bytecode dispatcher state')

    order = list(graph.blocks)
    random.shuffle(order)
    output = []
    block_offsets = {}
    transition_jumps = []
    conditional_jumps = []
    taken_proxies = []

    # The physical first block is randomized, so initialize the logical entry
    # state and enter the dispatcher before executing any block body.
    transition_jumps.append(_transition(
        output, state_index, transition_specs[0]))

    for block in order:
        block_offsets[block.start] = len(output)
        terminator = block.terminator
        name = opcode.opname[terminator.opcode]
        for item in block.instructions[:-1]:
            if item.target is not None:
                return code_bytes, original_consts, original_varnames, 0
            _emit(output, item.raw)
        if name in CONDITIONAL_NAMES:
            taken = edge_by_kind[(block.start, 'taken')]
            fallthrough = edge_by_kind[(block.start, 'fallthrough')]
            conditional = _emit_jump(output, terminator.opcode)
            conditional_jumps.append((conditional, taken.target.start))
            transition_jumps.append(_transition(
                output, state_index, transition_specs[fallthrough.target.start]))
            taken_proxies.append(taken.target.start)
        elif name in UNCONDITIONAL_NAMES:
            target = edge_by_kind[(block.start, 'jump')].target.start
            transition_jumps.append(_transition(
                output, state_index, transition_specs[target]))
        elif name in TERMINAL_NAMES:
            _emit(output, terminator.raw)
        elif block.successors:
            _emit(output, terminator.raw)
            target = block.successors[0].target.start
            transition_jumps.append(_transition(
                output, state_index, transition_specs[target]))
        else:
            _emit(output, terminator.raw)

    proxy_offsets = {}
    for target in taken_proxies:
        proxy_offsets.setdefault(target, len(output))
        transition_jumps.append(_transition(
            output, state_index, transition_specs[target]))

    dispatcher_start = len(output)
    dispatcher_cases = []
    starts = list(block_starts)
    random.shuffle(starts)
    for index, start in enumerate(starts):
        case_start = len(output)
        _emit(output, encode_oparg(LOAD_FAST, state_index))
        _emit(output, encode_oparg(LOAD_CONST, key_constants[start]))
        _emit(output, chr((BINARY_XOR, BINARY_ADD, BINARY_SUBTRACT)[
            state_ops[start]]))
        _emit(output, encode_oparg(LOAD_CONST, expected_constants[start]))
        _emit(output, encode_oparg(COMPARE_OP, 2))
        condition = _emit_jump(output, POP_JUMP_IF_FALSE)
        target_jump = _emit_jump(output, JUMP_ABSOLUTE)
        dispatcher_cases.append((case_start, condition, target_jump, start))
    failure_offset = len(output)
    _emit(output, encode_oparg(LOAD_CONST, failure_const))
    _emit(output, encode_oparg(RAISE_VARARGS, 1))

    for jump in transition_jumps:
        _patch_arg(output, jump, dispatcher_start)
    for index, item in enumerate(dispatcher_cases):
        case_start, condition, target_jump, start = item
        _patch_arg(output, target_jump, block_offsets[start])
        _patch_arg(output, condition, (
            dispatcher_cases[index + 1][0]
            if index + 1 < len(dispatcher_cases)
            else failure_offset))
    for position, target in conditional_jumps:
        _patch_arg(output, position, proxy_offsets[target])

    transformed = ''.join(output)
    if len(transformed) > 65535:
        return code_bytes, original_consts, original_varnames, 0
    try:
        verified = build_control_flow_graph(transformed)
    except (KeyError, TypeError, ValueError):
        return code_bytes, original_consts, original_varnames, 0
    if not verified.stack_safe or verified.has_exception_flow:
        return code_bytes, original_consts, original_varnames, 0
    return transformed, consts, varnames, len(graph.blocks)
