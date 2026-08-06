# -*- coding: utf-8 -*-
"""Skid-inspired condition-edge proxy transformation."""
from __future__ import absolute_import

import opcode
import random

from MCP_Armor_Src.bytecode_obf.cfg.builder import build_control_flow_graph


HAVE_ARGUMENT = opcode.HAVE_ARGUMENT
EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')
LOAD_CONST = opcode.opmap['LOAD_CONST']
LOAD_FAST = opcode.opmap['LOAD_FAST']
STORE_FAST = opcode.opmap['STORE_FAST']
BINARY_XOR = opcode.opmap['BINARY_XOR']
COMPARE_OP = opcode.opmap['COMPARE_OP']
POP_JUMP_IF_FALSE = opcode.opmap['POP_JUMP_IF_FALSE']
POP_JUMP_IF_TRUE = opcode.opmap['POP_JUMP_IF_TRUE']
JUMP_ABSOLUTE = opcode.opmap['JUMP_ABSOLUTE']
RAISE_VARARGS = opcode.opmap['RAISE_VARARGS']


def _arg(value):
    return chr(value & 255) + chr((value >> 8) & 255)


def _oparg(opv, value):
    return chr(opv) + _arg(value)


def _map_original_target(target, prefix_size):
    return target + prefix_size


def apply_conditional_edge_proxies(co, code_bytes, consts, varnames,
                                   ratio=35, max_edges=6):
    """Return transformed code metadata and the number of split edges.

    Only POP_JUMP edges proven to consume the sole operand-stack value are
    eligible. The original taken edge is redirected through an appended proxy
    that validates an edge-specific hash of a hidden flow-state local.
    """
    ratio = max(0, min(100, int(ratio or 0)))
    max_edges = max(0, min(64, int(max_edges or 0)))
    original_consts = list(consts)
    original_varnames = list(varnames)
    if ratio <= 0 or max_edges <= 0 or not code_bytes:
        return code_bytes, consts, varnames, 0
    # Keep phase one deliberately narrow: ordinary optimized functions only.
    # Generators, closures and module code have extra frame semantics.
    if not (co.co_flags & 0x0001) or not (co.co_flags & 0x0002):
        return code_bytes, consts, varnames, 0
    if co.co_flags & 0x0020 or co.co_freevars or co.co_cellvars:
        return code_bytes, consts, varnames, 0
    if len(code_bytes) > 60000:
        return code_bytes, consts, varnames, 0
    if EXTENDED_ARG is not None and chr(EXTENDED_ARG) in code_bytes:
        return code_bytes, consts, varnames, 0

    try:
        graph = build_control_flow_graph(code_bytes)
    except (KeyError, TypeError, ValueError):
        return code_bytes, consts, varnames, 0
    if not graph.stack_safe or graph.has_exception_flow:
        return code_bytes, consts, varnames, 0

    candidates = []
    for item in graph.conditional_instructions():
        incoming = graph.stack_depths.get(item.offset)
        target_depth = graph.stack_depths.get(item.target)
        fall_depth = graph.stack_depths.get(item.next_offset)
        if incoming != 1 or target_depth != 0 or fall_depth != 0:
            continue
        if random.randint(1, 100) <= ratio:
            candidates.append(item)
    if not candidates:
        return code_bytes, consts, varnames, 0
    if len(candidates) > max_edges:
        candidates = random.sample(candidates, max_edges)
    candidates = sorted(candidates, key=lambda item: item.offset)

    consts = list(consts)
    varnames = list(varnames)
    if len(consts) + (len(candidates) * 5) + 3 > 65535 or len(varnames) >= 65535:
        return code_bytes, consts, varnames, 0

    state_name = '_bytecode_%08x' % random.randint(0, 0xffffffff)
    while state_name in varnames:
        state_name = '_bytecode_%08x' % random.randint(0, 0xffffffff)
    state_index = len(varnames)
    varnames.append(state_name)

    seed_left = random.randint(-2147483647, 2147483647)
    seed_right = random.randint(-2147483647, 2147483647)
    state_value = seed_left ^ seed_right
    left_index = len(consts)
    consts.append(seed_left)
    right_index = len(consts)
    consts.append(seed_right)
    error_index = len(consts)
    consts.append('invalid flow state')

    prefix = (_oparg(LOAD_CONST, left_index) +
              _oparg(LOAD_CONST, right_index) +
              chr(BINARY_XOR) +
              _oparg(STORE_FAST, state_index))
    prefix_size = len(prefix)
    # Each proxy validates the entry state, mutates it, validates the new
    # state, then restores it before entering the original target block.
    proxy_size = 55
    original_end = prefix_size + len(code_bytes)
    proxy_offsets = dict((item.offset, original_end + (index * proxy_size))
                         for index, item in enumerate(candidates))
    failure_offset = original_end + (len(candidates) * proxy_size)
    final_size = failure_offset + 6
    if final_size > 65535:
        return code_bytes, consts, varnames[:-1], 0

    key_rows = {}
    for item in candidates:
        first_key = random.randint(-2147483647, 2147483647)
        first_expected = state_value ^ first_key
        delta = random.randint(1, 2147483647)
        transitioned = state_value ^ delta
        second_key = random.randint(-2147483647, 2147483647)
        second_expected = transitioned ^ second_key
        indexes = []
        for value in (first_key, first_expected, delta,
                      second_key, second_expected):
            indexes.append(len(consts))
            consts.append(value)
        key_rows[item.offset] = tuple(indexes)

    selected = set(proxy_offsets)
    output = [prefix]
    for item in graph.instructions:
        opv = item.opcode
        if item.size != 3 or opv == EXTENDED_ARG:
            output.append(item.raw)
            continue
        argument = item.argument
        if item.offset in selected and opv in (POP_JUMP_IF_FALSE, POP_JUMP_IF_TRUE):
            argument = proxy_offsets[item.offset]
        elif item.target is not None:
            mapped = _map_original_target(item.target, prefix_size)
            if opv in opcode.hasjrel:
                new_offset = _map_original_target(item.offset, prefix_size)
                argument = mapped - (new_offset + item.size)
                if argument < 0:
                    return code_bytes, original_consts, original_varnames, 0
            elif opv in opcode.hasjabs:
                argument = mapped
        if argument < 0 or argument > 65535:
            return code_bytes, original_consts, original_varnames, 0
        output.append(_oparg(opv, argument))

    for item in candidates:
        first_key_index, first_expected_index, delta_index, \
            second_key_index, second_expected_index = key_rows[item.offset]
        target = _map_original_target(item.target, prefix_size)
        output.append(_oparg(LOAD_FAST, state_index))
        output.append(_oparg(LOAD_CONST, first_key_index))
        output.append(chr(BINARY_XOR))
        output.append(_oparg(LOAD_CONST, first_expected_index))
        output.append(_oparg(COMPARE_OP, 2))
        output.append(_oparg(POP_JUMP_IF_FALSE, failure_offset))
        output.append(_oparg(LOAD_FAST, state_index))
        output.append(_oparg(LOAD_CONST, delta_index))
        output.append(chr(BINARY_XOR))
        output.append(_oparg(STORE_FAST, state_index))
        output.append(_oparg(LOAD_FAST, state_index))
        output.append(_oparg(LOAD_CONST, second_key_index))
        output.append(chr(BINARY_XOR))
        output.append(_oparg(LOAD_CONST, second_expected_index))
        output.append(_oparg(COMPARE_OP, 2))
        output.append(_oparg(POP_JUMP_IF_FALSE, failure_offset))
        output.append(_oparg(LOAD_FAST, state_index))
        output.append(_oparg(LOAD_CONST, delta_index))
        output.append(chr(BINARY_XOR))
        output.append(_oparg(STORE_FAST, state_index))
        output.append(_oparg(JUMP_ABSOLUTE, target))
    output.append(_oparg(LOAD_CONST, error_index))
    output.append(_oparg(RAISE_VARARGS, 1))
    transformed = ''.join(output)
    try:
        verified = build_control_flow_graph(transformed)
    except (KeyError, TypeError, ValueError):
        return code_bytes, original_consts, original_varnames, 0
    if not verified.stack_safe:
        return code_bytes, original_consts, original_varnames, 0
    return transformed, consts, varnames, len(candidates)
