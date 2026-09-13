from MCP_Armor_Src.utils.encoding import byte_char, byte_value, random_ident
# -*- coding: utf-8 -*-
"""Per-basic-block flow predicates for verified CPython 2.7 ByteCode_Flow."""


from MCP_Armor_Src.core import py27_opcode as opcode
import random

from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import build_control_flow_graph
from MCP_Armor_Src.bytecode_obf.bytecode_flow.abstract_frame import frame_analysis_gate
from MCP_Armor_Src.bytecode_obf.bytecode_flow.relocator import (
    RelocationLayout,
    encode_oparg,
    relocate_stream,
)


LOAD_CONST = opcode.opmap['LOAD_CONST']
LOAD_FAST = opcode.opmap['LOAD_FAST']
STORE_FAST = opcode.opmap['STORE_FAST']
BINARY_XOR = opcode.opmap['BINARY_XOR']
COMPARE_OP = opcode.opmap['COMPARE_OP']
POP_JUMP_IF_FALSE = opcode.opmap['POP_JUMP_IF_FALSE']
JUMP_ABSOLUTE = opcode.opmap['JUMP_ABSOLUTE']
RAISE_VARARGS = opcode.opmap['RAISE_VARARGS']
EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')

CONDITIONAL_NAMES = set((
    'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
    'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'FOR_ITER'))
UNCONDITIONAL_NAMES = set(('JUMP_ABSOLUTE', 'JUMP_FORWARD'))
UNSUPPORTED_FLOW_NAMES = set(('BREAK_LOOP', 'CONTINUE_LOOP'))

CHECK_SIZE = 16
TRANSITION_SIZE = 10
EDGE_CHAIN_SIZE = (CHECK_SIZE * 2) + TRANSITION_SIZE
JUMP_SIZE = 3
PROXY_SIZE = EDGE_CHAIN_SIZE + JUMP_SIZE
FAILURE_SIZE = 6


def _random_int():
    return random.randint(-2147483647, 2147483647)


def _add_const(consts, value):
    index = len(consts)
    consts.append(value)
    return index


def _check_code(state_index, key_index, expected_index, failure_offset):
    return (encode_oparg(LOAD_FAST, state_index) +
            encode_oparg(LOAD_CONST, key_index) +
            byte_char(BINARY_XOR) +
            encode_oparg(LOAD_CONST, expected_index) +
            encode_oparg(COMPARE_OP, 2) +
            encode_oparg(POP_JUMP_IF_FALSE, failure_offset))


def _transition_code(state_index, delta_index):
    return (encode_oparg(LOAD_FAST, state_index) +
            encode_oparg(LOAD_CONST, delta_index) +
            byte_char(BINARY_XOR) +
            encode_oparg(STORE_FAST, state_index))


def apply_block_seed_flow(co, code_bytes, consts, varnames,
                          ratio=35, max_blocks=64):
    """Propagate a unique seed across every ordinary ByteCode_Flow edge."""
    ratio = max(0, min(100, int(ratio or 0)))
    max_blocks = max(2, min(256, int(max_blocks or 0)))
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

    try:
        graph = build_control_flow_graph(code_bytes)
    except (KeyError, TypeError, ValueError):
        return code_bytes, consts, varnames, 0
    if not graph.stack_safe or graph.has_exception_flow:
        return code_bytes, consts, varnames, 0
    frame_ok, _frame_result = frame_analysis_gate(
        co, code_bytes, consts, varnames)
    if not frame_ok:
        return code_bytes, consts, varnames, 0
    if not graph.reachable_edges_stack_compatible():
        return code_bytes, consts, varnames, 0
    if len(graph.blocks) < 2 or len(graph.blocks) > max_blocks:
        return code_bytes, consts, varnames, 0
    if any(item.opcode == EXTENDED_ARG for item in graph.instructions):
        return code_bytes, consts, varnames, 0
    if any(opcode.opname[item.opcode] in UNSUPPORTED_FLOW_NAMES
           for item in graph.instructions):
        return code_bytes, consts, varnames, 0
    if any(block.start not in graph.stack_depths for block in graph.blocks):
        return code_bytes, consts, varnames, 0

    consts = list(consts)
    varnames = list(varnames)
    estimated_consts = 2 + (len(graph.blocks) * 2) + len(graph.edges)
    if len(consts) + estimated_consts > 65535 or len(varnames) >= 65535:
        return code_bytes, original_consts, original_varnames, 0

    state_name = random_ident('bytecode')
    while state_name in varnames:
        state_name = random_ident('bytecode')
    state_index = len(varnames)
    varnames.append(state_name)

    used_seeds = set()
    seeds = {}
    validation = {}
    for block in graph.blocks:
        seed = _random_int()
        while seed in used_seeds:
            seed = _random_int()
        used_seeds.add(seed)
        seeds[block.start] = seed
        key = _random_int()
        validation[block.start] = (
            _add_const(consts, key),
            _add_const(consts, seed ^ key))

    entry_seed_index = _add_const(consts, seeds[0])
    error_index = _add_const(consts, 'invalid bytecode block state')
    prefix = (encode_oparg(LOAD_CONST, entry_seed_index) +
              encode_oparg(STORE_FAST, state_index))

    transition_indexes = {}
    for edge in graph.edges:
        key = (edge.source.start, edge.target.start, edge.kind)
        delta = seeds[edge.source.start] ^ seeds[edge.target.start]
        transition_indexes[key] = _add_const(consts, delta)

    before_sizes = dict((block.start, CHECK_SIZE) for block in graph.blocks)
    after_sizes = {}
    proxy_edges = []
    edge_by_kind = {}
    for edge in graph.edges:
        edge_by_kind[(edge.source.start, edge.kind)] = edge

    for block in graph.blocks:
        item = block.terminator
        name = opcode.opname[item.opcode]
        if name in CONDITIONAL_NAMES:
            taken = edge_by_kind.get((block.start, 'taken'))
            fallthrough = edge_by_kind.get((block.start, 'fallthrough'))
            if taken is None or fallthrough is None:
                return code_bytes, original_consts, original_varnames, 0
            proxy_edges.append((item, taken))
            after_sizes[item.offset] = PROXY_SIZE
        elif name in UNCONDITIONAL_NAMES:
            jump = edge_by_kind.get((block.start, 'jump'))
            if jump is None:
                return code_bytes, original_consts, original_varnames, 0
            proxy_edges.append((item, jump))
        elif block.successors:
            if len(block.successors) != 1 or block.successors[0].kind != 'fallthrough':
                return code_bytes, original_consts, original_varnames, 0
            after_sizes[item.offset] = EDGE_CHAIN_SIZE

    layout = RelocationLayout(
        graph, len(prefix), before_sizes, after_sizes)
    failure_depths = sorted(set(
        graph.stack_depths[block.start] for block in graph.blocks))
    proxy_start = layout.main_end
    failures_start = proxy_start + (len(proxy_edges) * PROXY_SIZE)
    failure_offsets = dict(
        (depth, failures_start + (index * FAILURE_SIZE))
        for index, depth in enumerate(failure_depths))
    final_size = failures_start + (len(failure_depths) * FAILURE_SIZE)
    if final_size > 65535:
        return code_bytes, original_consts, original_varnames, 0

    def block_check(block):
        key_index, expected_index = validation[block.start]
        depth = graph.stack_depths[block.start]
        return _check_code(
            state_index, key_index, expected_index,
            failure_offsets[depth])

    def edge_chain(edge):
        target = edge.target
        depth = graph.stack_depths[target.start]
        source_key, source_expected = validation[edge.source.start]
        target_key, target_expected = validation[target.start]
        delta_key = (edge.source.start, target.start, edge.kind)
        return (_check_code(state_index, source_key, source_expected,
                            failure_offsets[depth]) +
                _transition_code(state_index, transition_indexes[delta_key]) +
                _check_code(state_index, target_key, target_expected,
                            failure_offsets[depth]))

    before = dict((block.start, block_check(block)) for block in graph.blocks)
    after = {}
    jump_overrides = {}
    suffix = []
    for index, row in enumerate(proxy_edges):
        item, edge = row
        proxy_offset = proxy_start + (index * PROXY_SIZE)
        jump_overrides[item.offset] = proxy_offset
        suffix.append(edge_chain(edge))
        suffix.append(encode_oparg(
            JUMP_ABSOLUTE, layout.mapped_target(edge.target.start)))

    for block in graph.blocks:
        item = block.terminator
        name = opcode.opname[item.opcode]
        if name in CONDITIONAL_NAMES:
            edge = edge_by_kind[(block.start, 'fallthrough')]
            after[item.offset] = (edge_chain(edge) + encode_oparg(
                JUMP_ABSOLUTE, layout.mapped_target(edge.target.start)))
        elif name not in UNCONDITIONAL_NAMES and block.successors:
            after[item.offset] = edge_chain(block.successors[0])

    for _depth in failure_depths:
        suffix.append(encode_oparg(LOAD_CONST, error_index))
        suffix.append(encode_oparg(RAISE_VARARGS, 1))

    try:
        transformed, rendered_layout = relocate_stream(
            graph, prefix, before, after, jump_overrides, b''.join(suffix))
        if rendered_layout.main_end != layout.main_end:
            raise ValueError('relocation layout changed during rendering')
        verified = build_control_flow_graph(transformed)
    except (KeyError, TypeError, ValueError):
        return code_bytes, original_consts, original_varnames, 0
    if not verified.stack_safe or len(transformed) != final_size:
        return code_bytes, original_consts, original_varnames, 0
    frame_ok, _frame_result = frame_analysis_gate(
        co, transformed, consts, varnames)
    if not frame_ok:
        return code_bytes, original_consts, original_varnames, 0
    return transformed, consts, varnames, len(graph.edges)\n