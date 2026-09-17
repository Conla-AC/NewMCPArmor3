# -*- coding: utf-8 -*-
"""Compact structural metrics for ByteCode_Flow anti-pattern regression."""

from MCP_Armor_Src.core import py27_opcode as opcode
from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import (
    build_control_flow_graph, decode_instructions,
)


def audit_bytecode_flow(code_bytes, ngram_width=4):
    instructions = decode_instructions(code_bytes)
    graph = build_control_flow_graph(code_bytes)
    names = [opcode.opname[item.opcode] for item in instructions]
    width = max(2, min(8, int(ngram_width or 4)))
    counts = {}
    for index in range(max(0, len(names) - width + 1)):
        key = tuple(names[index:index + width])
        counts[key] = counts.get(key, 0) + 1
    arithmetic = set(name for name in names if name.startswith('BINARY_') or
                     name.startswith('INPLACE_'))
    fast_slots = set(
        int(item.argument) for item in instructions
        if opcode.opname[item.opcode] in (
            'LOAD_FAST', 'STORE_FAST', 'DELETE_FAST') and
        item.argument is not None)
    conditional = sum(1 for name in names if name in (
        'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
        'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'FOR_ITER'))
    jumps = sum(1 for item in instructions
                if item.opcode in opcode.hasjabs or item.opcode in opcode.hasjrel)
    const_compare_sites = 0
    for index, name in enumerate(names):
        if name != 'COMPARE_OP':
            continue
        window = names[max(0, index - 4):index]
        if 'LOAD_CONST' in window:
            const_compare_sites += 1
    return {
        'code_size': len(code_bytes),
        'instructions': len(instructions),
        'blocks': len(graph.blocks),
        'edges': len(graph.edges),
        'conditional_sites': conditional,
        'jump_sites': jumps,
        'arithmetic_diversity': len(arithmetic),
        'fast_local_slots': len(fast_slots),
        'const_compare_sites': const_compare_sites,
        'max_ngram_repeat': max(list(counts.values()) or [0]),
        'stack_safe': bool(graph.stack_safe),
        'frame_candidate': bool(graph.reachable_edges_stack_compatible()),
    }
