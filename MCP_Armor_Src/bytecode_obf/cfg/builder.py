# -*- coding: utf-8 -*-
"""Build and validate a basic-block graph from CPython 2.7 bytecode."""
from __future__ import absolute_import

import opcode

from MCP_Armor_Src.bytecode_obf.cfg.model import BasicBlock, ControlFlowGraph, Edge, Instruction
from MCP_Armor_Src.bytecode_obf.cfg.stack import instruction_stack_effect


HAVE_ARGUMENT = opcode.HAVE_ARGUMENT
CONDITIONAL_NAMES = set(('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
                         'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP',
                         'FOR_ITER'))
UNCONDITIONAL_NAMES = set(('JUMP_ABSOLUTE', 'JUMP_FORWARD', 'CONTINUE_LOOP'))
TERMINAL_NAMES = set(('RETURN_VALUE', 'RAISE_VARARGS', 'BREAK_LOOP', 'STOP_CODE'))
EXCEPTION_NAMES = set(('SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH',
                       'WITH_CLEANUP', 'END_FINALLY'))


def _read_arg(code_bytes, offset):
    return ord(code_bytes[offset + 1]) | (ord(code_bytes[offset + 2]) << 8)


def decode_instructions(code_bytes):
    instructions = []
    offset = 0
    size = len(code_bytes)
    while offset < size:
        opv = ord(code_bytes[offset])
        width = 3 if opv >= HAVE_ARGUMENT else 1
        if offset + width > size:
            raise ValueError('truncated bytecode instruction at %d' % offset)
        argument = _read_arg(code_bytes, offset) if width == 3 else None
        target = None
        if width == 3 and opv in opcode.hasjrel:
            target = offset + width + argument
        elif width == 3 and opv in opcode.hasjabs:
            target = argument
        instructions.append(Instruction(
            offset, opv, argument, width,
            code_bytes[offset:offset + width], target))
        offset += width
    return instructions


def _successor_specs(item, code_size):
    name = opcode.opname[item.opcode]
    next_offset = item.next_offset
    if name == 'SETUP_LOOP':
        return [('fallthrough', next_offset)] if next_offset < code_size else []
    if name in CONDITIONAL_NAMES:
        result = [('taken', item.target)]
        if next_offset < code_size:
            result.append(('fallthrough', next_offset))
        return result
    if name in UNCONDITIONAL_NAMES:
        return [('jump', item.target)]
    if name in TERMINAL_NAMES:
        return []
    if name.startswith('SETUP_'):
        result = [('exception', item.target)]
        if next_offset < code_size:
            result.append(('fallthrough', next_offset))
        return result
    if next_offset < code_size:
        return [('fallthrough', next_offset)]
    return []


def _analyze_stack(instructions, code_size):
    by_offset = dict((item.offset, item) for item in instructions)
    depths = {0: 0}
    queue = [0]
    while queue:
        offset = queue.pop(0)
        item = by_offset[offset]
        incoming = depths[offset]
        for kind, target in _successor_specs(item, code_size):
            if kind == 'exception':
                return depths, False, 'exception stack edge'
            effect = instruction_stack_effect(item, kind)
            if effect is None:
                return depths, False, 'unknown stack effect for %s' % opcode.opname[item.opcode]
            outgoing = incoming + effect
            if outgoing < 0:
                return depths, False, 'negative stack at %d' % offset
            if target is None or target == code_size:
                continue
            previous = depths.get(target)
            if previous is None:
                depths[target] = outgoing
                queue.append(target)
            elif previous != outgoing:
                return depths, False, 'stack merge mismatch at %d' % target
    return depths, True, None


def build_control_flow_graph(code_bytes, extra_leaders=None):
    instructions = decode_instructions(code_bytes)
    if not instructions:
        raise ValueError('empty bytecode')
    code_size = len(code_bytes)
    boundaries = set(item.offset for item in instructions)
    boundaries.add(code_size)
    leaders = set([0])
    for leader in extra_leaders or ():
        if leader not in boundaries or leader == code_size:
            raise ValueError('invalid extra block leader %d' % leader)
        leaders.add(leader)
    for item in instructions:
        name = opcode.opname[item.opcode]
        if item.target is not None:
            if item.target not in boundaries:
                raise ValueError('invalid jump target %d' % item.target)
            if item.target < code_size:
                leaders.add(item.target)
        if (name in CONDITIONAL_NAMES or name in UNCONDITIONAL_NAMES or
                name in TERMINAL_NAMES or name.startswith('SETUP_')):
            if item.next_offset < code_size:
                leaders.add(item.next_offset)

    ordered = sorted(leaders)
    blocks = []
    instruction_index = dict((item.offset, index)
                             for index, item in enumerate(instructions))
    for block_id, start in enumerate(ordered):
        end = ordered[block_id + 1] if block_id + 1 < len(ordered) else code_size
        start_index = instruction_index[start]
        body = []
        index = start_index
        while index < len(instructions) and instructions[index].offset < end:
            body.append(instructions[index])
            index += 1
        blocks.append(BasicBlock(block_id, start, body))

    block_by_start = dict((block.start, block) for block in blocks)
    edges = []
    for block in blocks:
        item = block.terminator
        for kind, target in _successor_specs(item, code_size):
            if target == code_size:
                continue
            target_block = block_by_start.get(target)
            if target_block is None:
                raise ValueError('edge target has no block: %d' % target)
            edge = Edge(block, target_block, kind)
            edges.append(edge)
            block.successors.append(edge)
            target_block.predecessors.append(edge)

    depths, stack_safe, unsafe_reason = _analyze_stack(instructions, code_size)
    graph = ControlFlowGraph(code_size, instructions, blocks, edges, depths,
                             stack_safe, unsafe_reason)
    graph.conditional_opcodes = set(
        opcode.opmap[name] for name in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE')
        if name in opcode.opmap)
    graph.has_exception_flow = any(opcode.opname[item.opcode] in EXCEPTION_NAMES
                                   for item in instructions)
    graph.validate()
    return graph
