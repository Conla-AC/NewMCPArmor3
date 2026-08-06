# -*- coding: utf-8 -*-
"""Instruction, basic-block and edge models."""
from __future__ import absolute_import


class Instruction(object):
    def __init__(self, offset, opcode_value, argument, size, raw, target=None):
        self.offset = offset
        self.opcode = opcode_value
        self.argument = argument
        self.size = size
        self.raw = raw
        self.target = target

    @property
    def next_offset(self):
        return self.offset + self.size


class Edge(object):
    def __init__(self, source, target, kind):
        self.source = source
        self.target = target
        self.kind = kind


class BasicBlock(object):
    def __init__(self, block_id, start, instructions):
        self.block_id = block_id
        self.start = start
        self.instructions = list(instructions)
        self.successors = []
        self.predecessors = []
        self.flags = set()

    @property
    def end(self):
        if not self.instructions:
            return self.start
        return self.instructions[-1].next_offset

    @property
    def terminator(self):
        return self.instructions[-1] if self.instructions else None


class ControlFlowGraph(object):
    def __init__(self, code_size, instructions, blocks, edges, stack_depths,
                 stack_safe=True, unsafe_reason=None):
        self.code_size = code_size
        self.instructions = list(instructions)
        self.blocks = list(blocks)
        self.edges = list(edges)
        self.stack_depths = dict(stack_depths)
        self.stack_safe = bool(stack_safe)
        self.unsafe_reason = unsafe_reason
        self.block_by_start = dict((block.start, block) for block in blocks)
        self.instruction_by_offset = dict((item.offset, item)
                                          for item in instructions)

    def conditional_instructions(self):
        return [block.terminator for block in self.blocks
                if block.terminator is not None and
                block.terminator.opcode in self.conditional_opcodes]

    def validate(self):
        boundaries = set(self.instruction_by_offset)
        boundaries.add(self.code_size)
        if not self.instructions or self.instructions[0].offset != 0:
            raise ValueError('CFG has no entry instruction')
        cursor = 0
        for item in self.instructions:
            if item.offset != cursor:
                raise ValueError('non-contiguous instruction at %d' % item.offset)
            cursor = item.next_offset
            if item.target is not None and item.target not in boundaries:
                raise ValueError('jump target is not an instruction boundary: %d' % item.target)
        if cursor != self.code_size:
            raise ValueError('instruction stream length mismatch')
        for edge in self.edges:
            if edge.source not in self.blocks or edge.target not in self.blocks:
                raise ValueError('edge references a foreign block')
        return True
