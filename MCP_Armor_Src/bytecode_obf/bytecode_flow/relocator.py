# -*- coding: utf-8 -*-
"""Instruction insertion and jump relocation for CPython 2.7 bytecode."""


from MCP_Armor_Src.core import py27_opcode as opcode


EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')


def encode_argument(value):
    if value < 0 or value > 65535:
        raise ValueError('bytecode argument out of range: %d' % value)
    return chr(value & 255) + chr((value >> 8) & 255)


def encode_oparg(opcode_value, value):
    return chr(opcode_value) + encode_argument(value)


class RelocationLayout(object):
    def __init__(self, graph, prefix_size=0, before_sizes=None,
                 after_sizes=None):
        self.graph = graph
        self.prefix_size = int(prefix_size or 0)
        self.before_sizes = dict(before_sizes or {})
        self.after_sizes = dict(after_sizes or {})
        self.entry_offsets = {}
        self.instruction_offsets = {}
        cursor = self.prefix_size
        for item in graph.instructions:
            self.entry_offsets[item.offset] = cursor
            cursor += self.before_sizes.get(item.offset, 0)
            self.instruction_offsets[item.offset] = cursor
            cursor += item.size
            cursor += self.after_sizes.get(item.offset, 0)
        self.main_end = cursor

    def mapped_target(self, original_target):
        if original_target == self.graph.code_size:
            return self.main_end
        if original_target not in self.entry_offsets:
            raise ValueError('unknown original target: %d' % original_target)
        return self.entry_offsets[original_target]


def rewrite_instruction(item, layout, jump_override=None):
    if item.size != 3:
        return item.raw
    if item.opcode == EXTENDED_ARG:
        raise ValueError('EXTENDED_ARG relocation is not supported')
    argument = item.argument
    target = jump_override
    if target is None and item.target is not None:
        target = layout.mapped_target(item.target)
    if target is not None:
        if item.opcode in opcode.hasjrel:
            current = layout.instruction_offsets[item.offset]
            argument = target - (current + item.size)
        elif item.opcode in opcode.hasjabs:
            argument = target
    return encode_oparg(item.opcode, argument)


def relocate_stream(graph, prefix='', before=None, after=None,
                    jump_overrides=None, suffix=''):
    before = dict(before or {})
    after = dict(after or {})
    layout = RelocationLayout(
        graph, len(prefix),
        dict((offset, len(value)) for offset, value in list(before.items())),
        dict((offset, len(value)) for offset, value in list(after.items())))
    output = [prefix]
    jump_overrides = dict(jump_overrides or {})
    for item in graph.instructions:
        output.append(before.get(item.offset, ''))
        output.append(rewrite_instruction(
            item, layout, jump_overrides.get(item.offset)))
        output.append(after.get(item.offset, ''))
    output.append(suffix)
    return b''.join(output), layout
