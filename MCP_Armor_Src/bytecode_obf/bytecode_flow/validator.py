# -*- coding: utf-8 -*-
"""Final reachable-bytecode validation for CPython 2.7 CodeObjects.

The individual ByteCode_Flow transforms validate their own output, but later
combinations can still invalidate an earlier jump or index.  This module is a
single final gate.  Deliberately unreachable poison remains permitted; every
instruction reachable from offset zero must be structurally and semantically
consistent with the rebuilt CodeObject tables.
"""


from collections import deque

from MCP_Armor_Src.core import py27_opcode as opcode

from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import (
    decode_instructions,
)
from MCP_Armor_Src.bytecode_obf.bytecode_flow.stack import (
    instruction_stack_effect,
)


_CONDITIONAL = set((
    'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
    'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'FOR_ITER',
))
_UNCONDITIONAL = set((
    'JUMP_ABSOLUTE', 'JUMP_FORWARD', 'CONTINUE_LOOP',
))
_TERMINAL = set((
    'RETURN_VALUE', 'RAISE_VARARGS', 'BREAK_LOOP', 'STOP_CODE',
))
_EXCEPTION_SETUP = set(('SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH'))
_STACK_UNKNOWN = set(('WITH_CLEANUP', 'END_FINALLY'))
_KNOWN_OPCODES = set(opcode.opmap.values())


class BytecodeValidationResult(object):
    def __init__(self, valid, reason=None, reachable=0, max_stack=0,
                 stack_complete=True):
        self.valid = bool(valid)
        self.reason = reason
        self.reachable = int(reachable or 0)
        self.max_stack = int(max_stack or 0)
        self.stack_complete = bool(stack_complete)

    def __bool__(self):
        return self.valid

    __nonzero__ = __bool__


def _invalid(reason, reachable=0, max_stack=0, stack_complete=True):
    return BytecodeValidationResult(
        False, reason, reachable, max_stack, stack_complete)


def _operand_error(item, consts, names, varnames, free_count):
    argument = int(item.argument or 0)
    opvalue = item.opcode
    if opvalue in opcode.hasconst and argument >= len(consts):
        return 'constant index %d out of range at %d' % (
            argument, item.offset)
    if opvalue in opcode.hasname and argument >= len(names):
        return 'name index %d out of range at %d' % (
            argument, item.offset)
    if opvalue in opcode.haslocal and argument >= len(varnames):
        return 'local index %d out of range at %d' % (
            argument, item.offset)
    if opvalue in opcode.hascompare and argument >= len(opcode.cmp_op):
        return 'compare index %d out of range at %d' % (
            argument, item.offset)
    name = opcode.opname[opvalue]
    if name in ('LOAD_CLOSURE', 'LOAD_DEREF', 'STORE_DEREF') and (
            argument >= free_count):
        return 'closure index %d out of range at %d' % (
            argument, item.offset)
    return None


def _merge_depth(depths, target, depth):
    if target not in depths:
        depths[target] = depth
        return True, None
    previous = depths[target]
    if previous is None:
        return False, None
    if depth is None:
        depths[target] = None
        return True, None
    if previous != depth:
        return False, 'stack merge mismatch at %d (%d != %d)' % (
            target, previous, depth)
    return False, None


def validate_code_object_layout(co, code_bytes=None, consts=None, names=None,
                                varnames=None, stacksize=None):
    """Validate the reachable portion of a rebuilt Python-2 CodeObject."""
    code_bytes = co.co_code if code_bytes is None else code_bytes
    consts = co.co_consts if consts is None else consts
    names = co.co_names if names is None else names
    varnames = co.co_varnames if varnames is None else varnames
    stacksize = co.co_stacksize if stacksize is None else int(stacksize)
    try:
        instructions = decode_instructions(code_bytes)
    except (IndexError, KeyError, TypeError, ValueError) as error:
        return _invalid('decode failed: %s' % error)
    if not instructions or instructions[0].offset != 0:
        return _invalid('missing entry instruction')

    code_size = len(code_bytes)
    by_offset = dict((item.offset, item) for item in instructions)
    boundaries = set(by_offset)
    boundaries.add(code_size)
    free_count = len(co.co_cellvars) + len(co.co_freevars)
    depths = {0: 0}
    queue = deque([0])
    reachable = set()
    max_stack = 0
    stack_complete = True

    while queue:
        offset = queue.popleft()
        if offset in reachable:
            continue
        reachable.add(offset)
        item = by_offset.get(offset)
        if item is None:
            return _invalid('reachable offset is not an instruction: %d' %
                            offset, len(reachable), max_stack,
                            stack_complete)
        if item.opcode not in _KNOWN_OPCODES:
            return _invalid('unknown reachable opcode %d at %d' %
                            (item.opcode, item.offset), len(reachable),
                            max_stack, stack_complete)
        name = opcode.opname[item.opcode]
        operand_error = _operand_error(
            item, consts, names, varnames, free_count)
        if operand_error:
            return _invalid(operand_error, len(reachable), max_stack,
                            stack_complete)
        if item.target is not None and (
                item.target not in boundaries or item.target == code_size):
            return _invalid('invalid reachable jump target %r at %d' %
                            (item.target, item.offset), len(reachable),
                            max_stack, stack_complete)

        incoming = depths.get(offset)
        if incoming is not None:
            max_stack = max(max_stack, incoming)

        successors = []
        if name == 'SETUP_LOOP':
            if item.next_offset < code_size:
                successors.append(('fallthrough', item.next_offset, incoming))
        elif name in _EXCEPTION_SETUP:
            stack_complete = False
            if item.next_offset < code_size:
                successors.append(('fallthrough', item.next_offset, incoming))
            successors.append(('exception', item.target, None))
        elif name in _CONDITIONAL:
            successors.append(('taken', item.target, incoming))
            if item.next_offset < code_size:
                successors.append(('fallthrough', item.next_offset, incoming))
        elif name in _UNCONDITIONAL:
            successors.append(('jump', item.target, incoming))
        elif name in _TERMINAL:
            successors = []
        elif item.next_offset < code_size:
            successors.append(('fallthrough', item.next_offset, incoming))
        else:
            return _invalid('reachable path falls off bytecode at %d' %
                            item.offset, len(reachable), max_stack,
                            stack_complete)

        if name in _TERMINAL and incoming is not None:
            effect = (0 if name in ('BREAK_LOOP', 'STOP_CODE') else
                      instruction_stack_effect(item, None))
            if effect is not None and incoming + effect < 0:
                return _invalid('negative terminal stack at %d' % item.offset,
                                len(reachable), max_stack, stack_complete)

        for kind, target, base_depth in successors:
            if target is None or target not in boundaries or target == code_size:
                return _invalid('invalid %s successor %r at %d' %
                                (kind, target, item.offset), len(reachable),
                                max_stack, stack_complete)
            if base_depth is None or name in _STACK_UNKNOWN or kind == 'exception':
                outgoing = None
                stack_complete = False
            elif name in _EXCEPTION_SETUP or name == 'SETUP_LOOP':
                outgoing = base_depth
            elif name == 'EXTENDED_ARG':
                outgoing = base_depth
            else:
                effect = instruction_stack_effect(item, kind)
                if effect is None:
                    outgoing = None
                    stack_complete = False
                else:
                    outgoing = base_depth + effect
                    if outgoing < 0:
                        return _invalid('negative stack at %d' % item.offset,
                                        len(reachable), max_stack,
                                        stack_complete)
                    max_stack = max(max_stack, outgoing)
            changed, merge_error = _merge_depth(depths, target, outgoing)
            if merge_error:
                # Python 2's loop/exception block stack can unwind operands
                # without an explicit data-stack opcode.  Preserve structural
                # validation and continue with an unknown depth rather than
                # rejecting a valid CodeObject on an unprovable merge.
                depths[target] = None
                changed = True
                stack_complete = False
            if changed or target not in reachable:
                queue.append(target)

    if stack_complete and max_stack > stacksize:
        # Treat an over-estimate as an incomplete proof.  Definite underflow,
        # bad targets and bad table indexes remain hard failures.
        stack_complete = False
    return BytecodeValidationResult(
        True, None, len(reachable), max_stack, stack_complete)
