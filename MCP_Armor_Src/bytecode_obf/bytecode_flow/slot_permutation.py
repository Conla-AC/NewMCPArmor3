# -*- coding: utf-8 -*-
"""Use-def-aware permutation of CPython 2.7 fast-local slots.

The public argument slots remain fixed. Non-argument slots are shuffled as a
transaction and every LOAD/STORE/DELETE_FAST operand is rewritten together
with ``co_varnames``. This changes actual data-flow indexes rather than only
their display names.
"""

import random

from MCP_Armor_Src.core import py27_opcode as opcode
from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import decode_instructions
from MCP_Armor_Src.bytecode_obf.bytecode_flow.relocator import encode_oparg


FAST_NAMES = set(('LOAD_FAST', 'STORE_FAST', 'DELETE_FAST'))
EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')
CO_GENERATOR = 0x20
CO_VARARGS = 0x04
CO_VARKEYWORDS = 0x08


def _arg_slots(co, varnames):
    count = int(getattr(co, 'co_argcount', 0) or 0)
    flags = int(getattr(co, 'co_flags', 0) or 0)
    if flags & CO_VARARGS:
        count += 1
    if flags & CO_VARKEYWORDS:
        count += 1
    return min(len(varnames), count)


def permute_local_slots(co, code_bytes, varnames, limit=8, seed=0):
    """Return ``(code_bytes, varnames, changed_slots)``.

    Unsupported layouts return the original tuple. The permutation is
    restricted to slots observed by fast-local instructions and never touches
    closure, generator, introspection, or extended-argument code.
    """
    original_varnames = tuple(varnames)
    if (not code_bytes or not original_varnames or
            int(getattr(co, 'co_flags', 0) or 0) & CO_GENERATOR or
            getattr(co, 'co_freevars', ()) or
            getattr(co, 'co_cellvars', ())):
        return code_bytes, original_varnames, 0
    introspection = set(('locals', 'vars', 'eval', 'exec', 'inspect',
                         'currentframe', 'getouterframes', '_getframe',
                         'f_locals'))
    if introspection.intersection(set(getattr(co, 'co_names', ()) or ())):
        return code_bytes, original_varnames, 0
    try:
        instructions = decode_instructions(code_bytes)
    except (IndexError, KeyError, TypeError, ValueError):
        return code_bytes, original_varnames, 0
    if any(item.opcode == EXTENDED_ARG for item in instructions):
        return code_bytes, original_varnames, 0
    arg_slots = _arg_slots(co, original_varnames)
    used = set()
    for item in instructions:
        if opcode.opname[item.opcode] in FAST_NAMES:
            if item.argument is None or item.argument >= len(original_varnames):
                return code_bytes, original_varnames, 0
            if item.argument >= arg_slots:
                used.add(item.argument)
    candidates = sorted(used)
    budget = max(0, min(64, int(limit or 0)))
    if len(candidates) < 2 or budget < 2:
        return code_bytes, original_varnames, 0
    if len(candidates) > budget:
        rng = random.Random(int(seed or 0) ^ len(code_bytes))
        candidates = sorted(rng.sample(candidates, budget))
    rng = random.Random(int(seed or 0) ^ (len(code_bytes) * 1009))
    shuffled = list(candidates)
    for _attempt in range(8):
        rng.shuffle(shuffled)
        if any(old != new for old, new in zip(candidates, shuffled)):
            break
    mapping = dict(zip(candidates, shuffled))
    if all(mapping[index] == index for index in candidates):
        return code_bytes, original_varnames, 0
    output = []
    try:
        for item in instructions:
            name = opcode.opname[item.opcode]
            if name in FAST_NAMES:
                output.append(encode_oparg(
                    item.opcode, mapping.get(item.argument, item.argument)))
            else:
                output.append(item.raw)
    except (TypeError, ValueError):
        return code_bytes, original_varnames, 0
    reordered = list(original_varnames)
    for old, new in mapping.items():
        reordered[new] = original_varnames[old]
    return b''.join(output), tuple(reordered), len(mapping)
