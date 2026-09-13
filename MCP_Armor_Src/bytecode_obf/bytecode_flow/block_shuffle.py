# -*- coding: utf-8 -*-
"""Verified physical basic-block permutation for CPython 2.7 bytecode."""


from MCP_Armor_Src.core import py27_opcode as opcode
import random

from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import build_control_flow_graph
from MCP_Armor_Src.bytecode_obf.bytecode_flow.abstract_frame import frame_analysis_gate
from MCP_Armor_Src.bytecode_obf.bytecode_flow.relocator import encode_oparg


JUMP_ABSOLUTE = opcode.opmap['JUMP_ABSOLUTE']
EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')
# Loop opcodes are valid ByteCode_Flow edges for physical relocation.  The previous
# guard rejected any function containing BREAK_LOOP/CONTINUE_LOOP, which meant
# ordinary functions with a for/while tail were never shuffled at all.  The
# block-stack semantics stay attached to the emitted opcodes; only offsets and
# fall-through trampolines are rewritten below.
UNSUPPORTED_FLOW_NAMES = set()


def _random_topological_order(blocks, constraints):
    by_start = dict((block.start, block) for block in blocks)
    incoming = dict((block.start, set()) for block in blocks)
    outgoing = dict((block.start, set()) for block in blocks)
    for source, target in constraints:
        if source == target:
            continue
        incoming[target].add(source)
        outgoing[source].add(target)

    entry = by_start[0]
    if incoming[entry.start]:
        return None
    result = [entry]
    emitted = set([entry.start])
    for target in outgoing[entry.start]:
        incoming[target].discard(entry.start)

    while len(result) < len(blocks):
        ready = [by_start[start] for start in by_start
                 if start not in emitted and not incoming[start]]
        if not ready:
            return None
        block = random.choice(ready)
        result.append(block)
        emitted.add(block.start)
        for target in outgoing[block.start]:
            incoming[target].discard(block.start)
    return result


def _choose_order(graph):
    block_for_instruction = {}
    for block in graph.blocks:
        for item in block.instructions:
            block_for_instruction[item.offset] = block
    constraints = set()
    for item in graph.instructions:
        if item.target is None or item.target == graph.code_size:
            continue
        if item.opcode in opcode.hasjrel:
            constraints.add((block_for_instruction[item.offset].start,
                             graph.block_by_start[item.target].start))

    original = [block.start for block in graph.blocks]
    best = None
    best_distance = 0
    for _attempt in range(32):
        candidate = _random_topological_order(graph.blocks, constraints)
        if candidate is None:
            return None
        starts = [block.start for block in candidate]
        distance = sum(1 for index, start in enumerate(starts)
                       if start != original[index])
        if distance > best_distance:
            best = candidate
            best_distance = distance
        if distance >= max(2, len(graph.blocks) // 2):
            break
    return best if best_distance else None


def apply_basic_block_shuffle(co, code_bytes, ratio=35, max_blocks=192,
                              consts=None, varnames=None):
    """Return physically permuted bytecode and the number of moved blocks."""
    ratio = max(0, min(100, int(ratio or 0)))
    max_blocks = max(2, min(512, int(max_blocks or 0)))
    if ratio <= 0 or not code_bytes or len(code_bytes) > 60000:
        return code_bytes, 0
    if random.randint(1, 100) > ratio:
        return code_bytes, 0
    if not (co.co_flags & 0x0001) or not (co.co_flags & 0x0002):
        return code_bytes, 0
    if co.co_flags & 0x0020 or co.co_freevars or co.co_cellvars:
        return code_bytes, 0
    try:
        graph = build_control_flow_graph(code_bytes)
    except (KeyError, TypeError, ValueError):
        return code_bytes, 0
    if not graph.stack_safe or graph.has_exception_flow:
        return code_bytes, 0
    frame_ok, _frame_result = frame_analysis_gate(
        co, code_bytes, consts, varnames)
    if not frame_ok:
        return code_bytes, 0
    if not graph.reachable_edges_stack_compatible():
        return code_bytes, 0
    if len(graph.blocks) < 3 or len(graph.blocks) > max_blocks:
        return code_bytes, 0
    if any(item.opcode == EXTENDED_ARG for item in graph.instructions):
        return code_bytes, 0
    if any(opcode.opname[item.opcode] in UNSUPPORTED_FLOW_NAMES
           for item in graph.instructions):
        return code_bytes, 0
    # BREAK_LOOP is modeled as a terminal edge by the conservative stack
    # analyser, so the post-loop POP_BLOCK block can be unreachable in the
    # abstract graph even though CPython reaches it while unwinding the loop
    # block stack.  Unreachable blocks are still safe to relocate: all real
    # bytecode targets are remapped and the verifier checks reachable stack
    # paths after rendering.

    order = _choose_order(graph)
    if order is None:
        return code_bytes, 0
    fallthrough = {}
    for edge in graph.edges:
        if edge.kind == 'fallthrough':
            fallthrough[edge.source.start] = edge.target.start

    block_offsets = {}
    instruction_offsets = {}
    cursor = 0
    for block in order:
        block_offsets[block.start] = cursor
        for item in block.instructions:
            instruction_offsets[item.offset] = cursor
            cursor += item.size
        if block.start in fallthrough:
            cursor += 3
    final_size = cursor
    if final_size > 65535:
        return code_bytes, 0

    output = []
    try:
        for block in order:
            for item in block.instructions:
                if item.size != 3:
                    output.append(item.raw)
                    continue
                if item.opcode == EXTENDED_ARG:
                    raise ValueError('EXTENDED_ARG is unsupported')
                argument = item.argument
                if item.target is not None:
                    target = (final_size if item.target == graph.code_size
                              else block_offsets[item.target])
                    if item.opcode in opcode.hasjrel:
                        argument = target - (
                            instruction_offsets[item.offset] + item.size)
                    elif item.opcode in opcode.hasjabs:
                        argument = target
                output.append(encode_oparg(item.opcode, argument))
            if block.start in fallthrough:
                output.append(encode_oparg(
                    JUMP_ABSOLUTE, block_offsets[fallthrough[block.start]]))
        transformed = b''.join(output)
        verified = build_control_flow_graph(transformed)
    except (KeyError, TypeError, ValueError):
        return code_bytes, 0
    if not verified.stack_safe or len(transformed) != final_size:
        return code_bytes, 0
    frame_ok, _frame_result = frame_analysis_gate(
        co, transformed, consts, varnames)
    if not frame_ok:
        return code_bytes, 0
    original = [block.start for block in graph.blocks]
    changed = sum(1 for index, block in enumerate(order)
                  if block.start != original[index])
    return transformed, changed\n