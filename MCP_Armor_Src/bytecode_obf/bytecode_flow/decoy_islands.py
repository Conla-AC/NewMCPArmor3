from MCP_Armor_Src.utils.encoding import byte_char, byte_value
# -*- coding: utf-8 -*-
"""Verified legal decoy islands for CPython 2.7 bytecode."""


from MCP_Armor_Src.core import py27_opcode as opcode
import random
import zlib

from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import build_control_flow_graph
from MCP_Armor_Src.bytecode_obf.bytecode_flow.abstract_frame import frame_analysis_gate
from MCP_Armor_Src.bytecode_obf.bytecode_flow.relocator import encode_oparg


LOAD_CONST = opcode.opmap['LOAD_CONST']
LOAD_FAST = opcode.opmap['LOAD_FAST']
POP_TOP = opcode.opmap['POP_TOP']
COMPARE_OP = opcode.opmap['COMPARE_OP']
BINARY_XOR = opcode.opmap['BINARY_XOR']
BINARY_ADD = opcode.opmap['BINARY_ADD']
POP_JUMP_IF_FALSE = opcode.opmap['POP_JUMP_IF_FALSE']
POP_JUMP_IF_TRUE = opcode.opmap['POP_JUMP_IF_TRUE']
JUMP_FORWARD = opcode.opmap['JUMP_FORWARD']
NOP = opcode.opmap.get('NOP', 9)
UNARY_NOT = opcode.opmap['UNARY_NOT']
EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')

HOT_NAME_MARKERS = (
    'tick', 'update', 'timer', 'frame', 'render', 'callback',
    'listen', 'notify', 'destroy', 'post', 'dispatch')
UNSUPPORTED_NAMES = set((
    'BREAK_LOOP', 'CONTINUE_LOOP', 'YIELD_VALUE', 'FOR_ITER',
    'SETUP_LOOP', 'POP_BLOCK',
    'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH',
    'WITH_CLEANUP', 'END_FINALLY'))


def _stable_rng(co, seed):
    identity = '%s\x00%s\x00%d\x00%d' % (
        co.co_name or '', co.co_filename or '',
        int(getattr(co, 'co_firstlineno', 0)), int(seed or 0))
    checksum = zlib.crc32(identity.encode('utf-8')) & 0xffffffff
    checksum ^= zlib.crc32(co.co_code) & 0xffffffff
    return random.Random(checksum)


def _junk_payload(rng, width, true_const_index):
    """Return a varied stack-neutral mirror payload.

    The reference implementation mutates cloned JVM blocks.  CPython has no
    verifier/type lattice equivalent, so copying arbitrary user instructions
    would risk frame-stack corruption.  These two-value arithmetic/comparison
    sequences preserve the same visual shape while remaining legal and
    statically stack-balanced on Python 2.7.
    """
    rows = []
    for _index in range(width):
        choice = rng.randint(0, 6)
        if choice == 0:
            rows.append(byte_char(NOP))
        elif choice == 1:
            rows.append(encode_oparg(LOAD_CONST, true_const_index))
            rows.append(byte_char(POP_TOP))
        elif choice == 2:
            rows.append(encode_oparg(JUMP_FORWARD, 0))
        elif choice == 3:
            rows.append(encode_oparg(LOAD_CONST, true_const_index))
            rows.append(byte_char(UNARY_NOT))
            rows.append(byte_char(POP_TOP))
        elif choice == 4:
            rows.append(encode_oparg(LOAD_CONST, true_const_index))
            rows.append(encode_oparg(LOAD_CONST, true_const_index))
            rows.append(byte_char(BINARY_XOR))
            rows.append(byte_char(POP_TOP))
        elif choice == 5:
            rows.append(encode_oparg(LOAD_CONST, true_const_index))
            rows.append(encode_oparg(LOAD_CONST, true_const_index))
            rows.append(byte_char(BINARY_ADD))
            rows.append(byte_char(POP_TOP))
        else:
            rows.append(encode_oparg(LOAD_CONST, true_const_index))
            rows.append(encode_oparg(LOAD_CONST, true_const_index))
            rows.append(encode_oparg(COMPARE_OP, 2))
            rows.append(byte_char(POP_TOP))
    return b''.join(rows)


def _gate_prefix(rng, co, true_const_index, real_target):
    """Build varied always-taken predicates with a static fallthrough edge."""
    variants = [0, 1, 2, 4, 5]
    if co.co_argcount > 0:
        variants.append(3)
    variant = rng.choice(variants)
    if variant == 0:
        return (encode_oparg(LOAD_CONST, true_const_index) +
                encode_oparg(POP_JUMP_IF_TRUE, real_target))
    if variant == 1:
        return (encode_oparg(LOAD_CONST, true_const_index) +
                byte_char(UNARY_NOT) +
                encode_oparg(POP_JUMP_IF_FALSE, real_target))
    compare_is = 8
    try:
        compare_is = opcode.cmp_op.index('is')
    except (AttributeError, ValueError):
        pass
    if variant == 2:
        return (encode_oparg(LOAD_CONST, true_const_index) +
                encode_oparg(LOAD_CONST, true_const_index) +
                encode_oparg(COMPARE_OP, compare_is) +
                encode_oparg(POP_JUMP_IF_TRUE, real_target))
    if variant == 4:
        # (True XOR True) < True -> 0 < 1 -> true
        return (encode_oparg(LOAD_CONST, true_const_index) +
                encode_oparg(LOAD_CONST, true_const_index) +
                byte_char(BINARY_XOR) +
                encode_oparg(LOAD_CONST, true_const_index) +
                encode_oparg(COMPARE_OP, 0) +
                encode_oparg(POP_JUMP_IF_TRUE, real_target))
    if variant == 5:
        # (True + True) > True -> 2 > 1 -> true
        return (encode_oparg(LOAD_CONST, true_const_index) +
                encode_oparg(LOAD_CONST, true_const_index) +
                byte_char(BINARY_ADD) +
                encode_oparg(LOAD_CONST, true_const_index) +
                encode_oparg(COMPARE_OP, 4) +
                encode_oparg(POP_JUMP_IF_TRUE, real_target))
    return (encode_oparg(LOAD_FAST, 0) +
            encode_oparg(LOAD_FAST, 0) +
            encode_oparg(COMPARE_OP, compare_is) +
            encode_oparg(POP_JUMP_IF_TRUE, real_target))


def _relocate_original(item, mapped_offsets, insert_lengths, old_size,
                       new_size):
    raw = item.raw
    if item.size != 3 or item.opcode == EXTENDED_ARG:
        return raw
    if item.target is None:
        return raw
    target = item.target
    if target == old_size:
        mapped_target = new_size
    elif target in mapped_offsets:
        mapped_target = mapped_offsets[target] + insert_lengths.get(target, 0)
    else:
        raise ValueError('jump target is not an instruction boundary')
    if item.opcode in opcode.hasjrel:
        mapped_source_end = (mapped_offsets[item.offset] +
                             insert_lengths.get(item.offset, 0) + 3)
        argument = mapped_target - mapped_source_end
    else:
        argument = mapped_target
    if argument < 0 or argument > 65535:
        raise ValueError('relocated jump exceeds 16-bit operand')
    return encode_oparg(item.opcode, argument)


def apply_decoy_islands(co, code_bytes, true_const_index, ratio=20, limit=2,
                        width=4, growth_percent=15, seed=0, consts=None,
                        varnames=None):
    """Insert verified opaque-entry decoy islands into cold functions.

    The executed edge jumps directly to the original instruction. The false
    ByteCode_Flow edge enters legal stack-neutral junk, giving each island plausible
    in-degree without executing its payload at runtime.
    """
    ratio = max(0, min(100, int(ratio or 0)))
    limit = max(0, min(8, int(limit or 0)))
    width = max(2, min(8, int(width or 0)))
    growth_percent = max(1, min(100, int(growth_percent or 0)))
    if (ratio <= 0 or limit <= 0 or not code_bytes or
            len(code_bytes) < 48 or len(code_bytes) > 48000 or
            true_const_index < 0 or true_const_index > 65535):
        return code_bytes, 0
    if not (co.co_flags & 0x0001) or not (co.co_flags & 0x0002):
        return code_bytes, 0
    if co.co_flags & 0x0020 or co.co_freevars or co.co_cellvars:
        return code_bytes, 0
    function_name = (co.co_name or '').lower()
    if ((function_name.startswith('__') and function_name.endswith('__')) or
            any(marker in function_name for marker in HOT_NAME_MARKERS)):
        return code_bytes, 0

    rng = _stable_rng(co, seed)
    if rng.randint(1, 100) > ratio:
        return code_bytes, 0
    try:
        graph = build_control_flow_graph(code_bytes)
    except (IndexError, KeyError, TypeError, ValueError):
        return code_bytes, 0
    if not graph.stack_safe or graph.has_exception_flow:
        return code_bytes, 0
    analysis_consts = list(getattr(co, 'co_consts', ())) \
        if consts is None else list(consts)
    while len(analysis_consts) <= true_const_index:
        analysis_consts.append(None)
    analysis_consts[true_const_index] = True
    analysis_varnames = (getattr(co, 'co_varnames', ())
                         if varnames is None else varnames)
    frame_ok, _frame_result = frame_analysis_gate(
        co, code_bytes, analysis_consts, analysis_varnames)
    if not frame_ok:
        return code_bytes, 0
    if any(item.opcode == EXTENDED_ARG or
           opcode.opname[item.opcode] in UNSUPPORTED_NAMES
           for item in graph.instructions):
        return code_bytes, 0

    leaders = set(block.start for block in graph.blocks)
    candidates = []
    for item in graph.instructions:
        if item.offset == 0 or graph.stack_depths.get(item.offset) != 0:
            continue
        name = opcode.opname[item.opcode]
        if name.startswith('RETURN') or name.startswith('RAISE'):
            continue
        # An interior zero-stack site has a real fallthrough predecessor, so
        # its gate is executed while only the decoy edge remains untaken.
        candidates.append((1 if item.offset in leaders else 0, item.offset))
    if not candidates:
        return code_bytes, 0
    rng.shuffle(candidates)
    candidates.sort(key=lambda row: row[0])

    max_size = min(65535, len(code_bytes) +
                   ((len(code_bytes) * growth_percent) // 100))
    specs = {}
    added = 0
    for _priority, offset in candidates:
        if len(specs) >= limit:
            break
        local_width = rng.randint(2, width)
        payload = _junk_payload(rng, local_width, true_const_index)
        # Probe the actual randomized gate size instead of reserving a fixed
        # 18-byte worst case.  Small compiler-generated functions commonly
        # have only a 15--30% growth budget; the fixed reserve rejected every
        # legal island even when the emitted gate+payload would fit.
        marker = rng.getstate()
        prefix_probe = _gate_prefix(rng, co, true_const_index, 0)
        reserved = len(prefix_probe) + len(payload)
        if len(code_bytes) + added + reserved > max_size:
            continue
        specs[offset] = (payload, marker, len(prefix_probe))
        added += reserved
    if not specs:
        return code_bytes, 0

    # Prefix sizes vary, so settle the exact layout before encoding targets.
    prefix_variants = {}
    insert_lengths = {}
    for offset, row in list(specs.items()):
        payload, marker, prefix_size = row
        prefix_variants[offset] = (marker, prefix_size)
        insert_lengths[offset] = prefix_size + len(payload)
    total_added = sum(insert_lengths.values())
    if len(code_bytes) + total_added > max_size:
        return code_bytes, 0

    mapped_offsets = {}
    cursor = 0
    for item in graph.instructions:
        mapped_offsets[item.offset] = cursor
        cursor += insert_lengths.get(item.offset, 0) + item.size
    new_size = cursor
    if new_size > 65535:
        return code_bytes, 0

    output = []
    try:
        for item in graph.instructions:
            if item.offset in specs:
                state, expected_size = prefix_variants[item.offset]
                rng.setstate(state)
                real_target = (mapped_offsets[item.offset] +
                               insert_lengths[item.offset])
                prefix = _gate_prefix(
                    rng, co, true_const_index, real_target)
                if len(prefix) != expected_size:
                    raise ValueError('unstable decoy gate size')
                output.append(prefix)
                output.append(specs[item.offset][0])
            output.append(_relocate_original(
                item, mapped_offsets, insert_lengths,
                len(code_bytes), new_size))
        transformed = b''.join(output)
        verified = build_control_flow_graph(transformed)
        if (not verified.validate() or not verified.stack_safe or
                verified.has_exception_flow):
            return code_bytes, 0
        frame_ok, _frame_result = frame_analysis_gate(
            co, transformed, analysis_consts, analysis_varnames)
        if not frame_ok:
            return code_bytes, 0
    except (IndexError, KeyError, TypeError, ValueError):
        return code_bytes, 0
    return transformed, len(specs)\n