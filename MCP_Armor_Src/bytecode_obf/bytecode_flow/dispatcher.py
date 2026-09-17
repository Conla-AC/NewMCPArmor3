# -*- coding: utf-8 -*-
"""Verified state-dispatch ByteCode_Flow rewriting for Python 2.7 bytecode.

The dispatcher has two state encodings.  Functions with an argument compute a
runtime token from ``arg is None`` once, then encode each state through two
independent lanes: a primary affine ``token op block_tag`` lane and a secondary
affine lane whose operation varies per edge.  The two lanes are checked at
the leaf of a balanced router tree, so a single visible state expression no
longer describes the complete transition relation.  Functions without
arguments retain the constant arithmetic encoding. Where a names table is
available, argument-bearing functions derive the primary token from a
call-level builtin ``id`` nonce; direct API callers without a names table keep
the compatibility token path. Both forms are emitted
only after ByteCode_Flow and stack verification, and loop block targets are
relocated along with ordinary jumps.
"""


from MCP_Armor_Src.core import py27_opcode as opcode
import random

from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import build_control_flow_graph
from MCP_Armor_Src.bytecode_obf.bytecode_flow.abstract_frame import (
    frame_analysis_gate,
)
from MCP_Armor_Src.bytecode_obf.bytecode_flow.relocator import encode_oparg
from MCP_Armor_Src.utils.encoding import byte_char, byte_value, random_ident


LOAD_CONST = opcode.opmap['LOAD_CONST']
LOAD_GLOBAL = opcode.opmap['LOAD_GLOBAL']
LOAD_FAST = opcode.opmap['LOAD_FAST']
STORE_FAST = opcode.opmap['STORE_FAST']
BINARY_XOR = opcode.opmap['BINARY_XOR']
BINARY_LSHIFT = opcode.opmap['BINARY_LSHIFT']
BINARY_ADD = opcode.opmap['BINARY_ADD']
BINARY_SUBTRACT = opcode.opmap['BINARY_SUBTRACT']
COMPARE_OP = opcode.opmap['COMPARE_OP']
POP_JUMP_IF_FALSE = opcode.opmap['POP_JUMP_IF_FALSE']
JUMP_ABSOLUTE = opcode.opmap['JUMP_ABSOLUTE']
RAISE_VARARGS = opcode.opmap['RAISE_VARARGS']
CALL_FUNCTION = opcode.opmap.get('CALL_FUNCTION')
EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG')

CONDITIONAL_NAMES = set(('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE', 'FOR_ITER'))
UNCONDITIONAL_NAMES = set(('JUMP_ABSOLUTE', 'JUMP_FORWARD'))
TERMINAL_NAMES = set(('RETURN_VALUE', 'RAISE_VARARGS', 'BREAK_LOOP', 'STOP_CODE'))
UNSUPPORTED_NAMES = set((
    'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'CONTINUE_LOOP',
    'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH', 'WITH_CLEANUP',
    'END_FINALLY'))
HOT_NAME_MARKERS = (
    'tick', 'update', 'timer', 'frame', 'render', 'callback',
    'listen', 'notify', 'destroy')


def _random_word(used):
    value = random.randint(1, 0x7fffffff)
    while value in used:
        value = random.randint(1, 0x7fffffff)
    used.add(value)
    return value


def _emit(output, data):
    position = len(output)
    output.extend(data)
    return position


def _emit_jump(output, opvalue):
    return _emit(output, encode_oparg(opvalue, 0))


def _patch_arg(output, position, argument):
    encoded = encode_oparg(byte_value(output[position]), argument)
    output[position:position + 3] = list(encoded)


def _patch_target(output, position, opcode_value, target):
    """Patch an absolute or relative bytecode target at *position*."""
    if opcode_value in opcode.hasjrel:
        argument = target - (position + 3)
    else:
        argument = target
    if argument < 0 or argument > 65535:
        raise ValueError('relocated jump argument out of range')
    _patch_arg(output, position, argument)


def _transition(output, state_index, transition_spec):
    left_const, right_const, operation = transition_spec
    _emit(output, encode_oparg(LOAD_CONST, left_const))
    _emit(output, encode_oparg(LOAD_CONST, right_const))
    _emit(output, byte_char(operation))
    _emit(output, encode_oparg(STORE_FAST, state_index))
    jump = _emit_jump(output, JUMP_ABSOLUTE)
    return jump


def _dynamic_transition(output, state_index, token_index, tag_index):
    """Set a frame-dependent ``token XOR tag`` dispatcher state."""
    _emit(output, encode_oparg(LOAD_FAST, token_index))
    _emit(output, encode_oparg(LOAD_CONST, tag_index))
    _emit(output, byte_char(BINARY_XOR))
    _emit(output, encode_oparg(STORE_FAST, state_index))
    return _emit_jump(output, JUMP_ABSOLUTE)


def _dynamic_transition_dual(output, state_index, token_index, tag_index,
                              primary_operation, secondary_state_index,
                              secondary_tag_index, secondary_operation):
    """Set both keyed lanes before entering the router.

    The secondary operation is selected independently for each logical block;
    the dispatcher emits its inverse when validating the lane.
    """
    _emit(output, encode_oparg(LOAD_FAST, token_index))
    _emit(output, encode_oparg(LOAD_CONST, tag_index))
    _emit(output, byte_char(primary_operation))
    _emit(output, encode_oparg(STORE_FAST, state_index))
    # Re-key the second lane from the primary state without another token
    # load. The tag is edge-specific, so the router also validates which
    # predecessor route entered the target block.
    _emit(output, encode_oparg(LOAD_FAST, state_index))
    _emit(output, encode_oparg(LOAD_CONST, secondary_tag_index))
    _emit(output, byte_char(secondary_operation))
    _emit(output, encode_oparg(STORE_FAST, secondary_state_index))
    return _emit_jump(output, JUMP_ABSOLUTE)


def _inverse_operation(operation):
    if operation == BINARY_ADD:
        return BINARY_SUBTRACT
    if operation == BINARY_SUBTRACT:
        return BINARY_ADD
    return BINARY_XOR


def _relative_order_safe(order, graph):
    """Keep forward-only SETUP_LOOP handlers physically after their setup."""
    positions = dict((block.start, index)
                     for index, block in enumerate(order))
    block_for_instruction = {}
    for block in graph.blocks:
        for item in block.instructions:
            block_for_instruction[item.offset] = block
    for item in graph.instructions:
        if opcode.opname[item.opcode] != 'SETUP_LOOP' or item.target is None:
            continue
        target = graph.block_by_start.get(item.target)
        source = block_for_instruction.get(item.offset)
        if target is None or source is None:
            return False
        if positions[target.start] <= positions[source.start]:
            return False
    return True


def apply_state_dispatcher(co, code_bytes, consts, varnames,
                           ratio=25, max_blocks=32, allow_loops=False,
                           names=None):
    """Route verified blocks through an encoded state dispatcher.

    Exception regions, generators, closures and extended arguments remain
    excluded.  ``FOR_ITER`` and ``SETUP_LOOP`` are admitted because their
    block-stack effects are preserved; their physical targets are relocated
    after rendering.  Any failed verification returns the original stream.
    """
    ratio = max(0, min(100, int(ratio or 0)))
    max_blocks = max(2, min(128, int(max_blocks or 0)))
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
    function_name = (co.co_name or '').lower()
    if ((function_name.startswith('__') and function_name.endswith('__')) or
            any(marker in function_name for marker in HOT_NAME_MARKERS)):
        return code_bytes, consts, varnames, 0
    try:
        graph = build_control_flow_graph(code_bytes)
    except (KeyError, TypeError, ValueError):
        return code_bytes, consts, varnames, 0
    if (not graph.stack_safe or graph.has_exception_flow or
            len(graph.blocks) > max_blocks):
        return code_bytes, consts, varnames, 0
    frame_ok, _frame_result = frame_analysis_gate(
        co, code_bytes, consts, varnames)
    if not frame_ok:
        return code_bytes, consts, varnames, 0
    if not graph.reachable_edges_stack_compatible():
        return code_bytes, consts, varnames, 0
    has_loop = any(opcode.opname[item.opcode] in
                   ('FOR_ITER', 'SETUP_LOOP', 'BREAK_LOOP')
                   for item in graph.instructions)
    if has_loop and not allow_loops:
        return code_bytes, original_consts, original_varnames, 0
    if any(item.opcode == EXTENDED_ARG for item in graph.instructions):
        return code_bytes, consts, varnames, 0
    if any(opcode.opname[item.opcode] in UNSUPPORTED_NAMES
           for item in graph.instructions):
        return code_bytes, consts, varnames, 0
    if any(block.start not in graph.stack_depths for block in graph.blocks):
        return code_bytes, consts, varnames, 0
    frame_ok, frame_result = frame_analysis_gate(
        co, code_bytes, consts, varnames)
    if not frame_ok or frame_result is None:
        return code_bytes, consts, varnames, 0
    if any(block.start not in frame_result.frames for block in graph.blocks
           if block.start in graph.stack_depths):
        return code_bytes, consts, varnames, 0

    # Split ordinary blocks only where the evaluation stack has returned to
    # the block's incoming depth. This exposes additional states without
    # spilling Python stack values into dispatcher code.
    split_candidates = []
    existing = set(block.start for block in graph.blocks)
    for block in graph.blocks:
        incoming = graph.stack_depths[block.start]
        for item in block.instructions[1:-1]:
            if (item.offset not in existing and
                    graph.stack_depths.get(item.offset) == incoming):
                split_candidates.append(item.offset)
    capacity = max_blocks - len(graph.blocks)
    needed = max(0, 3 - len(graph.blocks))
    if needed and len(split_candidates) < needed:
        return code_bytes, consts, varnames, 0
    if split_candidates and capacity > 0:
        random.shuffle(split_candidates)
        upper = min(capacity, max(needed, max(1, len(split_candidates) // 2)))
        split_count = random.randint(max(needed, 1), upper)
        try:
            graph = build_control_flow_graph(
                code_bytes, split_candidates[:split_count])
        except (KeyError, TypeError, ValueError):
            return code_bytes, consts, varnames, 0
    if len(graph.blocks) < 3 or len(graph.blocks) > max_blocks:
        return code_bytes, consts, varnames, 0

    edge_by_kind = {}
    for edge in graph.edges:
        edge_by_kind[(edge.source.start, edge.kind)] = edge
    for block in graph.blocks:
        name = opcode.opname[block.terminator.opcode]
        if name in CONDITIONAL_NAMES:
            if (edge_by_kind.get((block.start, 'taken')) is None or
                    edge_by_kind.get((block.start, 'fallthrough')) is None):
                return code_bytes, original_consts, original_varnames, 0
        elif name in UNCONDITIONAL_NAMES:
            if edge_by_kind.get((block.start, 'jump')) is None:
                return code_bytes, original_consts, original_varnames, 0
        elif name not in TERMINAL_NAMES and block.successors:
            if len(block.successors) != 1 or block.successors[0].kind != 'fallthrough':
                return code_bytes, original_consts, original_varnames, 0

    consts = list(consts)
    varnames = list(varnames)
    dynamic_state = bool(getattr(co, 'co_argcount', 0) and varnames)
    # Dynamic routing carries two independent lane tags plus the token mixer
    # constants; reserve the actual upper bound before appending any rows.
    estimated_consts = (len(graph.blocks) + len(graph.edges) + 12
                        if dynamic_state
                       else (len(graph.blocks) * 4) + 2)
    if len(consts) + estimated_consts > 65535:
        return code_bytes, original_consts, original_varnames, 0
    if len(varnames) + (2 if dynamic_state else 1) > 65535:
        return code_bytes, original_consts, original_varnames, 0

    runtime_nonce = bool(
        dynamic_state and names is not None and CALL_FUNCTION is not None and
        'id' not in tuple(names) and
        not (function_name.startswith('_') and not function_name.startswith('__')))
    if runtime_nonce and len(names) >= 65535:
        runtime_nonce = False

    state_name = random_ident('dispatch')
    while state_name in varnames:
        state_name = random_ident('dispatch')
    state_index = len(varnames)
    varnames.append(state_name)
    token_index = None
    secondary_state_index = None
    if dynamic_state:
        token_name = random_ident('token')
        while token_name in varnames:
            token_name = random_ident('token')
        token_index = len(varnames)
        varnames.append(token_name)
        secondary_state_name = random_ident('route')
        while secondary_state_name in varnames:
            secondary_state_name = random_ident('route')
        secondary_state_index = len(varnames)
        varnames.append(secondary_state_name)

    used = set()
    block_starts = [block.start for block in graph.blocks]
    nonce_salt_index = None
    nonce_name_index = None
    if dynamic_state:
        # ``is`` has no user-overridable comparison hook.  It gives each call
        # frame a runtime bit while keeping the generated state tuple small.
        none_index = consts.index(None) if None in consts else len(consts)
        if none_index == len(consts):
            consts.append(None)
        route_keys = [(edge.source.start, edge.target.start, edge.kind)
                      for edge in graph.edges]
        entry_route = ('entry', 0, 'entry')
        if entry_route not in route_keys:
            route_keys.append(entry_route)
        state_tags = dict((start, _random_word(used)) for start in block_starts)
        secondary_tags = dict((key, _random_word(used))
                              for key in route_keys)
        secondary_operations = dict(
            (key, random.choice((BINARY_XOR, BINARY_ADD, BINARY_SUBTRACT)))
            for key in route_keys)
        primary_operation = random.choice(
            (BINARY_XOR, BINARY_ADD, BINARY_SUBTRACT))
        tag_constants = dict(
            (start, len(consts) + index)
            for index, start in enumerate(block_starts))
        consts.extend(state_tags[start] for start in block_starts)
        secondary_tag_constants = dict(
            (key, len(consts) + index)
            for index, key in enumerate(route_keys))
        consts.extend(secondary_tags[key] for key in route_keys)
        argcount = min(int(co.co_argcount), len(varnames))
        token_arg_indexes = [0]
        if argcount > 1:
            token_arg_indexes.append(argcount - 1)
        if argcount > 2:
            middle = argcount // 2
            if middle not in token_arg_indexes:
                token_arg_indexes.append(middle)
        token_arg_indexes = token_arg_indexes[:3]
        shift_constants = {}
        for shift in range(1, len(token_arg_indexes)):
            try:
                shift_constants[shift] = consts.index(shift)
            except ValueError:
                shift_constants[shift] = len(consts)
                consts.append(shift)
        if runtime_nonce:
            nonce_salt_index = len(consts)
            consts.append(_random_word(used))
            nonce_name_index = len(names)
            names.append('id')
        transition_specs = None
        key_constants = None
        expected_constants = None
    else:
        state_values = dict((start, _random_word(used)) for start in block_starts)
        state_keys = dict((start, _random_word(used)) for start in block_starts)
        state_ops = dict((start, random.randrange(3)) for start in block_starts)
        state_expected = {}
        for start in block_starts:
            if state_ops[start] == 0:
                expected = state_values[start] ^ state_keys[start]
            elif state_ops[start] == 1:
                expected = state_values[start] + state_keys[start]
            else:
                expected = state_values[start] - state_keys[start]
            state_expected[start] = expected
        transition_specs = {}
        for start in block_starts:
            operation_index = random.randrange(3)
            left = _random_word(used)
            if operation_index == 0:
                right = left ^ state_values[start]
            elif operation_index == 1:
                right = state_values[start] - left
            else:
                right = left - state_values[start]
            left_index = len(consts)
            consts.append(left)
            right_index = len(consts)
            consts.append(right)
            transition_specs[start] = (
                left_index, right_index,
                (BINARY_XOR, BINARY_ADD, BINARY_SUBTRACT)[operation_index])
        key_constants = dict(
            (start, len(consts) + index)
            for index, start in enumerate(block_starts))
        consts.extend(state_keys[start] for start in block_starts)
        expected_constants = dict(
            (start, len(consts) + index)
            for index, start in enumerate(block_starts))
        consts.extend(state_expected[start] for start in block_starts)
    failure_const = len(consts)
    consts.append('invalid bytecode dispatcher state')

    def emit_transition(start, route_key=None):
        if dynamic_state:
            if route_key is None:
                route_key = ('entry', 0, 'entry')
            jump = _dynamic_transition_dual(
                output, state_index, token_index, tag_constants[start],
                primary_operation,
                secondary_state_index, secondary_tag_constants[route_key],
                secondary_operations[route_key])
        else:
            jump = _transition(output, state_index, transition_specs[start])
        # Preserve the exact logical target. Equal stack heights do not imply
        # equal iterator, local or block-stack shapes.
        return jump, start

    order = list(graph.blocks)
    random.shuffle(order)
    if not _relative_order_safe(order, graph):
        # Dispatcher routing still destroys the source-level loop shape even
        # when the forward-only SETUP_LOOP handler requires source ordering.
        order = list(graph.blocks)
    output = []
    block_offsets = {}
    transition_jumps = []
    conditional_jumps = []
    target_patches = []
    taken_proxies = []
    backedge_jumps = []

    if dynamic_state:
        if runtime_nonce:
            _emit(output, encode_oparg(LOAD_GLOBAL, nonce_name_index))
            _emit(output, encode_oparg(LOAD_FAST, token_arg_indexes[0]))
            _emit(output, encode_oparg(CALL_FUNCTION, 1))
            _emit(output, encode_oparg(LOAD_CONST, nonce_salt_index))
            _emit(output, byte_char(BINARY_XOR))
        else:
            for lane, arg_index in enumerate(token_arg_indexes):
                _emit(output, encode_oparg(LOAD_FAST, arg_index))
                _emit(output, encode_oparg(LOAD_CONST, none_index))
                _emit(output, encode_oparg(COMPARE_OP, opcode.cmp_op.index('is')))
                if lane:
                    _emit(output, encode_oparg(
                        LOAD_CONST, shift_constants[lane]))
                    _emit(output, byte_char(BINARY_LSHIFT))
                    _emit(output, byte_char(BINARY_XOR))
        _emit(output, encode_oparg(STORE_FAST, token_index))

    # The physical first block is randomized, so initialize the logical entry
    # state and enter the dispatcher before executing any block body.
    transition_jumps.append(emit_transition(
        0, ('entry', 0, 'entry') if dynamic_state else None))

    for block in order:
        block_offsets[block.start] = len(output)
        terminator = block.terminator
        name = opcode.opname[terminator.opcode]
        for item in block.instructions[:-1]:
            if item.target is not None and opcode.opname[item.opcode] != 'SETUP_LOOP':
                return code_bytes, original_consts, original_varnames, 0
            item_position = _emit(output, item.raw)
            if item.target is not None:
                target_patches.append((item_position, item.opcode, item.target))
        if name in CONDITIONAL_NAMES:
            taken = edge_by_kind[(block.start, 'taken')]
            fallthrough = edge_by_kind[(block.start, 'fallthrough')]
            conditional_opcode = terminator.opcode
            branch_target = taken.target.start
            fallthrough_target = fallthrough.target.start
            branch_kind = 'taken'
            fallthrough_kind = 'fallthrough'
            # BranchInstructionChange-style polarity variation. FOR_ITER is
            # excluded because its taken path mutates the iterator stack;
            # POP_JUMP polarity can be inverted while swapping the two
            # verified edge destinations.
            if (name in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE') and
                    random.randint(0, 1)):
                conditional_opcode = opcode.opmap[
                    'POP_JUMP_IF_TRUE' if name == 'POP_JUMP_IF_FALSE'
                    else 'POP_JUMP_IF_FALSE']
                branch_target, fallthrough_target = (
                    fallthrough_target, branch_target)
                branch_kind, fallthrough_kind = (
                    fallthrough_kind, branch_kind)
            conditional = _emit_jump(output, conditional_opcode)
            conditional_jumps.append((conditional, conditional_opcode,
                                      branch_target,
                                      (block.start, branch_target,
                                       branch_kind)))
            transition_jumps.append(emit_transition(
                fallthrough_target,
                (block.start, fallthrough_target,
                 fallthrough_kind)))
            taken_proxies.append((branch_target, (block.start,
                                                  branch_target, branch_kind)))
        elif name in UNCONDITIONAL_NAMES:
            target = edge_by_kind[(block.start, 'jump')].target.start
            if allow_loops and target <= block.start:
                backedge_jumps.append((_emit_jump(output, JUMP_ABSOLUTE),
                                       target))
            else:
                transition_jumps.append(emit_transition(
                    target, (block.start, target, 'jump')))
        elif name in TERMINAL_NAMES:
            item_position = _emit(output, terminator.raw)
            if terminator.target is not None:
                target_patches.append(
                    (item_position, terminator.opcode, terminator.target))
        elif block.successors:
            item_position = _emit(output, terminator.raw)
            if terminator.target is not None:
                target_patches.append(
                    (item_position, terminator.opcode, terminator.target))
            target = block.successors[0].target.start
            transition_jumps.append(emit_transition(
                target, (block.start, target, 'fallthrough')))
        else:
            item_position = _emit(output, terminator.raw)
            if terminator.target is not None:
                target_patches.append(
                    (item_position, terminator.opcode, terminator.target))

    proxy_offsets = {}
    for target, route_key in taken_proxies:
        proxy_offsets.setdefault(route_key, len(output))
        transition_jumps.append(emit_transition(target, route_key))

    direct_backedges = []
    for source_jump, target in backedge_jumps:
        proxy = len(output)
        _patch_arg(output, source_jump, proxy)
        direct_backedges.append((_emit_jump(output, JUMP_ABSOLUTE), target))

    # A single dispatcher cannot merge paths carrying different Frame shapes.
    # Group by the complete shape signature (locals, value stack, block stack,
    # exception state), not merely the integer stack depth. This keeps routes
    # with live iterators/cleanup handlers isolated even when their heights
    # happen to match.
    dispatcher_starts = {}
    dispatcher_failures = {}
    dispatcher_cases = []
    starts_by_shape = {}
    shape_for_start = {}
    region_for_start = {}
    if dynamic_state and len(block_starts) >= 6:
        region_count = min(4, max(2, len(block_starts) // 6))
        region_for_start[0] = 0
        for start in block_starts:
            if start not in region_for_start:
                region_for_start[start] = random.randrange(region_count)
    else:
        region_count = 1
        region_for_start = dict((start, 0) for start in block_starts)
    for start in block_starts:
        frame = frame_result.frame_at(start)
        if frame is None:
            return code_bytes, original_consts, original_varnames, 0
        shape = (region_for_start[start], frame.shape_signature())
        starts_by_shape.setdefault(shape, []).append(start)
        shape_for_start[start] = shape

    def emit_dynamic_value(tag_index):
        if primary_operation == BINARY_SUBTRACT:
            # state = token - tag  =>  tag = token - state
            _emit(output, encode_oparg(LOAD_FAST, token_index))
            _emit(output, encode_oparg(LOAD_FAST, state_index))
            _emit(output, byte_char(BINARY_SUBTRACT))
        else:
            _emit(output, encode_oparg(LOAD_FAST, state_index))
            _emit(output, encode_oparg(LOAD_FAST, token_index))
            _emit(output, byte_char(_inverse_operation(primary_operation)))
        _emit(output, encode_oparg(LOAD_CONST, tag_index))

    def emit_dynamic_secondary(tag_index, operation):
        # Invert the per-block affine operation to recover the secondary tag.
        if operation == BINARY_SUBTRACT:
            # state = token - tag  =>  tag = token - state
            _emit(output, encode_oparg(LOAD_FAST, state_index))
            _emit(output, encode_oparg(LOAD_FAST, secondary_state_index))
            _emit(output, byte_char(BINARY_SUBTRACT))
        else:
            _emit(output, encode_oparg(LOAD_FAST, secondary_state_index))
            _emit(output, encode_oparg(LOAD_FAST, state_index))
            _emit(output, byte_char(_inverse_operation(operation)))
        _emit(output, encode_oparg(LOAD_CONST, tag_index))

    def emit_dynamic_tree(specs):
        """Emit a balanced tag decision tree and return mismatch jumps."""
        groups = []
        for item in specs:
            if groups and groups[-1][0][2] == item[2]:
                groups[-1].append(item)
            else:
                groups.append([item])

        def emit_group(group):
            emit_dynamic_value(group[0][1])
            _emit(output, encode_oparg(COMPARE_OP, 2))
            mismatches = [_emit_jump(output, POP_JUMP_IF_FALSE)]
            check_starts = []
            check_mismatches = []
            for item in group:
                start, _tag_index, _tag_value, secondary_tag_index, operation = item
                if operation is None:
                    _patch_arg(output, _emit_jump(output, JUMP_ABSOLUTE),
                               block_offsets[start])
                    continue
                check_starts.append(len(output))
                emit_dynamic_secondary(secondary_tag_index, operation)
                _emit(output, encode_oparg(COMPARE_OP, 2))
                check_mismatches.append(_emit_jump(output, POP_JUMP_IF_FALSE))
                _patch_arg(output, _emit_jump(output, JUMP_ABSOLUTE),
                           block_offsets[start])
            for index, mismatch in enumerate(check_mismatches[:-1]):
                _patch_arg(output, mismatch, check_starts[index + 1])
            if check_mismatches:
                mismatches.append(check_mismatches[-1])
            return mismatches

        def flatten(rows):
            result = []
            for row in rows:
                result.extend(row)
            return result

        if len(groups) == 1:
            return emit_group(groups[0])
        middle = len(groups) // 2
        left = flatten(groups[:middle])
        right = flatten(groups[middle:])
        pivot_index = right[0][1]
        emit_dynamic_value(pivot_index)
        _emit(output, encode_oparg(COMPARE_OP, 0))
        choose_right = _emit_jump(output, POP_JUMP_IF_FALSE)
        failures = emit_dynamic_tree(left)
        right_start = len(output)
        _patch_arg(output, choose_right, right_start)
        failures.extend(emit_dynamic_tree(right))
        return failures

    shape_keys = sorted(starts_by_shape, key=repr)
    for shape in shape_keys:
        dispatcher_starts[shape] = len(output)
        starts = list(starts_by_shape[shape])
        if dynamic_state:
            hotness = dict((start, 0) for start in starts)
            for edge in graph.edges:
                if edge.source.start not in hotness or edge.target.start not in hotness:
                    continue
                if edge.target.start <= edge.source.start:
                    hotness[edge.target.start] += 8
                    hotness[edge.source.start] += 3
                elif edge.kind == 'taken':
                    hotness[edge.target.start] += 2
            starts.sort(key=lambda start: (-hotness[start], random.random()))
        else:
            random.shuffle(starts)
        if dynamic_state:
            case_specs = []
            for start in starts:
                incoming_routes = [
                    (edge.source.start, edge.target.start, edge.kind)
                    for edge in graph.edges if edge.target.start == start]
                if start == 0:
                    incoming_routes.append(('entry', 0, 'entry'))
                route_check = len(incoming_routes) > 1
                for route_key in incoming_routes:
                    case_specs.append((
                        start, tag_constants[start], state_tags[start],
                        secondary_tag_constants[route_key],
                        secondary_operations[route_key] if route_check else None))
        else:
            case_specs = [(start, key_constants[start], None)
                          for start in starts]
        if dynamic_state:
            # These tags are never assigned by a transition.  Keeping them in
            # the same depth table makes static state recovery less direct
            # without adding calls, imports, or malformed bytecode.
            if len(starts) >= 3 and not has_loop:
                for _ in range(min(2, max(1, len(starts) // 4))):
                    decoy_tag = _random_word(used)
                    decoy_index = len(consts)
                    consts.append(decoy_tag)
                    decoy_secondary_tag = _random_word(used)
                    decoy_secondary_index = len(consts)
                    consts.append(decoy_secondary_tag)
                    case_specs.append((
                        starts[0], decoy_index, decoy_tag,
                        decoy_secondary_index,
                        random.choice((BINARY_XOR, BINARY_ADD,
                                       BINARY_SUBTRACT))))
            case_specs.sort(key=lambda item: item[2])
            mismatches = emit_dynamic_tree(case_specs)
            dispatcher_failures[shape] = len(output)
            for mismatch in mismatches:
                _patch_arg(output, mismatch, dispatcher_failures[shape])
        else:
            for start, tag_index, _tag_value in case_specs:
                case_start = len(output)
                _emit(output, encode_oparg(LOAD_FAST, state_index))
                _emit(output, encode_oparg(LOAD_CONST, key_constants[start]))
                _emit(output, byte_char((BINARY_XOR, BINARY_ADD, BINARY_SUBTRACT)[
                    state_ops[start]]))
                _emit(output, encode_oparg(LOAD_CONST, expected_constants[start]))
                _emit(output, encode_oparg(COMPARE_OP, 2))
                condition = _emit_jump(output, POP_JUMP_IF_FALSE)
                target_jump = _emit_jump(output, JUMP_ABSOLUTE)
                dispatcher_cases.append((shape, case_start, condition,
                                         target_jump, start))
            dispatcher_failures[shape] = len(output)
        if dynamic_state:
            _emit(output, encode_oparg(LOAD_CONST, failure_const))
            _emit(output, encode_oparg(RAISE_VARARGS, 1))
        else:
            _emit(output, encode_oparg(LOAD_CONST, failure_const))
            _emit(output, encode_oparg(RAISE_VARARGS, 1))

    for jump, target_start in transition_jumps:
        target_shape = shape_for_start.get(target_start)
        if target_shape is None:
            return code_bytes, original_consts, original_varnames, 0
        _patch_arg(output, jump, dispatcher_starts[target_shape])
    for index, item in enumerate(dispatcher_cases):
        shape, case_start, condition, target_jump, start = item
        _patch_arg(output, target_jump, block_offsets[start])
        next_case = None
        for candidate in dispatcher_cases[index + 1:]:
            if candidate[0] == shape:
                next_case = candidate[1]
                break
        _patch_arg(output, condition,
                   next_case if next_case is not None
                   else dispatcher_failures[shape])
    for position, opcode_value, target, route_key in conditional_jumps:
        _patch_target(output, position, opcode_value,
                      proxy_offsets[route_key])
    for position, opcode_value, target in target_patches:
        mapped = block_offsets.get(target)
        if mapped is None:
            return code_bytes, original_consts, original_varnames, 0
        _patch_target(output, position, opcode_value, mapped)
    for position, target in direct_backedges:
        mapped = block_offsets.get(target)
        if mapped is None:
            return code_bytes, original_consts, original_varnames, 0
        _patch_arg(output, position, mapped)

    transformed = b''.join(output)
    if len(transformed) > 65535:
        return code_bytes, original_consts, original_varnames, 0
    try:
        verified = build_control_flow_graph(transformed)
    except (KeyError, TypeError, ValueError):
        return code_bytes, original_consts, original_varnames, 0
    if not verified.stack_safe or verified.has_exception_flow:
        return code_bytes, original_consts, original_varnames, 0
    frame_ok, _frame_result = frame_analysis_gate(
        co, transformed, consts, varnames)
    if not frame_ok:
        return code_bytes, original_consts, original_varnames, 0
    return transformed, consts, varnames, len(graph.blocks)
