# -*- coding: utf-8 -*-
"""Fixed-point abstract frame analysis for Python 2.7 ByteCode_Flow.

This module is analysis-only.  It never rewrites code bytes; callers can use
the resulting frame signatures as a proof gate before applying a transform.
Unknown operations fail closed and are reported in ``diagnostics``.
"""

from MCP_Armor_Src.core import py27_opcode as opcode
from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import (
    build_control_flow_graph,
    decode_instructions,
    _successor_specs,
)
from MCP_Armor_Src.bytecode_obf.bytecode_flow.stack import instruction_stack_effect
from MCP_Armor_Src.utils.encoding import byte_char, byte_value

try:
    _integer_types = (int, long)
except NameError:
    _integer_types = (int,)
try:
    _text_types = (basestring,)
except NameError:
    _text_types = (str,)


UNKNOWN = 'unknown'


class AbstractValue(object):
    __slots__ = ('kind', 'detail')

    def __init__(self, kind='unknown', detail=None):
        self.kind = kind
        self.detail = detail

    def __repr__(self):
        return self.kind if self.detail is None else '%s:%s' % (
            self.kind, self.detail)

    def __eq__(self, other):
        return isinstance(other, AbstractValue) and (
            self.kind, self.detail) == (other.kind, other.detail)

    def __hash__(self):
        return hash((self.kind, self.detail))


UNKNOWN_VALUE = AbstractValue()


class AbstractFrame(object):
    __slots__ = ('locals', 'stack', 'blocks', 'exception_state')

    def __init__(self, locals_=(), stack=(), blocks=(), exception_state=False):
        self.locals = tuple(locals_)
        self.stack = tuple(stack)
        self.blocks = tuple(blocks)
        self.exception_state = bool(exception_state)

    def signature(self):
        return (self.locals, self.stack, self.blocks, self.exception_state)

    def shape_signature(self):
        """Return the merge-safe shape without value provenance details."""
        return (tuple(value.kind for value in self.locals),
                tuple(value.kind for value in self.stack),
                self.blocks, self.exception_state)

    @property
    def stack_depth(self):
        return len(self.stack)

    def compatible_with(self, other):
        return isinstance(other, AbstractFrame) and \
            self.shape_signature() == other.shape_signature()

    def __eq__(self, other):
        return isinstance(other, AbstractFrame) and self.signature() == other.signature()

    def __repr__(self):
        return 'AbstractFrame(locals=%r, stack=%r, blocks=%r, exc=%r)' % (
            self.locals, self.stack, self.blocks, self.exception_state)


def _frame_equal(left, right):
    """Compare frame signatures without requiring object identity."""
    return left is not None and right is not None and left.signature() == right.signature()


class FrameAnalysisResult(object):
    def __init__(self, graph, frames, edge_frames, diagnostics,
                 converged, iterations, max_stack):
        self.graph = graph
        self.frames = frames
        self.edge_frames = edge_frames
        self.diagnostics = diagnostics
        self.converged = bool(converged)
        self.iterations = int(iterations)
        self.max_stack = int(max_stack)

    @property
    def safe(self):
        return bool(self.converged and not self.diagnostics)

    @property
    def exception_aware(self):
        return not any('unsupported exception edge' in value
                       for value in self.diagnostics)

    def frame_at(self, offset):
        return self.frames.get(offset)

    def edge_frame(self, source_offset, edge_kind, target_offset):
        return self.edge_frames.get((source_offset, edge_kind, target_offset))

    def edge_frame_compatible(self, source_offset, edge_kind, target_offset):
        outgoing = self.edge_frame(source_offset, edge_kind, target_offset)
        incoming = self.frame_at(target_offset)
        return outgoing is not None and incoming is not None and \
            outgoing.compatible_with(incoming)


def frame_analysis_gate(code_object, code_bytes=None, consts=None,
                        varnames=None, argcount=None):
    """Return ``(allowed, result)`` for a transform preflight.

    The gate is deliberately conservative: only a converged, diagnostic-free
    frame graph may enter a rewriting stage. Unsupported exception regions,
    closures and generators therefore fall back to their original bytes.
    """
    flags = int(getattr(code_object, 'co_flags', 0) or 0)
    if flags & 0x20 or getattr(code_object, 'co_freevars', ()) or \
            getattr(code_object, 'co_cellvars', ()):
        return False, None
    try:
        result = analyze_abstract_frames(
            code_bytes if code_bytes is not None else code_object.co_code,
            getattr(code_object, 'co_varnames', ())
            if varnames is None else varnames,
            getattr(code_object, 'co_argcount', 0)
            if argcount is None else argcount,
            consts=(getattr(code_object, 'co_consts', ())
                    if consts is None else consts))
    except (IndexError, KeyError, TypeError, ValueError):
        return False, None
    return bool(result.safe), result


def normalize_opcode_bytes(code_bytes, stored_to_logical=None):
    """Normalize a stored opcode alphabet to logical CPython 2.7 bytes.

    Instruction width is determined from the logical opcode. This is required
    for maps (such as an engine opcode table) that cross HAVE_ARGUMENT.
    """
    mapping = stored_to_logical or {}
    if not mapping:
        return code_bytes
    output = []
    position = 0
    while position < len(code_bytes):
        stored = byte_value(code_bytes[position])
        logical = int(mapping.get(stored, stored)) & 255
        output.append(byte_char(logical))
        position += 1
        if logical >= opcode.HAVE_ARGUMENT:
            if position + 1 >= len(code_bytes):
                raise ValueError('truncated stored instruction at %d' % (position - 1))
            output.extend((code_bytes[position], code_bytes[position + 1]))
            position += 2
    return b''.join(output)


def _merge_value(left, right):
    if left == right:
        return left
    if left.kind == 'unknown' or right.kind == 'unknown':
        return UNKNOWN_VALUE
    if left.kind == right.kind:
        return AbstractValue(left.kind)
    return UNKNOWN_VALUE


def _merge_frame(previous, incoming):
    if previous is None:
        return incoming
    if len(previous.locals) != len(incoming.locals) or \
            len(previous.stack) != len(incoming.stack) or \
            previous.blocks != incoming.blocks:
        return None
    return AbstractFrame(
        tuple(_merge_value(a, b) for a, b in zip(previous.locals, incoming.locals)),
        tuple(_merge_value(a, b) for a, b in zip(previous.stack, incoming.stack)),
        previous.blocks,
        previous.exception_state or incoming.exception_state)


def _is_raise_sink(offset, instructions, code_size):
    """Recognize the tiny linear trap used by transactional rewriters.

    State/edge guards deliberately converge many *invalid-state* paths on a
    shared ``LOAD_CONST; RAISE_VARARGS`` block.  Those paths can carry
    different loop/block shapes because they never return to user code.  A
    normal CFG merge must remain strict; only this terminal trap gets a
    widened frame so the post-transform proof can reason about the live
    paths without rejecting its error sink.
    """
    item = instructions.get(offset)
    if item is None:
        return False
    name = opcode.opname[item.opcode]
    if name == 'RAISE_VARARGS':
        return True
    if name != 'LOAD_CONST':
        return False
    next_item = instructions.get(item.next_offset)
    return next_item is not None and \
        opcode.opname[next_item.opcode] == 'RAISE_VARARGS'


def _widen_sink_frame(previous, incoming):
    """Build a conservative frame for a terminal raise sink."""
    if previous is None:
        previous = incoming
    local_count = max(len(previous.locals), len(incoming.locals))
    locals_ = []
    for index in range(local_count):
        left = previous.locals[index] if index < len(previous.locals) \
            else UNKNOWN_VALUE
        right = incoming.locals[index] if index < len(incoming.locals) \
            else UNKNOWN_VALUE
        locals_.append(_merge_value(left, right))
    stack_count = max(len(previous.stack), len(incoming.stack))
    return AbstractFrame(
        tuple(locals_), tuple([UNKNOWN_VALUE] * stack_count), (),
        previous.exception_state or incoming.exception_state)


def _value_for_load(name, arg, frame, consts=()):
    if name in ('LOAD_FAST', 'LOAD_DEREF'):
        return frame.locals[arg] if 0 <= arg < len(frame.locals) else UNKNOWN_VALUE
    if name == 'LOAD_CONST':
        value = consts[arg] if 0 <= arg < len(consts) else None
        if value is None:
            return AbstractValue('null', arg)
        if isinstance(value, _integer_types + (float, complex)):
            return AbstractValue('primitive', arg)
        if isinstance(value, _text_types):
            return AbstractValue('text', arg)
        if hasattr(value, 'co_code'):
            return AbstractValue('code', arg)
        return AbstractValue('constant', arg)
    if name in ('LOAD_GLOBAL', 'LOAD_NAME'):
        return AbstractValue('reference')
    if name == 'LOAD_CLOSURE':
        return AbstractValue('cell')
    return UNKNOWN_VALUE


def _transfer(item, frame, edge_kind=None, consts=()):
    name = opcode.opname[item.opcode]
    stack = list(frame.stack)
    locals_ = list(frame.locals)
    blocks = list(frame.blocks)
    arg = int(item.argument or 0)

    def pop(count=1):
        if len(stack) < count:
            raise ValueError('stack underflow at %d (%s)' % (item.offset, name))
        values = stack[-count:]
        del stack[-count:]
        return values

    if name == 'LOAD_ATTR':
        pop()
        stack.append(AbstractValue('reference'))
    elif name == 'GET_ITER':
        pop()
        stack.append(AbstractValue('iterator'))
    elif name == 'LOAD_CONST':
        stack.append(_value_for_load(name, arg, frame, consts))
    elif name.startswith('LOAD_'):
        stack.append(_value_for_load(name, arg, frame, consts))
    elif name in ('STORE_FAST', 'STORE_NAME', 'STORE_GLOBAL', 'STORE_DEREF'):
        value = pop()[0]
        if name == 'STORE_FAST' and 0 <= arg < len(locals_):
            locals_[arg] = value
    elif name in ('DELETE_FAST', 'DELETE_NAME', 'DELETE_GLOBAL', 'DELETE_DEREF'):
        if name == 'DELETE_FAST' and 0 <= arg < len(locals_):
            locals_[arg] = UNKNOWN_VALUE
    elif name == 'STORE_ATTR':
        pop(2)
    elif name == 'DELETE_ATTR':
        pop()
    elif name == 'POP_TOP':
        pop()
    elif name == 'DUP_TOP':
        stack.append(stack[-1] if stack else UNKNOWN_VALUE)
    elif name == 'DUP_TOPX':
        values = pop(arg)
        stack.extend(values)
        stack.extend(values)
    elif name in ('ROT_TWO', 'ROT_THREE', 'ROT_FOUR'):
        count = {'ROT_TWO': 2, 'ROT_THREE': 3, 'ROT_FOUR': 4}[name]
        values = pop(count)
        stack.extend(values[1:] + values[:1])
    elif name.startswith('UNARY_'):
        value = pop()[0]
        stack.append(AbstractValue('primitive') if name == 'UNARY_NOT' else value)
    elif name == 'BINARY_SUBSCR':
        pop(2)
        stack.append(UNKNOWN_VALUE)
    elif name.startswith('BINARY_') or name.startswith('INPLACE_'):
        pop(2)
        stack.append(AbstractValue('primitive'))
    elif name in ('COMPARE_OP',):
        pop(2)
        stack.append(AbstractValue('primitive'))
    elif name in ('BUILD_TUPLE', 'BUILD_LIST', 'BUILD_SET'):
        pop(arg)
        stack.append(AbstractValue('container'))
    elif name == 'BUILD_MAP':
        stack.append(AbstractValue('container'))
    elif name == 'BUILD_SLICE':
        pop(arg)
        stack.append(AbstractValue('slice'))
    elif name == 'BUILD_CLASS':
        pop(3)
        stack.append(AbstractValue('reference'))
    elif name in ('STORE_SUBSCR', 'DELETE_SUBSCR'):
        pop(3 if name == 'STORE_SUBSCR' else 2)
    elif name in ('STORE_SLICE+0', 'STORE_SLICE+1', 'STORE_SLICE+2',
                  'STORE_SLICE+3'):
        pop({'STORE_SLICE+0': 2, 'STORE_SLICE+1': 3,
             'STORE_SLICE+2': 3, 'STORE_SLICE+3': 4}[name])
    elif name in ('DELETE_SLICE+0', 'DELETE_SLICE+1', 'DELETE_SLICE+2',
                  'DELETE_SLICE+3'):
        pop({'DELETE_SLICE+0': 1, 'DELETE_SLICE+1': 2,
             'DELETE_SLICE+2': 2, 'DELETE_SLICE+3': 3}[name])
    elif name in ('CALL_FUNCTION', 'CALL_FUNCTION_VAR', 'CALL_FUNCTION_KW',
                  'CALL_FUNCTION_VAR_KW'):
        positional = arg & 255
        keywords = (arg >> 8) & 255
        extra = 0 if name == 'CALL_FUNCTION' else 1
        pop(1 + positional + 2 * keywords + extra)
        stack.append(UNKNOWN_VALUE)
    elif name in ('MAKE_FUNCTION', 'MAKE_CLOSURE'):
        pop(arg + (1 if name == 'MAKE_CLOSURE' else 0))
        stack.append(AbstractValue('function'))
    elif name == 'IMPORT_NAME':
        pop(2)
        stack.append(AbstractValue('module'))
    elif name == 'IMPORT_FROM':
        stack.append(AbstractValue('reference'))
    elif name == 'IMPORT_STAR':
        pop()
    elif name == 'UNPACK_SEQUENCE':
        pop()
        stack.extend([UNKNOWN_VALUE] * arg)
    elif name in ('LIST_APPEND', 'SET_ADD'):
        pop()
    elif name == 'MAP_ADD':
        pop(2)
    elif name in ('RETURN_VALUE',):
        pop()
    elif name == 'FOR_ITER':
        if edge_kind == 'taken':
            pop()
        else:
            if not stack:
                raise ValueError('FOR_ITER without iterator at %d' % item.offset)
            stack.append(AbstractValue('iterator_value'))
    elif name in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE'):
        pop()
    elif name in ('JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP'):
        if edge_kind != 'taken':
            pop()
    elif name in ('SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH'):
        blocks.append(name)
    elif name == 'POP_BLOCK':
        if blocks:
            blocks.pop()
    elif name in ('BREAK_LOOP', 'CONTINUE_LOOP'):
        pass
    elif name == 'WITH_CLEANUP':
        # Exception and normal ``with`` exits carry different temporary
        # values. Keep the model conservative while consuming the active
        # cleanup payload so END_FINALLY can converge with the normal edge.
        if frame.exception_state and len(stack) >= 3:
            del stack[-3:]
        elif stack:
            stack.pop()
        blocks = []
        frame = AbstractFrame(locals_, stack, blocks, frame.exception_state)
    elif name == 'END_FINALLY':
        if frame.exception_state and len(stack) >= 3:
            del stack[-3:]
        elif stack:
            stack.pop()
        blocks = []
        frame = AbstractFrame(locals_, stack, blocks, False)
    elif name in ('NOP', 'JUMP_ABSOLUTE', 'JUMP_FORWARD', 'PRINT_NEWLINE'):
        pass
    elif name in ('PRINT_ITEM', 'PRINT_EXPR', 'PRINT_ITEM_TO', 'PRINT_NEWLINE_TO'):
        pop(1 if name != 'PRINT_ITEM_TO' else 2)
    elif name == 'RAISE_VARARGS':
        pop(arg)
    elif name in ('YIELD_VALUE',):
        if stack:
            pop()
        stack.append(UNKNOWN_VALUE)
    else:
        # Preserve exact depth for every operation already described by the
        # conservative stack table, but discard value precision. This lets the
        # first milestone analyze broad real-world code without pretending to
        # know a semantic result type it has not modeled yet.
        effect = instruction_stack_effect(item, edge_kind)
        if effect is None:
            raise ValueError('unsupported frame transfer for %s at %d' % (
                name, item.offset))
        if effect < 0:
            pop(-effect)
        elif effect > 0:
            stack.extend([UNKNOWN_VALUE] * effect)
        stack = [UNKNOWN_VALUE] * len(stack)
    return AbstractFrame(locals_, stack, blocks, frame.exception_state)


def analyze_abstract_frames(code_bytes, varnames=(), argcount=0,
                            max_iterations=100000, stored_to_logical=None,
                            consts=()):
    code_bytes = normalize_opcode_bytes(code_bytes, stored_to_logical)
    graph = build_control_flow_graph(code_bytes)
    instructions = dict((item.offset, item) for item in decode_instructions(code_bytes))
    initial_locals = [UNKNOWN_VALUE] * len(tuple(varnames))
    for index in range(min(int(argcount or 0), len(initial_locals))):
        initial_locals[index] = AbstractValue('argument', index)
    frames = {0: AbstractFrame(initial_locals)}
    edge_frames = {}
    diagnostics = []
    queue = [0]
    queued = set([0])
    iterations = 0
    max_stack = 0
    while queue and iterations < max_iterations:
        offset = queue.pop(0)
        queued.discard(offset)
        iterations += 1
        frame = frames[offset]
        item = instructions[offset]
        successors = _successor_specs(item, graph.code_size)
        if not successors:
            try:
                outgoing = _transfer(item, frame, consts=consts)
            except ValueError as exc:
                diagnostics.append(str(exc))
            else:
                max_stack = max(max_stack, len(outgoing.stack))
        for kind, target in successors:
            if target is None or target == graph.code_size:
                continue
            if kind == 'exception':
                # Python 2.7 exception handlers enter with a temporary
                # exception payload. SETUP_EXCEPT exposes the classic
                # (type, value, traceback) triple; finally/with handlers use
                # a single sentinel that converges with their normal None
                # marker. The block stack is unwound at the handler boundary.
                count = 3 if opcode.opname[item.opcode] == 'SETUP_EXCEPT' else 1
                outgoing = AbstractFrame(
                    frame.locals,
                    tuple([UNKNOWN_VALUE] * count),
                    (), True)
                edge_frames[(item.offset, kind, target)] = outgoing
                max_stack = max(max_stack, len(outgoing.stack))
                merged = _merge_frame(frames.get(target), outgoing)
                if merged is None:
                    if _is_raise_sink(target, instructions, graph.code_size):
                        merged = _widen_sink_frame(frames.get(target), outgoing)
                    else:
                        diagnostics.append(
                            'exception frame merge mismatch at %d' % target)
                        continue
                if not _frame_equal(merged, frames.get(target)):
                    frames[target] = merged
                    if target not in queued:
                        queue.append(target)
                        queued.add(target)
                continue
            try:
                outgoing = _transfer(item, frame, kind, consts)
            except ValueError as exc:
                diagnostics.append(str(exc))
                continue
            edge_frames[(item.offset, kind, target)] = outgoing
            max_stack = max(max_stack, len(outgoing.stack))
            merged = _merge_frame(frames.get(target), outgoing)
            if merged is None:
                if _is_raise_sink(target, instructions, graph.code_size):
                    merged = _widen_sink_frame(frames.get(target), outgoing)
                else:
                    diagnostics.append('frame merge mismatch at %d' % target)
                    continue
            if not _frame_equal(merged, frames.get(target)):
                frames[target] = merged
                if target not in queued:
                    queue.append(target)
                    queued.add(target)
    if queue:
        diagnostics.append('frame analysis iteration limit exceeded')
    return FrameAnalysisResult(
        graph, frames, edge_frames, sorted(set(diagnostics)),
        not queue, iterations, max_stack)


def analyze_code_tree(code, stored_to_logical=None):
    """Analyze a recursive CodeType tree and return a compact audit report."""
    results = []
    pending = [code]
    while pending:
        item = pending.pop(0)
        result = analyze_abstract_frames(
            item.co_code, item.co_varnames, item.co_argcount,
            stored_to_logical=stored_to_logical, consts=item.co_consts)
        results.append((item, result))
        for const in item.co_consts:
            if hasattr(const, 'co_code') and hasattr(const, 'co_consts'):
                pending.append(const)
    diagnostics = []
    exception_regions = 0
    for item, result in results:
        diagnostics.extend('%s: %s' % (item.co_name, value)
                           for value in result.diagnostics)
        exception_regions += sum(
            1 for instruction in result.graph.instructions
            if opcode.opname[instruction.opcode] in (
                'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH'))
    return {
        'functions_analyzed': len(results),
        'functions_converged': sum(1 for _item, result in results
                                   if result.converged),
        'frames': sum(len(result.frames) for _item, result in results),
        'merge_failures': sum(1 for value in diagnostics
                              if 'merge mismatch' in value),
        'unsupported': sorted(set(
            value for value in diagnostics if 'unsupported' in value)),
        'exception_regions': exception_regions,
        'max_calculated_stack': max(
            [result.max_stack for _item, result in results] or [0]),
        'diagnostics': diagnostics,
        'results': results,
    }\n