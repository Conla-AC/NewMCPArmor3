# -*- coding: utf-8 -*-
"""Bytecode-level stack VM: compile CPython 2.7 code objects into a custom
instruction stream and interpret it with a self-contained Python runtime.

Unlike the AST layer's register machine, this path virtualizes the *compiled
code object* directly.  It runs inside the Python 2.7 target worker and emits
py2.7-compatible runtime source.

Scope (v1): a useful core covering arithmetic, comparisons, control flow,
loops, calls (positional/keyword/*args/**kwargs), containers, attribute and
subscript access, unpacking and slicing.  Code objects that use an unsupported
opcode are returned unchanged (native) by ``compile_vm``.
"""

import types

from MCP_Armor_Src.core import py27_opcode as opcode

HAVE_ARGUMENT = opcode.HAVE_ARGUMENT

CO_VARARGS = 0x04
CO_VARKEYWORDS = 0x08

_CMP_OPS = opcode.cmp_op


def _relative_jump_ops():
    names = ('FOR_ITER', 'SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY',
             'SETUP_WITH', 'JUMP_FORWARD')
    return set(name for name in names if name in opcode.opmap)


def _absolute_jump_ops():
    names = ('JUMP_ABSOLUTE', 'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
             'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'CONTINUE_LOOP')
    return set(name for name in names if name in opcode.opmap)


SUPPORTED_OPS = set((
    'LOAD_CONST', 'LOAD_FAST', 'STORE_FAST', 'DELETE_FAST',
    'LOAD_GLOBAL', 'STORE_GLOBAL', 'LOAD_NAME', 'LOAD_ATTR', 'STORE_ATTR',
    'DELETE_ATTR',
    'BINARY_ADD', 'BINARY_SUBTRACT', 'BINARY_MULTIPLY', 'BINARY_DIVIDE',
    'BINARY_MODULO', 'BINARY_POWER', 'BINARY_FLOOR_DIVIDE',
    'BINARY_TRUE_DIVIDE', 'BINARY_LSHIFT', 'BINARY_RSHIFT', 'BINARY_AND',
    'BINARY_XOR', 'BINARY_OR',
    'INPLACE_ADD', 'INPLACE_SUBTRACT', 'INPLACE_MULTIPLY', 'INPLACE_DIVIDE',
    'INPLACE_MODULO', 'INPLACE_POWER',
    'BINARY_SUBSCR', 'STORE_SUBSCR', 'DELETE_SUBSCR',
    'COMPARE_OP', 'UNARY_POSITIVE', 'UNARY_NEGATIVE', 'UNARY_NOT',
    'UNARY_INVERT',
    'POP_TOP', 'DUP_TOP', 'ROT_TWO', 'ROT_THREE', 'ROT_FOUR',
    'RETURN_VALUE',
    'CALL_FUNCTION', 'CALL_FUNCTION_VAR', 'CALL_FUNCTION_KW',
    'CALL_FUNCTION_VAR_KW',
    'BUILD_TUPLE', 'BUILD_LIST', 'BUILD_MAP', 'BUILD_SLICE', 'STORE_MAP',
    'UNPACK_SEQUENCE',
    'JUMP_ABSOLUTE', 'JUMP_FORWARD', 'POP_JUMP_IF_FALSE',
    'POP_JUMP_IF_TRUE', 'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP',
    'GET_ITER', 'FOR_ITER', 'BREAK_LOOP', 'CONTINUE_LOOP',
    'SETUP_LOOP', 'POP_BLOCK',
    'SLICE+0', 'SLICE+1', 'SLICE+2', 'SLICE+3',
))


def decode_code(co):
    """Decode a code object's bytecode into (offset, op_name, arg) triples."""
    code = co.co_code
    units = []
    pos = 0
    size = len(code)
    while pos < size:
        opv = ord(code[pos])
        op_name = opcode.opname[opv] if opv < len(opcode.opname) else None
        if opv >= HAVE_ARGUMENT and pos + 2 < size:
            arg = ord(code[pos + 1]) | (ord(code[pos + 2]) << 8)
            units.append((pos, op_name, arg))
            pos += 3
        else:
            units.append((pos, op_name, None))
            pos += 1
    return units


def compile_vm(co, defaults=()):
    """Compile a code object into a serializable VM payload, or return None.

    The payload is a tuple
    ``(consts, names, varnames, argcount, flags, defaults, instructions)``
    where each instruction is ``(op_name, arg)`` and jump args are instruction
    indices.
    """
    units = decode_code(co)
    if not units:
        return None
    relative = _relative_jump_ops()
    absolute = _absolute_jump_ops()
    for _pos, op_name, _arg in units:
        if op_name not in SUPPORTED_OPS:
            return None
    end_offset = len(co.co_code)
    off2idx = {}
    for index, (pos, _name, _arg) in enumerate(units):
        off2idx[pos] = index
    off2idx[end_offset] = len(units)
    instructions = []
    for pos, op_name, arg in units:
        if op_name in relative:
            arg = off2idx.get(pos + 3 + (arg or 0))
        elif op_name in absolute:
            arg = off2idx.get(arg)
        instructions.append((op_name, arg))
    return (
        tuple(co.co_consts), tuple(co.co_names), tuple(co.co_varnames),
        int(co.co_argcount), int(getattr(co, 'co_flags', 0) or 0),
        tuple(defaults or ()),
        tuple(instructions),
    )


RUNTIME_SOURCE = r'''
def _vm_run(_pl, _args, _kw):
    _consts = _pl[0]
    _names = _pl[1]
    _varnames = _pl[2]
    _argcount = _pl[3]
    _flags = _pl[4]
    _defaults = _pl[5]
    _code = _pl[6]
    _nlocals = len(_varnames)
    _fast = [None] * _nlocals
    _n_defaults = len(_defaults)
    _n_required = _argcount - _n_defaults
    for _i, _a in enumerate(_args):
        if _i < _argcount:
            _fast[_i] = _a
    _kwarg_idx = _argcount + 1
    for _k, _v in _kw.items():
        _matched = False
        for _idx in range(_argcount):
            if _idx < _nlocals and _varnames[_idx] == _k:
                _fast[_idx] = _v
                _matched = True
                break
        if not _matched:
            if _flags & 8:
                if _fast[_kwarg_idx] is None:
                    _fast[_kwarg_idx] = {}
                _fast[_kwarg_idx][_k] = _v
            else:
                raise TypeError("unexpected keyword argument '%s'" % _k)
    for _idx in range(_n_required, _argcount):
        if _idx < _nlocals and _fast[_idx] is None:
            _fast[_idx] = _defaults[_idx - _n_required]
    if _flags & 4:
        _fast[_argcount] = tuple(_args[_argcount:])
    if _flags & 8 and _fast[_kwarg_idx] is None:
        _fast[_kwarg_idx] = {}
    _stack = []
    _blocks = []
    _pc = 0
    _n = len(_code)
    _g = globals()
    while _pc < _n:
        _op, _arg = _code[_pc]
        _pc += 1
        if _op == 'LOAD_CONST':
            _stack.append(_consts[_arg])
        elif _op == 'LOAD_FAST':
            _stack.append(_fast[_arg])
        elif _op == 'STORE_FAST':
            _fast[_arg] = _stack.pop()
        elif _op == 'DELETE_FAST':
            _fast[_arg] = None
        elif _op == 'LOAD_GLOBAL':
            try:
                _stack.append(_g[_names[_arg]])
            except KeyError:
                _b = _g.get('__builtins__')
                if isinstance(_b, dict):
                    _stack.append(_b[_names[_arg]])
                else:
                    _stack.append(getattr(_b, _names[_arg]))
        elif _op == 'STORE_GLOBAL':
            _g[_names[_arg]] = _stack.pop()
        elif _op == 'LOAD_NAME':
            _nm = _names[_arg]
            try:
                _stack.append(_g[_nm])
            except KeyError:
                _b = _g.get('__builtins__')
                if isinstance(_b, dict):
                    _stack.append(_b[_nm])
                else:
                    _stack.append(getattr(_b, _nm))
        elif _op == 'LOAD_ATTR':
            _stack.append(getattr(_stack.pop(), _names[_arg]))
        elif _op == 'STORE_ATTR':
            _v = _stack.pop()
            _o = _stack.pop()
            setattr(_o, _names[_arg], _v)
        elif _op == 'DELETE_ATTR':
            delattr(_stack.pop(), _names[_arg])
        elif _op == 'BINARY_ADD':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a + _b)
        elif _op == 'BINARY_SUBTRACT':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a - _b)
        elif _op == 'BINARY_MULTIPLY':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a * _b)
        elif _op == 'BINARY_DIVIDE':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a / _b)
        elif _op == 'BINARY_MODULO':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a % _b)
        elif _op == 'BINARY_POWER':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a ** _b)
        elif _op == 'BINARY_FLOOR_DIVIDE':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a // _b)
        elif _op == 'BINARY_TRUE_DIVIDE':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a.__truediv__(_b))
        elif _op == 'BINARY_LSHIFT':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a << _b)
        elif _op == 'BINARY_RSHIFT':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a >> _b)
        elif _op == 'BINARY_AND':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a & _b)
        elif _op == 'BINARY_XOR':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a ^ _b)
        elif _op == 'BINARY_OR':
            _b = _stack.pop(); _a = _stack.pop(); _stack.append(_a | _b)
        elif _op == 'INPLACE_ADD':
            _b = _stack.pop(); _a = _stack.pop(); _a += _b; _stack.append(_a)
        elif _op == 'INPLACE_SUBTRACT':
            _b = _stack.pop(); _a = _stack.pop(); _a -= _b; _stack.append(_a)
        elif _op == 'INPLACE_MULTIPLY':
            _b = _stack.pop(); _a = _stack.pop(); _a *= _b; _stack.append(_a)
        elif _op == 'INPLACE_DIVIDE':
            _b = _stack.pop(); _a = _stack.pop(); _a /= _b; _stack.append(_a)
        elif _op == 'INPLACE_MODULO':
            _b = _stack.pop(); _a = _stack.pop(); _a %= _b; _stack.append(_a)
        elif _op == 'INPLACE_POWER':
            _b = _stack.pop(); _a = _stack.pop(); _a **= _b; _stack.append(_a)
        elif _op == 'BINARY_SUBSCR':
            _k = _stack.pop(); _o = _stack.pop(); _stack.append(_o[_k])
        elif _op == 'STORE_SUBSCR':
            _k = _stack.pop(); _o = _stack.pop(); _v = _stack.pop(); _o[_k] = _v
        elif _op == 'DELETE_SUBSCR':
            _k = _stack.pop(); _o = _stack.pop(); del _o[_k]
        elif _op == 'COMPARE_OP':
            _b = _stack.pop(); _a = _stack.pop()
            _c = _arg
            if _c == 0: _r = _a < _b
            elif _c == 1: _r = _a <= _b
            elif _c == 2: _r = _a == _b
            elif _c == 3: _r = _a != _b
            elif _c == 4: _r = _a > _b
            elif _c == 5: _r = _a >= _b
            elif _c == 6: _r = _a in _b
            elif _c == 7: _r = _a not in _b
            elif _c == 8: _r = _a is _b
            elif _c == 9: _r = _a is not _b
            else: _r = False
            _stack.append(_r)
        elif _op == 'UNARY_POSITIVE':
            _stack.append(+_stack.pop())
        elif _op == 'UNARY_NEGATIVE':
            _stack.append(-_stack.pop())
        elif _op == 'UNARY_NOT':
            _stack.append(not _stack.pop())
        elif _op == 'UNARY_INVERT':
            _stack.append(~_stack.pop())
        elif _op == 'POP_TOP':
            _stack.pop()
        elif _op == 'DUP_TOP':
            _stack.append(_stack[-1])
        elif _op == 'ROT_TWO':
            _a = _stack.pop(); _b = _stack.pop(); _stack.append(_a); _stack.append(_b)
        elif _op == 'ROT_THREE':
            _v = _stack.pop(); _w = _stack.pop(); _x = _stack.pop()
            _stack.append(_v); _stack.append(_x); _stack.append(_w)
        elif _op == 'ROT_FOUR':
            _d = _stack.pop(); _c = _stack.pop(); _b = _stack.pop(); _a = _stack.pop()
            _stack.append(_d); _stack.append(_a); _stack.append(_b); _stack.append(_c)
        elif _op == 'RETURN_VALUE':
            return _stack.pop()
        elif _op == 'CALL_FUNCTION':
            _nk = (_arg >> 8) & 0xff
            _na = _arg & 0xff
            _kw = {}
            for _ in range(_nk):
                _v = _stack.pop(); _k = _stack.pop(); _kw[_k] = _v
            _aa = [_stack.pop() for _ in range(_na)]
            _aa.reverse()
            _f = _stack.pop()
            _stack.append(_f(*_aa, **_kw))
        elif _op == 'CALL_FUNCTION_VAR':
            _nk = (_arg >> 8) & 0xff
            _na = _arg & 0xff
            _star = _stack.pop()
            _kw = {}
            for _ in range(_nk):
                _v = _stack.pop(); _k = _stack.pop(); _kw[_k] = _v
            _aa = [_stack.pop() for _ in range(_na)]
            _aa.reverse()
            _aa.extend(_star)
            _f = _stack.pop()
            _stack.append(_f(*_aa, **_kw))
        elif _op == 'CALL_FUNCTION_KW':
            _nk = (_arg >> 8) & 0xff
            _na = _arg & 0xff
            _extra_kw = _stack.pop()
            _kw = {}
            for _ in range(_nk):
                _v = _stack.pop(); _k = _stack.pop(); _kw[_k] = _v
            _kw.update(_extra_kw)
            _aa = [_stack.pop() for _ in range(_na)]
            _aa.reverse()
            _f = _stack.pop()
            _stack.append(_f(*_aa, **_kw))
        elif _op == 'CALL_FUNCTION_VAR_KW':
            _nk = (_arg >> 8) & 0xff
            _na = _arg & 0xff
            _extra_kw = _stack.pop()
            _star = _stack.pop()
            _kw = {}
            for _ in range(_nk):
                _v = _stack.pop(); _k = _stack.pop(); _kw[_k] = _v
            _kw.update(_extra_kw)
            _aa = [_stack.pop() for _ in range(_na)]
            _aa.reverse()
            _aa.extend(_star)
            _f = _stack.pop()
            _stack.append(_f(*_aa, **_kw))
        elif _op == 'BUILD_TUPLE':
            _vals = [_stack.pop() for _ in range(_arg)]
            _vals.reverse()
            _stack.append(tuple(_vals))
        elif _op == 'BUILD_LIST':
            _vals = [_stack.pop() for _ in range(_arg)]
            _vals.reverse()
            _stack.append(_vals)
        elif _op == 'BUILD_MAP':
            _stack.append({})
        elif _op == 'BUILD_SLICE':
            if _arg == 3:
                _step = _stack.pop(); _stop = _stack.pop(); _start = _stack.pop()
                _stack.append(slice(_start, _stop, _step))
            else:
                _stop = _stack.pop(); _start = _stack.pop()
                _stack.append(slice(_start, _stop))
        elif _op == 'STORE_MAP':
            _k = _stack.pop(); _v = _stack.pop(); _stack[-1][_k] = _v
        elif _op == 'UNPACK_SEQUENCE':
            _seq = _stack.pop()
            for _i in range(_arg - 1, -1, -1):
                _stack.append(_seq[_i])
        elif _op == 'JUMP_ABSOLUTE':
            _pc = _arg
        elif _op == 'JUMP_FORWARD':
            _pc = _arg
        elif _op == 'POP_JUMP_IF_FALSE':
            if not _stack.pop():
                _pc = _arg
        elif _op == 'POP_JUMP_IF_TRUE':
            if _stack.pop():
                _pc = _arg
        elif _op == 'JUMP_IF_FALSE_OR_POP':
            if _stack[-1]:
                _stack.pop()
            else:
                _pc = _arg
        elif _op == 'JUMP_IF_TRUE_OR_POP':
            if _stack[-1]:
                _pc = _arg
            else:
                _stack.pop()
        elif _op == 'SLICE+0':
            _o = _stack.pop(); _stack.append(_o[:])
        elif _op == 'SLICE+1':
            _v = _stack.pop(); _o = _stack.pop(); _stack.append(_o[_v:])
        elif _op == 'SLICE+2':
            _w = _stack.pop(); _o = _stack.pop(); _stack.append(_o[:_w])
        elif _op == 'SLICE+3':
            _w = _stack.pop(); _v = _stack.pop(); _o = _stack.pop(); _stack.append(_o[_v:_w])
        elif _op == 'GET_ITER':
            _stack.append(iter(_stack.pop()))
        elif _op == 'FOR_ITER':
            try:
                _stack.append(next(_stack[-1]))
            except StopIteration:
                _stack.pop()
                _pc = _arg
        elif _op == 'SETUP_LOOP':
            _blocks.append(_arg)
        elif _op == 'POP_BLOCK':
            _blocks.pop()
        elif _op == 'BREAK_LOOP':
            _pc = _blocks.pop()
        elif _op == 'CONTINUE_LOOP':
            _pc = _arg
    return None
'''


def make_vm_entry(func, globals_dict=None):
    """Return a callable virtualizing ``func``, or None if unsupported.

    ``globals_dict`` supplies the runtime's global namespace so that
    ``LOAD_GLOBAL``/``LOAD_NAME`` resolve the caller's module globals.
    """
    payload = compile_vm(func.func_code, getattr(func, 'func_defaults', None) or ())
    if payload is None:
        return None
    namespace = {}
    if globals_dict is not None:
        namespace.update(globals_dict)
    exec(compile(RUNTIME_SOURCE, '<bytecode_vm_runtime>', 'exec'), namespace)
    _run = namespace['_vm_run']

    def entry(*args, **kwargs):
        return _run(payload, args, kwargs)

    return entry\n