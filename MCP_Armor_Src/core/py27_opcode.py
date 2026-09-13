# -*- coding: utf-8 -*-
"""Frozen CPython 2.7 opcode metadata used by the NetEase target backend.

The MCPArmor host now runs on Python 3.13, whose opcode table is unrelated to
the Python 2.7 bytecode executed by NetEase.  Target transforms must import
this module instead of the host interpreter's :mod:`opcode` module.
"""

HAVE_ARGUMENT = 90

opmap = {
    'STOP_CODE': 0, 'POP_TOP': 1, 'ROT_TWO': 2, 'ROT_THREE': 3,
    'DUP_TOP': 4, 'ROT_FOUR': 5, 'NOP': 9, 'UNARY_POSITIVE': 10,
    'UNARY_NEGATIVE': 11, 'UNARY_NOT': 12, 'UNARY_CONVERT': 13,
    'UNARY_INVERT': 15, 'BINARY_POWER': 19, 'BINARY_MULTIPLY': 20,
    'BINARY_DIVIDE': 21, 'BINARY_MODULO': 22, 'BINARY_ADD': 23,
    'BINARY_SUBTRACT': 24, 'BINARY_SUBSCR': 25,
    'BINARY_FLOOR_DIVIDE': 26, 'BINARY_TRUE_DIVIDE': 27,
    'INPLACE_FLOOR_DIVIDE': 28, 'INPLACE_TRUE_DIVIDE': 29,
    'SLICE+0': 30, 'SLICE+1': 31, 'SLICE+2': 32, 'SLICE+3': 33,
    'STORE_SLICE+0': 40, 'STORE_SLICE+1': 41,
    'STORE_SLICE+2': 42, 'STORE_SLICE+3': 43,
    'DELETE_SLICE+0': 50, 'DELETE_SLICE+1': 51,
    'DELETE_SLICE+2': 52, 'DELETE_SLICE+3': 53,
    'STORE_MAP': 54, 'INPLACE_ADD': 55, 'INPLACE_SUBTRACT': 56,
    'INPLACE_MULTIPLY': 57, 'INPLACE_DIVIDE': 58,
    'INPLACE_MODULO': 59, 'STORE_SUBSCR': 60, 'DELETE_SUBSCR': 61,
    'BINARY_LSHIFT': 62, 'BINARY_RSHIFT': 63, 'BINARY_AND': 64,
    'BINARY_XOR': 65, 'BINARY_OR': 66, 'INPLACE_POWER': 67,
    'GET_ITER': 68, 'PRINT_EXPR': 70, 'PRINT_ITEM': 71,
    'PRINT_NEWLINE': 72, 'PRINT_ITEM_TO': 73, 'PRINT_NEWLINE_TO': 74,
    'INPLACE_LSHIFT': 75, 'INPLACE_RSHIFT': 76, 'INPLACE_AND': 77,
    'INPLACE_XOR': 78, 'INPLACE_OR': 79, 'BREAK_LOOP': 80,
    'WITH_CLEANUP': 81, 'LOAD_LOCALS': 82, 'RETURN_VALUE': 83,
    'IMPORT_STAR': 84, 'EXEC_STMT': 85, 'YIELD_VALUE': 86,
    'POP_BLOCK': 87, 'END_FINALLY': 88, 'BUILD_CLASS': 89,
    'STORE_NAME': 90, 'DELETE_NAME': 91, 'UNPACK_SEQUENCE': 92,
    'FOR_ITER': 93, 'LIST_APPEND': 94, 'STORE_ATTR': 95,
    'DELETE_ATTR': 96, 'STORE_GLOBAL': 97, 'DELETE_GLOBAL': 98,
    'DUP_TOPX': 99, 'LOAD_CONST': 100, 'LOAD_NAME': 101,
    'BUILD_TUPLE': 102, 'BUILD_LIST': 103, 'BUILD_SET': 104,
    'BUILD_MAP': 105, 'LOAD_ATTR': 106, 'COMPARE_OP': 107,
    'IMPORT_NAME': 108, 'IMPORT_FROM': 109, 'JUMP_FORWARD': 110,
    'JUMP_IF_FALSE_OR_POP': 111, 'JUMP_IF_TRUE_OR_POP': 112,
    'JUMP_ABSOLUTE': 113, 'POP_JUMP_IF_FALSE': 114,
    'POP_JUMP_IF_TRUE': 115, 'LOAD_GLOBAL': 116,
    'CONTINUE_LOOP': 119, 'SETUP_LOOP': 120, 'SETUP_EXCEPT': 121,
    'SETUP_FINALLY': 122, 'LOAD_FAST': 124, 'STORE_FAST': 125,
    'DELETE_FAST': 126, 'RAISE_VARARGS': 130, 'CALL_FUNCTION': 131,
    'MAKE_FUNCTION': 132, 'BUILD_SLICE': 133, 'MAKE_CLOSURE': 134,
    'LOAD_CLOSURE': 135, 'LOAD_DEREF': 136, 'STORE_DEREF': 137,
    'CALL_FUNCTION_VAR': 140, 'CALL_FUNCTION_KW': 141,
    'CALL_FUNCTION_VAR_KW': 142, 'SETUP_WITH': 143,
    'EXTENDED_ARG': 145, 'SET_ADD': 146, 'MAP_ADD': 147,
}

opname = ['<%r>' % index for index in range(256)]
for _name, _value in opmap.items():
    opname[_value] = _name

hasconst = [opmap['LOAD_CONST']]
hasname = [opmap[name] for name in (
    'STORE_NAME', 'DELETE_NAME', 'STORE_ATTR', 'DELETE_ATTR',
    'STORE_GLOBAL', 'DELETE_GLOBAL', 'LOAD_NAME', 'LOAD_ATTR',
    'IMPORT_NAME', 'IMPORT_FROM', 'LOAD_GLOBAL')]
hasjrel = [opmap[name] for name in (
    'FOR_ITER', 'JUMP_FORWARD', 'SETUP_LOOP', 'SETUP_EXCEPT',
    'SETUP_FINALLY', 'SETUP_WITH')]
hasjabs = [opmap[name] for name in (
    'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'JUMP_ABSOLUTE',
    'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE', 'CONTINUE_LOOP')]
haslocal = [opmap[name] for name in ('LOAD_FAST', 'STORE_FAST', 'DELETE_FAST')]
hascompare = [opmap['COMPARE_OP']]
hasfree = [opmap[name] for name in (
    'MAKE_CLOSURE', 'LOAD_CLOSURE', 'LOAD_DEREF', 'STORE_DEREF')]

cmp_op = (
    '<', '<=', '==', '!=', '>', '>=', 'in', 'not in', 'is', 'is not',
    'exception match', 'BAD',
)\n