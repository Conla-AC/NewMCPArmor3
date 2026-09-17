# -*- coding: utf-8 -*-
"""Conservative operand-stack analysis for CPython 2.7 instructions."""


from MCP_Armor_Src.core import py27_opcode as opcode


_BINARY_PREFIXES = ('BINARY_', 'INPLACE_')
_UNARY_PREFIXES = ('UNARY_',)


def instruction_stack_effect(item, edge_kind=None):
    name = opcode.opname[item.opcode]
    arg = int(item.argument or 0)

    if name in ('NOP', 'ROT_TWO', 'ROT_THREE', 'ROT_FOUR', 'GET_ITER',
                'POP_BLOCK', 'BREAK_LOOP', 'CONTINUE_LOOP', 'JUMP_FORWARD',
                'JUMP_ABSOLUTE', 'SETUP_LOOP'):
        return 0
    if name == 'POP_TOP':
        return -1
    if name == 'DUP_TOP':
        return 1
    if name == 'DUP_TOPX':
        return arg
    if name.startswith(_UNARY_PREFIXES):
        return 0
    if name.startswith(_BINARY_PREFIXES):
        return -1
    if name in ('SLICE+0',):
        return 0
    if name in ('SLICE+1', 'SLICE+2'):
        return -1
    if name == 'SLICE+3':
        return -2
    if name == 'STORE_SLICE+0':
        return -2
    if name == 'DELETE_SLICE+0':
        return -1
    if name in ('STORE_SLICE+1', 'STORE_SLICE+2'):
        return -3
    if name in ('DELETE_SLICE+1', 'DELETE_SLICE+2'):
        return -2
    if name == 'STORE_SLICE+3':
        return -4
    if name == 'DELETE_SLICE+3':
        return -3
    if name == 'STORE_SUBSCR':
        return -3
    if name == 'DELETE_SUBSCR':
        return -2
    # PRINT_NEWLINE emits the pending print line terminator and consumes no
    # operand.  Omitting it made every ordinary Python 2 print statement fail
    # ByteCode_Flow verification, disabling all downstream block transforms.
    if name in ('PRINT_EXPR', 'PRINT_ITEM', 'PRINT_NEWLINE_TO'):
        return -1
    if name == 'PRINT_NEWLINE':
        return 0
    if name == 'PRINT_ITEM_TO':
        return -2
    if name == 'RETURN_VALUE':
        return -1
    if name == 'YIELD_VALUE':
        return 0
    if name == 'BUILD_CLASS':
        return -2
    if name.startswith('LOAD_'):
        if name == 'LOAD_ATTR':
            return 0
        return 1
    if name.startswith('STORE_'):
        return -2 if name == 'STORE_ATTR' else -1
    if name.startswith('DELETE_'):
        return -1 if name == 'DELETE_ATTR' else 0
    if name == 'UNPACK_SEQUENCE':
        return arg - 1
    if name in ('BUILD_TUPLE', 'BUILD_LIST', 'BUILD_SET'):
        return 1 - arg
    if name == 'BUILD_MAP':
        return 1
    if name == 'STORE_MAP':
        return -2
    if name == 'MAP_ADD':
        return -2
    if name == 'LIST_APPEND' or name == 'SET_ADD':
        return -1
    if name == 'COMPARE_OP':
        return -1
    if name == 'IMPORT_NAME':
        return -1
    if name == 'IMPORT_FROM':
        return 1
    if name == 'IMPORT_STAR':
        return -1
    if name in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE'):
        return -1
    if name in ('JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP'):
        return 0 if edge_kind == 'taken' else -1
    if name == 'FOR_ITER':
        return -1 if edge_kind == 'taken' else 1
    if name == 'RAISE_VARARGS':
        return -arg
    if name == 'CALL_FUNCTION':
        positional = arg & 255
        keywords = (arg >> 8) & 255
        return -(positional + (keywords * 2))
    if name == 'CALL_FUNCTION_VAR':
        positional = arg & 255
        keywords = (arg >> 8) & 255
        return -(positional + (keywords * 2) + 1)
    if name == 'CALL_FUNCTION_KW':
        positional = arg & 255
        keywords = (arg >> 8) & 255
        return -(positional + (keywords * 2) + 1)
    if name == 'CALL_FUNCTION_VAR_KW':
        positional = arg & 255
        keywords = (arg >> 8) & 255
        return -(positional + (keywords * 2) + 2)
    if name == 'MAKE_FUNCTION':
        return -arg
    if name == 'MAKE_CLOSURE':
        return -(arg + 1)
    if name == 'BUILD_SLICE':
        return 1 - arg
    if name in ('EXEC_STMT',):
        return -3
    if name in ('SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH',
                'WITH_CLEANUP', 'END_FINALLY'):
        return None
    return None
