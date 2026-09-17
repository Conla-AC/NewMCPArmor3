# -*- coding: utf-8 -*-
"""Generated source templates for supported loader modes."""



SOURCE_LOADER_TEMPLATE = r'''# -*- coding: utf-8 -*-
%(payload_name)s = [
%(payload_rows)s
]
%(key_name)s = [
%(key_rows)s
]
%(debug_loader_init)s

def %(join_name)s(%(rows_arg)s, %(tag_arg)s):
    %(items_name)s = []
    for %(row_name)s in %(rows_arg)s:
        if %(row_name)s[0] == %(tag_arg)s:
            %(items_name)s.append((%(row_name)s[1], %(row_name)s[2]))
    %(items_name)s.sort(lambda %(left_name)s, %(right_name)s: cmp(%(left_name)s[0], %(right_name)s[0]))
    return ''.join([%(item_name)s[1] for %(item_name)s in %(items_name)s])

def %(str_name)s(%(codes_arg)s):
    return ''.join([chr(%(num_arg)s ^ %(int_xor_key)s) for %(num_arg)s in %(codes_arg)s])

def %(import_name)s(%(codes_arg)s):
    %(builtins_name)s = __builtins__
    if isinstance(%(builtins_name)s, dict):
        return %(builtins_name)s[%(str_name)s(%(import_builtin_code)s)](%(str_name)s(%(codes_arg)s))
    return getattr(%(builtins_name)s, %(str_name)s(%(import_builtin_code)s))(%(str_name)s(%(codes_arg)s))

%(chacha_import_code)s

def %(xor_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr(ord(%(ch_name)s) ^ ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s])))
    return ''.join(%(out_name)s)

def %(add_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr((ord(%(ch_name)s) - ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s])) & 255))
    return ''.join(%(out_name)s)

def %(roll_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr(ord(%(ch_name)s) ^ ((ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s]) + %(idx_name)s) & 255)))
    return ''.join(%(out_name)s)

%(chacha_helper_code)s
%(anti_debug_top_code)s

def %(decode_name)s(%(data_arg)s, %(key_arg)s, %(zlib_name)s):
    for %(op_name)s in reversed(%(ops_repr)s):
        if %(op_name)s == 0:
            %(data_arg)s = %(xor_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 1:
            %(data_arg)s = %(add_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 2:
            %(data_arg)s = %(roll_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 3:
            %(data_arg)s = %(data_arg)s[::-1]
        elif %(op_name)s == 5:
            %(data_arg)s = %(chacha_decode_name)s(%(data_arg)s)
        else:
            %(data_arg)s = %(zlib_name)s(%(data_arg)s)
    return %(data_arg)s

%(loader_noise)s

def %(run_name)s():
%(debug_run_begin)s
    %(b64_name)s = %(import_name)s(%(b64_code)s)
    %(zlib_name)s = %(import_name)s(%(zlib_code)s)
    %(b64decode_name)s = getattr(%(b64_name)s, %(str_name)s(%(b64decode_code)s))
    %(decompress_name)s = getattr(%(zlib_name)s, %(str_name)s(%(decompress_code)s))
    %(adler_name)s = getattr(%(zlib_name)s, %(str_name)s(%(adler_code)s))
%(debug_imports)s
    %(key_arg)s = %(decompress_name)s(%(b64decode_name)s(%(join_name)s(%(key_name)s, %(key_tag)r)))
%(debug_key)s
    %(data_arg)s = %(b64decode_name)s(%(join_name)s(%(payload_name)s, %(payload_tag)r))
%(debug_payload_b64)s
%(anti_debug_pre_code)s
%(payload_seal_code)s
    %(raw_name)s = %(decode_name)s(%(data_arg)s, %(key_arg)s, %(decompress_name)s)
%(debug_payload_decode)s
%(anti_debug_raw_code)s
%(debug_execute_begin)s
    exec %(raw_name)s in globals()
%(debug_execute_done)s

%(run_name)s()
'''


FUNC_LOADER_TEMPLATE = r'''# -*- coding: utf-8 -*-
%(payload_name)s = [
%(payload_rows)s
]
%(key_name)s = [
%(key_rows)s
]
%(decoy_table_name)s = [
%(decoy_rows)s
]
%(opcode_table_name)s = [
%(opcode_rows)s
]
%(fake_mcs_table_name)s = [
%(fake_mcs_rows)s
]
%(lazy_capsule_table_code)s
%(debug_loader_init)s

def %(join_name)s(%(rows_arg)s, %(tag_arg)s):
    %(items_name)s = []
    for %(row_name)s in %(rows_arg)s:
        if %(row_name)s[0] == %(tag_arg)s:
            %(row_key_name)s = %(row_name)s[3]
            %(enc_name)s = %(row_name)s[2][::-1]
            %(buf_name)s = []
            for %(idx_name)s, %(ch_name)s in enumerate(%(enc_name)s):
                %(buf_name)s.append(chr((ord(%(ch_name)s) - ((%(row_key_name)s + %(idx_name)s) & 255)) & 255))
            %(items_name)s.append(((%(row_name)s[1] ^ %(row_key_name)s), ''.join(%(buf_name)s)))
    %(items_name)s.sort(lambda %(left_name)s, %(right_name)s: cmp(%(left_name)s[0], %(right_name)s[0]))
    return ''.join([%(item_name)s[1] for %(item_name)s in %(items_name)s])


def %(str_name)s(%(codes_arg)s):
    return ''.join([chr(%(num_arg)s ^ %(int_xor_key)s) for %(num_arg)s in %(codes_arg)s])

def %(import_name)s(%(codes_arg)s):
    %(builtins_name)s = __builtins__
    if isinstance(%(builtins_name)s, dict):
        return %(builtins_name)s[%(str_name)s(%(import_builtin_code)s)](%(str_name)s(%(codes_arg)s))
    return getattr(%(builtins_name)s, %(str_name)s(%(import_builtin_code)s))(%(str_name)s(%(codes_arg)s))

%(chacha_import_code)s

def %(xor_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr(ord(%(ch_name)s) ^ ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s])))
    return ''.join(%(out_name)s)

def %(add_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr((ord(%(ch_name)s) - ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s])) & 255))
    return ''.join(%(out_name)s)

def %(roll_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr(ord(%(ch_name)s) ^ ((ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s]) + %(idx_name)s) & 255)))
    return ''.join(%(out_name)s)

%(chacha_helper_code)s
%(anti_debug_top_code)s

def %(decode_name)s(%(data_arg)s, %(key_arg)s, %(zlib_name)s):
    for %(op_name)s in reversed(%(ops_repr)s):
        if %(op_name)s == 0:
            %(data_arg)s = %(xor_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 1:
            %(data_arg)s = %(add_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 2:
            %(data_arg)s = %(roll_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 3:
            %(data_arg)s = %(data_arg)s[::-1]
        elif %(op_name)s == 5:
            %(data_arg)s = %(chacha_decode_name)s(%(data_arg)s)
        else:
            %(data_arg)s = %(zlib_name)s(%(data_arg)s)
    return %(data_arg)s

def %(payload_graph_name)s(%(rows_arg)s):
    if not %(payload_graph_enabled)r:
        return %(rows_arg)s
    %(items_name)s = []
    for %(row_name)s in %(rows_arg)s:
        %(row_key_name)s = %(row_name)s[3]
        if len(%(row_name)s) > 5 and ((%(row_name)s[5] ^ %(row_key_name)s) != 1):
            continue
        %(items_name)s.append(((%(row_name)s[1] ^ %(row_key_name)s), %(row_name)s[0]))
    %(items_name)s.sort(lambda %(left_name)s, %(right_name)s: cmp(%(left_name)s[0], %(right_name)s[0]))
    return [%(item_name)s[1] for %(item_name)s in %(items_name)s]

def %(opcode_decode_name)s():
    %(opcode_map_name)s = {}
    %(flat_opcode_map_name)s = {}
    %(opcode_salt_name)s = %(opcode_salt)d
    for %(row_name)s in %(opcode_table_name)s:
        if %(row_name)s[0] == %(opcode_tag)r:
            %(row_key_name)s = %(row_name)s[3]
            %(opcode_from_name)s = (%(row_name)s[1] ^ %(row_key_name)s ^ %(opcode_salt_name)s) & 255
            %(opcode_to_name)s = (%(row_name)s[2] ^ ((%(row_key_name)s + %(opcode_salt_name)s) & 255)) & 255
            if len(%(row_name)s) > 4:
                %(code_id_name)s = (%(row_name)s[4] ^ ((%(row_key_name)s + %(opcode_salt_name)s + 17) & 255))
                if %(code_id_name)s not in %(opcode_map_name)s:
                    %(opcode_map_name)s[%(code_id_name)s] = {}
                %(opcode_map_name)s[%(code_id_name)s][%(opcode_from_name)s] = %(opcode_to_name)s
            else:
                %(flat_opcode_map_name)s[%(opcode_from_name)s] = %(opcode_to_name)s
    if %(per_code_opcode_enabled)r:
        return %(opcode_map_name)s
    return %(flat_opcode_map_name)s

def %(opcode_restore_name)s(%(code_arg)s, %(opcode_map_name)s, %(types_name)s, %(counter_name)s):
    %(restore_noise_code)s
    if %(per_code_opcode_enabled)r:
        %(code_id_name)s = %(counter_name)s[0]
        %(counter_name)s[0] += 1
        %(active_opcode_map_name)s = %(opcode_map_name)s.get(%(code_id_name)s, {})
    else:
        %(active_opcode_map_name)s = %(opcode_map_name)s
    %(consts_name)s = []
    for %(const_name)s in %(code_arg)s.co_consts:
        if isinstance(%(const_name)s, getattr(%(types_name)s, %(str_name)s(%(codetype_code)s))):
            %(const_name)s = %(opcode_restore_name)s(%(const_name)s, %(opcode_map_name)s, %(types_name)s, %(counter_name)s)
        %(consts_name)s.append(%(const_name)s)
    %(src_name)s = %(code_arg)s.co_code
    %(out_name)s = []
    %(pos_name)s = 0
    while %(pos_name)s < len(%(src_name)s):
        %(opv_name)s = ord(%(src_name)s[%(pos_name)s])
        %(out_name)s.append(chr(%(active_opcode_map_name)s.get(%(opv_name)s, %(opv_name)s)))
        %(pos_name)s += 1
        if %(opv_name)s >= %(have_argument)d and %(pos_name)s + 1 < len(%(src_name)s):
            %(out_name)s.append(%(src_name)s[%(pos_name)s])
            %(out_name)s.append(%(src_name)s[%(pos_name)s + 1])
            %(pos_name)s += 2
    return getattr(%(types_name)s, %(str_name)s(%(codetype_code)s))(%(code_arg)s.co_argcount, %(code_arg)s.co_nlocals, %(code_arg)s.co_stacksize, %(code_arg)s.co_flags, ''.join(%(out_name)s), tuple(%(consts_name)s), %(code_arg)s.co_names, %(code_arg)s.co_varnames, %(code_arg)s.co_filename, %(code_arg)s.co_name, %(code_arg)s.co_firstlineno, %(code_arg)s.co_lnotab, %(code_arg)s.co_freevars, %(code_arg)s.co_cellvars)

%(code_tuple_loader_code)s
%(lazy_capsule_top_code)s

%(loader_noise)s
%(fake_ref_code)s
%(loader_decoy_tuple_code)s
%(outer_decompiler_bait_code)s
%(trampoline_code)s
%(facade_top_code)s
%(capsule_top_code)s

def %(run_name)s():
%(facade_cached_code)s
%(debug_run_begin)s
    %(b64_name)s = %(import_name)s(%(b64_code)s)
    %(zlib_name)s = %(import_name)s(%(zlib_code)s)
    %(b64decode_name)s = getattr(%(b64_name)s, %(str_name)s(%(b64decode_code)s))
    %(decompress_name)s = getattr(%(zlib_name)s, %(str_name)s(%(decompress_code)s))
    %(adler_name)s = getattr(%(zlib_name)s, %(str_name)s(%(adler_code)s))
%(debug_imports)s
    %(mask_name)s = %(decompress_name)s(%(b64decode_name)s(%(join_name)s(%(key_name)s, %(mask_tag)r)))
%(debug_key_mask)s
    %(key_arg)s = %(xor_name)s(%(decompress_name)s(%(b64decode_name)s(%(join_name)s(%(key_name)s, %(key_tag)r))), %(mask_name)s)
%(debug_key)s
%(closure_vault_setup_code)s
    %(payload_join_name)s = ''.join([%(join_name)s(%(payload_name)s, %(tag_iter_name)s) for %(tag_iter_name)s in %(payload_graph_name)s(%(payload_tags_repr)s)])
%(debug_payload_graph)s
    %(data_arg)s = %(b64decode_name)s(%(payload_join_name)s)
%(debug_payload_b64)s
%(anti_debug_pre_code)s
%(payload_seal_code)s
    %(raw_name)s = %(decode_name)s(%(data_arg)s, %(runtime_key_expr)s, %(decompress_name)s)
%(debug_payload_decode)s
%(anti_debug_raw_code)s
%(payload_load_code)s
%(debug_code_object)s
    if %(runtime_opcode_enabled)r and not %(fused_code_restore)r:
%(debug_opcode_begin)s
%(runtime_types_import_code)s
        %(code_arg)s = %(opcode_restore_name)s(%(code_arg)s, %(opcode_decode_name)s(), %(types_name)s, [0])
%(debug_opcode_done)s
%(anti_debug_code_code)s
    %(func_type_name)s = (lambda: None).__class__
%(debug_function_type)s
%(facade_exec_pre_code)s
%(lazy_capsule_setup_code)s
    %(module_func_name)s = %(trampoline_entry)s(%(func_type_name)s, %(code_arg)s, %(exec_globals_expr)s)
%(loader_cleanup_code)s
%(debug_execute_begin)s
%(capsule_invoke_code)s
%(debug_execute_done)s
%(metadata_decoy_code)s
%(facade_exec_post_code)s
    return %(func_result_name)s

%(outer_dispatch_code)s
'''


LOADER_TEMPLATE = r'''# -*- coding: utf-8 -*-
%(payload_name)s = [
%(payload_rows)s
]
%(key_name)s = [
%(key_rows)s
]
%(table_name)s = [
%(table_rows)s
]
%(debug_loader_init)s

def %(join_name)s(%(rows_arg)s, %(tag_arg)s):
    %(items_name)s = []
    for %(row_name)s in %(rows_arg)s:
        if %(row_name)s[0] == %(tag_arg)s:
            %(items_name)s.append((%(row_name)s[1], %(row_name)s[2]))
    %(items_name)s.sort(lambda %(left_name)s, %(right_name)s: cmp(%(left_name)s[0], %(right_name)s[0]))
    return ''.join([%(item_name)s[1] for %(item_name)s in %(items_name)s])

def %(str_name)s(%(codes_arg)s):
    return ''.join([chr(%(num_arg)s ^ %(int_xor_key)s) for %(num_arg)s in %(codes_arg)s])

def %(import_name)s(%(codes_arg)s):
    %(builtins_name)s = __builtins__
    if isinstance(%(builtins_name)s, dict):
        return %(builtins_name)s[%(str_name)s(%(import_builtin_code)s)](%(str_name)s(%(codes_arg)s))
    return getattr(%(builtins_name)s, %(str_name)s(%(import_builtin_code)s))(%(str_name)s(%(codes_arg)s))

%(chacha_import_code)s

def %(xor_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr(ord(%(ch_name)s) ^ ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s])))
    return ''.join(%(out_name)s)

def %(add_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr((ord(%(ch_name)s) - ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s])) & 255))
    return ''.join(%(out_name)s)

def %(roll_name)s(%(data_arg)s, %(key_arg)s):
    %(out_name)s = []
    %(key_len_name)s = len(%(key_arg)s)
    for %(idx_name)s, %(ch_name)s in enumerate(%(data_arg)s):
        %(out_name)s.append(chr(ord(%(ch_name)s) ^ ((ord(%(key_arg)s[%(idx_name)s %% %(key_len_name)s]) + %(idx_name)s) & 255)))
    return ''.join(%(out_name)s)

%(chacha_helper_code)s
%(anti_debug_top_code)s

def %(decode_name)s(%(data_arg)s, %(key_arg)s, %(zlib_name)s):
    for %(op_name)s in reversed(%(ops_repr)s):
        if %(op_name)s == 0:
            %(data_arg)s = %(xor_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 1:
            %(data_arg)s = %(add_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 2:
            %(data_arg)s = %(roll_name)s(%(data_arg)s, %(key_arg)s)
        elif %(op_name)s == 3:
            %(data_arg)s = %(data_arg)s[::-1]
        elif %(op_name)s == 5:
            %(data_arg)s = %(chacha_decode_name)s(%(data_arg)s)
        else:
            %(data_arg)s = %(zlib_name)s(%(data_arg)s)
    return %(data_arg)s

def %(table_decode_name)s():
    %(tbl_name)s = {}
    %(salt_name)s = %(table_salt)d
    for %(row_name)s in %(table_name)s:
        if %(row_name)s[0] == %(table_tag)r:
            %(tbl_name)s[(%(row_name)s[1] ^ %(salt_name)s) & 255] = (%(row_name)s[2] ^ ((%(salt_name)s * 3) & 255)) & 255
    return %(tbl_name)s

def %(restore_name)s(%(code_arg)s, %(table_arg)s, %(types_name)s):
    %(consts_name)s = []
    for %(const_name)s in %(code_arg)s.co_consts:
        if isinstance(%(const_name)s, getattr(%(types_name)s, %(str_name)s(%(codetype_code)s))):
            %(const_name)s = %(restore_name)s(%(const_name)s, %(table_arg)s, %(types_name)s)
        %(consts_name)s.append(%(const_name)s)
    %(src_name)s = %(code_arg)s.co_code
    %(out_name)s = []
    %(pos_name)s = 0
    while %(pos_name)s < len(%(src_name)s):
        %(opv_name)s = ord(%(src_name)s[%(pos_name)s])
        %(out_name)s.append(chr(%(table_arg)s.get(%(opv_name)s, %(opv_name)s)))
        %(pos_name)s += 1
        if %(opv_name)s >= %(have_argument)d and %(pos_name)s + 1 < len(%(src_name)s):
            %(out_name)s.append(%(src_name)s[%(pos_name)s])
            %(out_name)s.append(%(src_name)s[%(pos_name)s + 1])
            %(pos_name)s += 2
    return getattr(%(types_name)s, %(str_name)s(%(codetype_code)s))(
        %(code_arg)s.co_argcount, %(code_arg)s.co_nlocals, %(code_arg)s.co_stacksize,
        %(code_arg)s.co_flags, ''.join(%(out_name)s), tuple(%(consts_name)s),
        %(code_arg)s.co_names, %(code_arg)s.co_varnames, %(code_arg)s.co_filename,
        %(code_arg)s.co_name, %(code_arg)s.co_firstlineno, %(code_arg)s.co_lnotab,
        %(code_arg)s.co_freevars, %(code_arg)s.co_cellvars)

%(code_tuple_loader_code)s

def %(run_name)s():
%(debug_run_begin)s
    %(b64_name)s = %(import_name)s(%(b64_code)s)
    %(zlib_name)s = %(import_name)s(%(zlib_code)s)
    %(b64decode_name)s = getattr(%(b64_name)s, %(str_name)s(%(b64decode_code)s))
    %(decompress_name)s = getattr(%(zlib_name)s, %(str_name)s(%(decompress_code)s))
    %(adler_name)s = getattr(%(zlib_name)s, %(str_name)s(%(adler_code)s))
%(debug_imports)s
    %(key_arg)s = %(decompress_name)s(%(b64decode_name)s(%(join_name)s(%(key_name)s, %(key_tag)r)))
%(debug_key)s
    %(data_arg)s = %(b64decode_name)s(%(join_name)s(%(payload_name)s, %(payload_tag)r))
%(debug_payload_b64)s
%(anti_debug_pre_code)s
%(payload_seal_code)s
    %(raw_name)s = %(decode_name)s(%(data_arg)s, %(key_arg)s, %(decompress_name)s)
%(debug_payload_decode)s
%(anti_debug_raw_code)s
%(payload_load_code)s
%(debug_code_object)s
    if %(tunnel_enabled)r:
%(debug_opcode_begin)s
%(tunnel_types_import_code)s
        %(code_arg)s = %(restore_name)s(%(code_arg)s, %(table_decode_name)s(), %(types_name)s)
%(debug_opcode_done)s
%(anti_debug_code_code)s
%(debug_execute_begin)s
    exec %(code_arg)s in globals()
%(debug_execute_done)s

%(loader_noise)s
%(run_name)s()
'''
