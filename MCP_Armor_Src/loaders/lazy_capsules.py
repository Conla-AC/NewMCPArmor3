# -*- coding: utf-8 -*-
"""Lazy capsule payload and hydration loader generation."""


import base64
import random

from MCP_Armor_Src.loaders.code_tuple import (
    dumps_code_payload,
)

from MCP_Armor_Src.utils.encoding import (
    chunk_text,
    encode_payload,
    random_bytes,
    random_ident,
)


def dumps_code_payload_with_options(code, options, stored_to_std=None):
    return dumps_code_payload(
        code, options.code_tuple_payload, options.code_bytes_split,
        options.code_bytes_split_min, options.code_bytes_split_max_chunks,
        options.code_bytes_fake_chunks, options.code_ref_table,
        options.code_tuple_field_shuffle, options.code_ref_decoys,
        options.code_ref_wide_rows, options.code_ref_mask_markers,
        options.code_tuple_fragments,
        options.code_tuple_fragment_providers,
        options.code_tuple_provider_graph,
        options.code_tuple_provider_decoys, options.code_global_arena,
        options.code_template_delta, options.code_global_arena_decoys,
        options.code_block_relocation, options.code_block_reloc_decoys,
        stored_to_std, options.code_unit_arena,
        options.code_unit_arena_decoys, options.code_operand_graph,
        options.code_const_arena, options.code_const_arena_decoys,
        options.code_const_provider_graph, options.code_const_arena_limit,
        options.code_field_descriptors, options.code_provider_context_bind)


def build_lazy_capsule_loader_parts(entries, options, names,
                                    stored_to_std=None, binding_key=None,
                                    runtime_key_expr=None):
    if not entries:
        return {
            'lazy_capsule_table_code': '',
            'lazy_capsule_top_code': '',
            'lazy_capsule_setup_code': '',
        }
    records = []
    mode_codes = {'call': 0, 'once': 1, 'count': 2}
    binding_enabled = bool(
        getattr(options, 'lazy_capsule_cross_key', False) and binding_key)
    for entry in entries:
        raw = dumps_code_payload_with_options(
            entry['code'], options, stored_to_std)
        key = random_bytes(max(8, options.key_len))
        encoded, ops = encode_payload(raw, key, options.compress_level)
        encoded_text = base64.b64encode(encoded)
        chunks = chunk_text(
            encoded_text, max(16, options.chunk_min),
            max(32, options.chunk_max))
        chunk_rows = []
        for index, chunk in enumerate(chunks):
            row_mask = random.randint(1, 0x7fffffff)
            chunk_rows.append((index ^ row_mask, chunk[::-1], row_mask,
                               random.randint(0x1000, 0x7fffffff)))
        random.shuffle(chunk_rows)
        key_mask = random.randint(1, 255)
        bind_salt = random.randint(1, 0x7fffffff)
        if binding_enabled:
            key_values = tuple(
                ord(value) ^ ((key_mask + index * 17) & 255) ^
                ord(binding_key[(index * 7 + bind_salt) % len(binding_key)])
                for index, value in enumerate(key))
        else:
            key_values = tuple(
                ord(value) ^ ((key_mask + index * 17) & 255)
                for index, value in enumerate(key))
        id_mask = random.randint(0x10000, 0x7fffffff)
        records.append((
            int(entry['id']) ^ id_mask, id_mask, tuple(chunk_rows),
            key_values, key_mask, tuple(ops),
            mode_codes.get(entry.get('mode'), 2),
            max(1, int(entry.get('retain_calls', 1))),
            random.randint(0x10000, 0x7fffffff),
            bind_salt,
            1 if binding_enabled else 0,
        ))
    random.shuffle(records)

    table_name = names['lazy_table_name']
    factory_name = names['lazy_factory_name']
    manager_local = names['lazy_manager_local']
    manager_public = names['lazy_manager_public']
    table_arg = random_ident('lazy_rows')
    globals_arg = random_ident('lazy_globals')
    function_arg = random_ident('lazy_function')
    pickle_arg = random_ident('lazy_pickle')
    types_arg = random_ident('lazy_types')
    b64_arg = random_ident('lazy_b64')
    zlib_arg = random_ident('lazy_zlib')
    loader_arg = random_ident('lazy_loader')
    binding_arg = random_ident('lazy_binding')
    states_name = random_ident('lazy_states')
    record_name = random_ident('lazy_record')
    capsule_name = random_ident('lazy_id')
    state_name = random_ident('lazy_state')
    args_name = random_ident('lazy_args')
    kwargs_name = random_ident('lazy_kwargs')
    function_name = random_ident('lazy_real')
    rows_name = random_ident('lazy_chunks')
    row_name = random_ident('lazy_chunk')
    joined_name = random_ident('lazy_joined')
    data_name = random_ident('lazy_data')
    key_list_name = random_ident('lazy_keybuf')
    key_name = random_ident('lazy_key')
    index_name = random_ident('lazy_index')
    value_name = random_ident('lazy_value')
    op_name = random_ident('lazy_op')
    out_name = random_ident('lazy_out')
    char_name = random_ident('lazy_char')
    code_name = random_ident('lazy_code')
    called_name = random_ident('lazy_called')
    bootstrap_name = random_ident('lazy_bootstrap')
    bootstrap_mask_name = random_ident('lazy_bootmask')
    epoch_name = random_ident('lazy_epoch')
    next_epoch_name = random_ident('lazy_next_epoch')
    rotate_key_list_name = random_ident('lazy_rotate_keybuf')
    rotate_key_name = random_ident('lazy_rotate_key')
    rotate_data_name = random_ident('lazy_rotate_data')
    rotate_out_name = random_ident('lazy_rotate_out')
    rotate_rows_name = random_ident('lazy_rotate_rows')
    rotate_count_name = random_ident('lazy_rotate_count')
    rotate_size_name = random_ident('lazy_rotate_size')
    rotate_chunk_name = random_ident('lazy_rotate_chunk')
    rotate_mask_name = random_ident('lazy_rotate_mask')
    rotate_key_mask_name = random_ident('lazy_rotate_keymask')
    rotated_name = random_ident('lazy_rotated')
    carrier_seed_name = random_ident('lazy_carrier_seed')
    carrier_code_name = random_ident('lazy_carrier_code')
    carrier_name = random_ident('lazy_carrier')
    carrier_args_name = random_ident('lazy_carrier_args')
    carrier_kwargs_name = random_ident('lazy_carrier_kwargs')
    carrier_enabled = bool(
        getattr(options, 'lazy_capsule_carrier_swap', False))
    carrier_route_enabled = bool(
        carrier_enabled and
        getattr(options, 'lazy_capsule_carrier_route_rotation', False))
    carrier_route_name = random_ident('lazy_carrier_route')
    carrier_route_arg_name = random_ident('lazy_carrier_route_arg')
    carrier_route_used_name = random_ident('lazy_carrier_route_used')
    carrier_new_code_name = random_ident('lazy_carrier_new_code')
    carrier_code_attr_name = random_ident('lazy_carrier_code_attr')
    carrier_name_attr_name = random_ident('lazy_carrier_name_attr')
    carrier_attr_value_name = random_ident('lazy_carrier_attr_value')
    carrier_attr_key = random.randint(1, 255)
    carrier_code_attr_codes = tuple(
        ord(value) ^ carrier_attr_key for value in 'func_code')
    carrier_name_attr_codes = tuple(
        ord(value) ^ carrier_attr_key for value in 'func_name')
    manager_proxy_enabled = bool(
        getattr(options, 'lazy_capsule_manager_proxy', False))
    manager_proxy_class_name = random_ident('lazy_manager_proxy_class')
    manager_proxy_call_name = random_ident('lazy_manager_proxy_call')
    manager_proxy_getattr_name = random_ident('lazy_manager_proxy_getattr')
    manager_proxy_reduce_name = random_ident('lazy_manager_proxy_reduce')
    manager_proxy_reduce_ex_name = random_ident('lazy_manager_proxy_reduce_ex')
    manager_proxy_copy_name = random_ident('lazy_manager_proxy_copy')
    manager_proxy_deepcopy_name = random_ident('lazy_manager_proxy_deepcopy')
    manager_proxy_repr_name = random_ident('lazy_manager_proxy_repr')
    manager_proxy_self_name = random_ident('lazy_manager_proxy_self')
    manager_proxy_attr_name = random_ident('lazy_manager_proxy_attr')
    manager_proxy_proto_name = random_ident('lazy_manager_proxy_proto')
    manager_proxy_memo_name = random_ident('lazy_manager_proxy_memo')
    manager_proxy_label = random_ident('LazyCapsuleGate')
    manager_proxy_decoy_key = random_ident('sealed_state')
    manager_proxy_decoy_value = random.randint(0x10000, 0x7fffffff)
    manager_proxy_blocked_name = random_ident('lazy_manager_blocked')
    manager_proxy_blocked_row_name = random_ident('lazy_manager_blocked_row')
    manager_proxy_blocked_value_name = random_ident('lazy_manager_blocked_value')
    manager_proxy_blocked_key = random.randint(1, 255)
    manager_proxy_blocked_rows = tuple(
        tuple(ord(ch) ^ manager_proxy_blocked_key for ch in value)
        for value in ('func_code', 'func_closure', '__closure__', 'im_func',
                      'gi_frame', 'f_locals'))
    sort_left_name = random_ident('lazy_sort_left')
    sort_right_name = random_ident('lazy_sort_right')
    b64decode_fn_name = random_ident('lazy_b64decode')
    decompress_fn_name = random_ident('lazy_decompress')

    lines = [
        'def %s(%s, %s, %s, %s, %s, %s, %s, %s, %s):' % (
            factory_name, table_arg, globals_arg, function_arg, pickle_arg,
            types_arg, b64_arg, zlib_arg, loader_arg, binding_arg),
        '    %s = getattr(%s, %s(%s))' % (
            b64decode_fn_name, b64_arg, names['str_name'],
            names['b64decode_code']),
        '    %s = getattr(%s, %s(%s))' % (
            decompress_fn_name, zlib_arg, names['str_name'],
            names['decompress_code']),
    ]
    if carrier_enabled:
        lines.extend([
            '    def %s(*%s, **%s):' % (
                carrier_seed_name, carrier_args_name, carrier_kwargs_name),
            '        return None',
        ])
        if carrier_route_enabled:
            lines.extend([
                "    %s = ''.join(chr(%s ^ %d) for %s in %r)" % (
                    carrier_code_attr_name, carrier_attr_value_name,
                    carrier_attr_key, carrier_attr_value_name,
                    carrier_code_attr_codes),
                "    %s = ''.join(chr(%s ^ %d) for %s in %r)" % (
                    carrier_name_attr_name, carrier_attr_value_name,
                    carrier_attr_key, carrier_attr_value_name,
                    carrier_name_attr_codes),
                '    %s = getattr(%s, %s)' % (
                    carrier_code_name, carrier_seed_name,
                    carrier_code_attr_name),
                '    def %s(%s, %s, %s):' % (
                    carrier_route_name, carrier_name,
                    carrier_new_code_name, carrier_route_arg_name),
                '        %s = %s %% 3' % (
                    carrier_route_used_name, carrier_route_arg_name),
                '        if %s == 0:' % carrier_route_used_name,
                '            setattr(%s, %s, %s)' % (
                    carrier_name, carrier_code_attr_name,
                    carrier_new_code_name),
                '        elif %s == 1:' % carrier_route_used_name,
                '            getattr(%s, %s).__set__(%s, %s)' % (
                    function_arg, carrier_code_attr_name, carrier_name,
                    carrier_new_code_name),
                '        else:',
                '            %s.__setattr__(%s, %s, %s)' % (
                    function_arg, carrier_name, carrier_code_attr_name,
                    carrier_new_code_name),
                '        try:',
                '            setattr(%s, %s, %s.co_name)' % (
                    carrier_name, carrier_name_attr_name,
                    carrier_new_code_name),
                '        except Exception:',
                '            pass',
                '        return (%s + 1) %% 3' % carrier_route_used_name,
            ])
        else:
            lines.append('    %s = %s.func_code' % (
                carrier_code_name, carrier_seed_name))
    lines.extend([
        '    %s = {}' % states_name,
        '    for %s in %s:' % (record_name, table_arg),
        '        %s = list(%s)' % (record_name, record_name),
        '        %s = %s[0] ^ %s[1]' % (
            capsule_name, record_name, record_name),
        '        if %s[10] and %s:' % (record_name, binding_arg),
        '            %s = []' % key_list_name,
        '            for %s, %s in enumerate(%s[3]):' % (
            index_name, value_name, record_name),
        '                %s.append(chr(%s ^ ((%s[4] + %s * 17) & 255) ^ ord(%s[(%s * 7 + %s[9]) %% len(%s)])))' % (
            key_list_name, value_name, record_name, index_name,
            binding_arg, index_name, record_name, binding_arg),
        "            %s = ''.join(%s)" % (bootstrap_name, key_list_name),
        '            %s = (id(%s) ^ %s ^ %s[8]) & 255' % (
            bootstrap_mask_name, globals_arg, capsule_name, record_name),
        '            %s[3] = tuple(ord(%s) ^ ((%s + %s * 17) & 255) for %s, %s in enumerate(%s))' % (
            record_name, char_name, bootstrap_mask_name, index_name,
            index_name, char_name, bootstrap_name),
        '            %s[4] = %s' % (record_name, bootstrap_mask_name),
        '            %s[10] = 0' % record_name,
        '            for %s in range(len(%s)):' % (index_name, key_list_name),
        "                %s[%s] = '\\x00'" % (key_list_name, index_name),
        '            %s = None' % bootstrap_name,
    ])
    if carrier_enabled:
        lines.extend([
            "        %s = %s(%s, %s, '_' + str(%s))" % (
                carrier_name, function_arg, carrier_code_name,
                globals_arg, capsule_name),
            '        %s[%s] = [%s, None, %s[7], None, 0, %s, (%s ^ %s[8] ^ %s[9]) %% 3]' % (
                states_name, capsule_name, record_name, record_name,
                carrier_name, capsule_name, record_name, record_name),
        ])
    else:
        lines.append(
            '        %s[%s] = [%s, None, %s[7], None, 0, None, 0]' % (
                states_name, capsule_name, record_name, record_name))
    lines.extend([
        '    %s = None' % binding_arg,
        '    def %s(%s, %s, %s):' % (
            manager_public, capsule_name, args_name, kwargs_name),
        '        %s = %s[%s]' % (state_name, states_name, capsule_name),
        '        if %s[3] is not None:' % state_name,
        '            return %s[3](*%s, **%s)' % (
            state_name, args_name, kwargs_name),
        '        %s = %s[0]' % (record_name, state_name),
        '        %s = %s[1]' % (function_name, state_name),
        '        %s = []' % key_list_name,
        '        %s = None' % data_name,
        '        %s = False' % called_name,
        '        try:',
        '            if %s is None:' % function_name,
        '                %s = list(%s[2])' % (rows_name, record_name),
        '                %s.sort(lambda %s, %s: cmp(%s[0] ^ %s[2], %s[0] ^ %s[2]))' % (
            rows_name, sort_left_name, sort_right_name,
            sort_left_name, sort_left_name,
            sort_right_name, sort_right_name),
        "                %s = ''.join([%s[1][::-1] for %s in %s])" % (
            joined_name, row_name, row_name, rows_name),
        '                %s = %s(%s)' % (
            data_name, b64decode_fn_name, joined_name),
        '                for %s, %s in enumerate(%s[3]):' % (
            index_name, value_name, record_name),
        '                    %s.append(chr(%s ^ ((%s[4] + %s * 17) & 255)))' % (
            key_list_name, value_name, record_name, index_name),
        "                %s = ''.join(%s)" % (key_name, key_list_name),
        '                for %s in reversed(%s[5]):' % (op_name, record_name),
        '                    if %s == 0:' % op_name,
        '                        %s = %s(%s, %s)' % (
            data_name, names['xor_name'], data_name, key_name),
        '                    elif %s == 1:' % op_name,
        '                        %s = %s(%s, %s)' % (
            data_name, names['add_name'], data_name, key_name),
        '                    elif %s == 2:' % op_name,
        '                        %s = %s(%s, %s)' % (
            data_name, names['roll_name'], data_name, key_name),
        '                    elif %s == 3:' % op_name,
        '                        %s = %s[::-1]' % (data_name, data_name),
        '                    else:',
        '                        %s = %s(%s)' % (
            data_name, decompress_fn_name, data_name),
        '                %s = %s(%s, %s, %s)' % (
            code_name, loader_arg, data_name, pickle_arg, types_arg),
    ])
    rotate_enabled = bool(
        getattr(options, 'lazy_capsule_rotate_payload', False) and
        int(getattr(options, 'lazy_capsule_rotate_max_bytes', 0) or 0) > 0)
    if rotate_enabled:
        rotate_max_bytes = max(
            1, min(16 * 1024 * 1024,
                   int(options.lazy_capsule_rotate_max_bytes)))
        lines.extend([
            '                if len(%s) <= %d:' % (
                data_name, rotate_max_bytes),
            '                    %s = []' % rotate_key_list_name,
            '                    %s = None' % rotate_key_name,
            '                    %s = None' % rotate_data_name,
            '                    %s = []' % rotate_out_name,
            '                    %s = False' % rotated_name,
            '                    try:',
            '                        %s = %s[4] + 1' % (
                next_epoch_name, state_name),
            '                        for %s, %s in enumerate(%s):' % (
                index_name, char_name, key_name),
            '                            %s.append(chr(ord(%s) ^ ((%s + %s * 131 + %s * 29 + %s[8]) & 255)))' % (
                rotate_key_list_name, char_name, capsule_name,
                next_epoch_name, index_name, record_name),
            "                        %s = ''.join(%s)" % (
                rotate_key_name, rotate_key_list_name),
            '                        %s = %s.compress(%s, 9)' % (
                rotate_data_name, zlib_arg, data_name),
            '                        %s = %s(%s, %s)' % (
                rotate_data_name, names['xor_name'], rotate_data_name,
                rotate_key_name),
            '                        for %s, %s in enumerate(%s):' % (
                index_name, char_name, rotate_data_name),
            '                            %s.append(chr((ord(%s) + ord(%s[%s %% len(%s)])) & 255))' % (
                rotate_out_name, char_name, rotate_key_name, index_name,
                rotate_key_name),
            "                        %s = ''.join(%s)" % (
                rotate_data_name, rotate_out_name),
            '                        %s = %s(%s, %s)' % (
                rotate_data_name, names['roll_name'], rotate_data_name,
                rotate_key_name),
            '                        %s = %s.b64encode(%s[::-1])' % (
                joined_name, b64_arg, rotate_data_name),
            '                        %s = max(1, len(%s[2]))' % (
                rotate_count_name, record_name),
            '                        %s = max(1, (len(%s) + %s - 1) // %s)' % (
                rotate_size_name, joined_name, rotate_count_name,
                rotate_count_name),
            '                        %s = []' % rotate_rows_name,
            '                        for %s in range(%s):' % (
                index_name, rotate_count_name),
            '                            %s = %s[%s * %s:(%s + 1) * %s]' % (
                rotate_chunk_name, joined_name, index_name,
                rotate_size_name, index_name, rotate_size_name),
            '                            if not %s:' % rotate_chunk_name,
            '                                break',
            '                            %s = (%s ^ (%s * 1103515245) ^ (%s * 2654435761) ^ %s[8]) & 0x7fffffff' % (
                rotate_mask_name, capsule_name, next_epoch_name,
                index_name, record_name),
            '                            if not %s:' % rotate_mask_name,
            '                                %s = %s + 1' % (
                rotate_mask_name, index_name),
            '                            %s.append((%s ^ %s, %s[::-1], %s, (%s ^ %s ^ %s[8]) & 0x7fffffff))' % (
                rotate_rows_name, index_name, rotate_mask_name,
                rotate_chunk_name, rotate_mask_name, capsule_name,
                next_epoch_name, record_name),
            '                        %s.reverse()' % rotate_rows_name,
            '                        %s = (%s ^ %s ^ %s[8]) & 255' % (
                rotate_key_mask_name, capsule_name, next_epoch_name,
                record_name),
            '                        %s = tuple(ord(%s) ^ ((%s + %s * 17) & 255) for %s, %s in enumerate(%s))' % (
                bootstrap_name, char_name, rotate_key_mask_name,
                index_name, index_name, char_name, rotate_key_name),
            '                        %s[2] = tuple(%s)' % (
                record_name, rotate_rows_name),
            '                        %s[3] = %s' % (
                record_name, bootstrap_name),
            '                        %s[4] = %s' % (
                record_name, rotate_key_mask_name),
            '                        %s[4] = %s' % (
                state_name, next_epoch_name),
            '                        %s = True' % rotated_name,
            '                    except Exception:',
            '                        pass',
            '                    finally:',
            '                        for %s in range(len(%s)):' % (
                index_name, rotate_key_list_name),
            "                            %s[%s] = '\\x00'" % (
                rotate_key_list_name, index_name),
            '                        %s = None' % rotate_key_name,
            '                        %s = None' % rotate_data_name,
            '                        %s = []' % rotate_out_name,
            '                        %s = []' % rotate_rows_name,
        ])
        if options.lazy_capsule_debug or options.debug:
            lines.extend([
                '                    if %s:' % rotated_name,
                "                        print('[DEBUG] MCP LazyCapsule Rotated', %s, %s[4])" % (
                    capsule_name, state_name),
            ])
    if carrier_enabled:
        lines.append('                %s = %s[5]' % (
            function_name, state_name))
        if carrier_route_enabled:
            lines.extend([
                '                %s = %s[6] %% 3' % (
                    carrier_route_used_name, state_name),
                '                %s[6] = %s(%s, %s, %s[6])' % (
                    state_name, carrier_route_name, function_name,
                    code_name, state_name),
            ])
        else:
            lines.extend([
                '                %s.func_code = %s' % (
                    function_name, code_name),
                '                try:',
                '                    %s.func_name = %s.co_name' % (
                    function_name, code_name),
                '                except Exception:',
                '                    pass',
            ])
        if options.lazy_capsule_debug or options.debug:
            if carrier_route_enabled:
                lines.append(
                    "                print('[DEBUG] MCP LazyCapsule CarrierSwap', %s, 'route', %s)" %
                    (capsule_name, carrier_route_used_name))
            else:
                lines.append(
                    "                print('[DEBUG] MCP LazyCapsule CarrierSwap', %s)" %
                    capsule_name)
    else:
        lines.append(
            '                %s = %s(%s, %s, %s.co_name)' % (
                function_name, function_arg, code_name, globals_arg,
                code_name))
    lines.extend([
        '                if %s[6] in (1, 2):' % record_name,
        '                    %s[1] = %s' % (state_name, function_name),
    ])
    if options.lazy_capsule_debug or options.debug:
        lines.append("                print('[DEBUG] MCP LazyCapsule Hydrated', %s)" % capsule_name)
    lines.extend([
        '            %s[3] = %s' % (state_name, function_name),
        '            %s = True' % called_name,
        '            return %s(*%s, **%s)' % (
            function_name, args_name, kwargs_name),
        '        finally:',
        '            %s[3] = None' % state_name,
        '            for %s in range(len(%s)):' % (
            index_name, key_list_name),
        "                %s[%s] = '\\x00'" % (key_list_name, index_name),
        '            %s = None' % data_name,
        '            %s = None' % key_name,
        '            %s = None' % code_name,
        '            if %s:' % called_name,
        '                if %s[6] == 0:' % record_name,
        '                    %s[1] = None' % state_name,
    ])
    if carrier_enabled:
        if carrier_route_enabled:
            lines.extend([
                '                    %s = %s[6] %% 3' % (
                    carrier_route_used_name, state_name),
                '                    %s[6] = %s(%s[5], %s, %s[6])' % (
                    state_name, carrier_route_name, state_name,
                    carrier_code_name, state_name),
            ])
        else:
            lines.extend([
                '                    %s[5].func_code = %s' % (
                    state_name, carrier_code_name),
                '                    try:',
                '                        %s[5].func_name = %s.co_name' % (
                    state_name, carrier_code_name),
                '                    except Exception:',
                '                        pass',
            ])
        if options.lazy_capsule_debug or options.debug:
            if carrier_route_enabled:
                lines.append(
                    "                    print('[DEBUG] MCP LazyCapsule CarrierRestored', %s, 'route', %s)" %
                    (capsule_name, carrier_route_used_name))
            else:
                lines.append(
                    "                    print('[DEBUG] MCP LazyCapsule CarrierRestored', %s)" %
                    capsule_name)
    lines.extend([
        '                elif %s[6] == 2:' % record_name,
        '                    %s[2] -= 1' % state_name,
        '                    if %s[2] <= 0:' % state_name,
        '                        %s[1] = None' % state_name,
        '                        %s[2] = %s[7]' % (state_name, record_name),
    ])
    if carrier_enabled:
        if carrier_route_enabled:
            lines.extend([
                '                        %s = %s[6] %% 3' % (
                    carrier_route_used_name, state_name),
                '                        %s[6] = %s(%s[5], %s, %s[6])' % (
                    state_name, carrier_route_name, state_name,
                    carrier_code_name, state_name),
            ])
        else:
            lines.extend([
                '                        %s[5].func_code = %s' % (
                    state_name, carrier_code_name),
                '                        try:',
                '                            %s[5].func_name = %s.co_name' % (
                    state_name, carrier_code_name),
                '                        except Exception:',
                '                            pass',
            ])
    if options.lazy_capsule_debug or options.debug:
        lines.extend([
            '                        print(\'[DEBUG] MCP LazyCapsule Evicted\', %s)' % capsule_name,
        ])
    if manager_proxy_enabled:
        lines.extend([
            "    %s = tuple(''.join(chr(%s ^ %d) for %s in %s) for %s in %r)" % (
                manager_proxy_blocked_name, manager_proxy_blocked_value_name,
                manager_proxy_blocked_key, manager_proxy_blocked_value_name,
                manager_proxy_blocked_row_name, manager_proxy_blocked_row_name,
                manager_proxy_blocked_rows),
            '    def %s(%s, %s, %s, %s):' % (
                manager_proxy_call_name, manager_proxy_self_name,
                capsule_name, args_name, kwargs_name),
            '        return %s(%s, %s, %s)' % (
                manager_public, capsule_name, args_name, kwargs_name),
            '    def %s(%s, %s):' % (
                manager_proxy_getattr_name, manager_proxy_self_name,
                manager_proxy_attr_name),
            '        if %s == %r:' % (
                manager_proxy_attr_name, '__dict__'),
            '            return {%r: %d}' % (
                manager_proxy_decoy_key, manager_proxy_decoy_value),
            '        if %s in %s:' % (
                manager_proxy_attr_name, manager_proxy_blocked_name),
            '            raise AttributeError(%s)' % manager_proxy_attr_name,
            '        return object.__getattribute__(%s, %s)' % (
                manager_proxy_self_name, manager_proxy_attr_name),
            '    def %s(%s):' % (
                manager_proxy_reduce_name, manager_proxy_self_name),
            "        raise TypeError('sealed capsule gate')",
            '    def %s(%s, %s):' % (
                manager_proxy_reduce_ex_name, manager_proxy_self_name,
                manager_proxy_proto_name),
            '        return %s(%s)' % (
                manager_proxy_reduce_name, manager_proxy_self_name),
            '    def %s(%s):' % (
                manager_proxy_copy_name, manager_proxy_self_name),
            '        return %s' % manager_proxy_self_name,
            '    def %s(%s, %s):' % (
                manager_proxy_deepcopy_name, manager_proxy_self_name,
                manager_proxy_memo_name),
            '        try:',
            '            %s[id(%s)] = %s' % (
                manager_proxy_memo_name, manager_proxy_self_name,
                manager_proxy_self_name),
            '        except Exception:',
            '            pass',
            '        return %s' % manager_proxy_self_name,
            '    def %s(%s):' % (
                manager_proxy_repr_name, manager_proxy_self_name),
            '        return %r' % ('<%s sealed>' % manager_proxy_label),
            '    %s = type(%r, (object,), {%r: %s, %r: %s, %r: %s, %r: %s, %r: %s, %r: %s, %r: %s})' % (
                manager_proxy_class_name, manager_proxy_label,
                '__call__', manager_proxy_call_name,
                '__getattribute__', manager_proxy_getattr_name,
                '__reduce__', manager_proxy_reduce_name,
                '__reduce_ex__', manager_proxy_reduce_ex_name,
                '__copy__', manager_proxy_copy_name,
                '__deepcopy__', manager_proxy_deepcopy_name,
                '__repr__', manager_proxy_repr_name),
        ])
        if options.lazy_capsule_debug or options.debug:
            lines.append(
                "    print('[DEBUG] MCP LazyCapsule ManagerProxy Loaded')")
        lines.append('    return %s()' % manager_proxy_class_name)
    else:
        lines.append('    return %s' % manager_public)

    module_key_expr = runtime_key_expr or names['key_arg']
    setup_lines = [
        '    %s = %s(%s, %s, %s, %s, %s, %s, %s, %s, %s)' % (
            manager_local, factory_name, table_name, names['exec_globals_expr'],
            names['func_type_name'], names['pickle_name'], names['types_name'],
            names['b64_name'], names['zlib_name'], names['code_tuple_load_name'],
            module_key_expr),
        '    %s[%r] = %s' % (
            names['exec_globals_expr'], manager_public, manager_local),
        '    %s[:] = []' % table_name,
    ]
    if options.lazy_capsule_debug or options.debug:
        setup_lines.append("    print('[DEBUG] MCP LazyCapsule Registry Loaded', %d)" % len(entries))
    return {
        'lazy_capsule_table_code': '%s = %r' % (table_name, records),
        'lazy_capsule_top_code': '\n'.join(lines),
        'lazy_capsule_setup_code': '\n'.join(setup_lines),
    }
