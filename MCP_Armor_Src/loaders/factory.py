# -*- coding: utf-8 -*-
"""Final source, marshal and function loader assembly."""


import base64
import random
import sys
import time
import zlib

from MCP_Armor_Src.utils.branding import normalize_output_date

from MCP_Armor_Src.opcode_rep_netease.opcode_maps import (
    encode_opcode_table,
    encode_runtime_opcode_rows,
    invert_opcode_map,
    load_mcs_opcode_map,
    runtime_table_to_stored_std,
    tunnel_code_object,
)

from MCP_Armor_Src.core.constants import (
    CODE_TUPLE_MAGIC,
    HAVE_ARGUMENT,
    MCP_SHILED_ART,
    MCP_SHILED_VERSION,
)

from MCP_Armor_Src.loaders.builders import (
    build_api_decoy_chain,
    build_decoy_opcode_rows,
    build_executable_decoys,
    build_fake_reference_chain,
    build_loader_noise,
    build_restore_noise,
    build_trampoline_layers,
    rows_repr_any,
)

from MCP_Armor_Src.loaders.anti_debug import (
    build_anti_debug_parts,
)

from MCP_Armor_Src.loaders.netease_guard import (
    build_netease_key_guard,
)

from MCP_Armor_Src.loaders.code_tuple import (
    build_code_tuple_loader_code,
    dumps_code_payload,
)

from MCP_Armor_Src.loaders.components import (
    build_code_capsule_parts,
    build_import_facade_parts,
    build_loader_cleanup_code,
    build_loader_decoy_tuple_code,
    build_outer_decompiler_bait_code,
)

from MCP_Armor_Src.loaders.lazy_capsules import (
    build_lazy_capsule_loader_parts,
    dumps_code_payload_with_options,
)

from MCP_Armor_Src.loaders.outer_runtime import (
    build_outer_runtime_parts,
)

from MCP_Armor_Src.loaders.templates import (
    FUNC_LOADER_TEMPLATE,
    LOADER_TEMPLATE,
    SOURCE_LOADER_TEMPLATE,
)

from MCP_Armor_Src.utils.encoding import (
    byte_char,
    byte_value,
    build_fake_mcs_rows,
    build_loader_debug_parts,
    build_payload_split_rows,
    chunk_text,
    debug_print_code,
    encode_multilayer_rows,
    encode_payload,
    make_table_rows,
    random_bytes,
    random_ident,
    rows_repr,
    xor_code_list,
    xor_data,
    visual_int,
)

from MCP_Armor_Src.utils.chacha import chacha8
from MCP_Armor_Src.utils.crypto_v2 import encrypt_payload
from MCP_Armor_Src.loaders.crypto_vm import (
    virtualize_crypto_source,
    _wrap_numeric_tuple_lines,
)

def _loader_dialect(options):
    value = str(getattr(options, 'loader_dialect', 'auto') or 'auto')
    return random.randrange(3) if value == 'auto' else int(value)


def _strip_indent(code):
    """Strip the common 4-space loader indent from a generated block."""
    lines = code.split('\n')
    out = []
    for line in lines:
        if line.startswith('    '):
            out.append(line[4:])
        else:
            out.append(line)
    return '\n'.join(out)


def _build_flat_run_code(names, values):
    """Control-flow-flattened run() body."""
    state = random_ident()
    junk = random_ident()
    execute_code = _strip_indent(values['module_execute_code'])
    export_code = _strip_indent(values['module_export_code'])
    real_blocks = [
        '%s = %s(\'\'.join(%s))' % (
            names['data'], names['decode64'], names['payload']),
        '%s = %s(%s, %s, %s)' % (
            names['raw'], values['decrypt_fn'], names['data'],
            names['key'], names['nonce']),
        'if not %s(%s, %s)(%s):\n    raise ValueError()' % (
            names['prefix'], names['raw'], values['prefix_codes'],
            names['magic']),
        '%s = %s(%s[len(%s):])' % (
            names['row'], names['loads'], names['raw'], names['magic']),
        '%s = %s(%s, %s, %s)' % (
            names['code'], names['code_tuple_load_name'], names['row'],
            names['pickle'], names['types']),
        execute_code,
        '%s()' % names['result'] + (
            '\n' + export_code if export_code else ''),
    ]
    decoy_holder = values.get('decoy_holder', '')
    fake0 = values.get('fake0_fn', '')
    fake1 = values.get('fake1_fn', '')
    fake2 = values.get('fake2_fn', '')
    fake3 = values.get('fake3_fn', '')
    fake4 = values.get('fake4_fn', '')
    fake_stmts = []
    if fake0:
        fake_stmts.append(
            '%s = (%s ^ %s(%s + %s)) & 0x7fffffff' % (
                junk, junk, fake0, names['key'], names['nonce']))
    if fake3:
        fake_stmts.append('%s = %s(%s)' % (junk, fake3, junk))
    if fake2:
        fake_stmts.append(
            '%s = (%s ^ %s(%s, %s)) & 0x7fffffff' % (
                junk, junk, fake2, names['key'], names['nonce']))
    if fake1:
        fake_stmts.append(
            '%s = (%s ^ len(%s(%s, %s))) & 0x7fffffff' % (
                junk, junk, fake1, names['key'], names['nonce']))
    if fake4:
        fake_stmts.append(
            '%s = (%s ^ %s(%s)) & 0x7fffffff' % (
                junk, junk, fake4, names['key']))
    blocks = []
    decoy_index = 0
    for index, real in enumerate(real_blocks):
        blocks.append(real)
        if index < len(real_blocks) - 1:
            mode = decoy_index % 3
            if mode == 0 and fake_stmts:
                blocks.append(fake_stmts[decoy_index % len(fake_stmts)])
            elif mode == 1 and decoy_holder and decoy_holder != '()':
                blocks.append(
                    '%s = %s[(%s & 255) %% len(%s)](%s)' % (
                        junk, decoy_holder, state, decoy_holder, junk))
            else:
                blocks.append(
                    '%s = (%s * 1103515245 + 12345 + (%s & 255)) & 0x7fffffff' % (
                        junk, junk, state))
            decoy_index += 1
    ids = []
    cursor = random.randint(0x10000000, 0x6fffffff)
    for _ in blocks:
        ids.append(cursor)
        cursor = random.randint(0x10000000, 0x6fffffff)
    xors = [ids[k] ^ ids[k + 1] for k in range(len(ids) - 1)]
    lines = []
    lines.append('def %s():' % names['run'])
    lines.append('    %s = None' % names['data'])
    lines.append('    %s = None' % names['raw'])
    lines.append('    %s = None' % names['row'])
    lines.append('    %s = None' % names['code'])
    lines.append('    %s = 0' % junk)
    lines.append('    %s = %d' % (state, ids[0]))
    lines.append('    while True:')
    for index, block in enumerate(blocks):
        keyword = 'if' if index == 0 else 'elif'
        lines.append('        %s %s == %d:' % (keyword, state, ids[index]))
        for statement in block.split('\n'):
            lines.append('            %s' % statement)
        if index < len(blocks) - 1:
            lines.append('            %s = %s ^ %d' % (state, state, xors[index]))
        else:
            lines.append('            return')
    lines.append('        else:')
    lines.append('            %s = (%s * 1103515245 + 12345) & 0x7fffffff' % (
        state, state))
    return '\n'.join(lines)


def _build_payload_seal_code(encoded, names):
    mask = random.randint(1, 0x7fffffff)
    encoded_bytes = (encoded.encode('utf-8')
                     if sys.version_info[0] >= 3 and isinstance(encoded, str)
                     else encoded)
    actual = zlib.adler32(encoded_bytes) & 0x7fffffff
    stored = actual ^ mask
    return (
        '    if (((%s(%s) & %s) ^ %s) != %s):\n'
        '        raise ValueError(%r)'
    ) % (
        names['adler_name'], names['data_arg'], visual_int(0x7fffffff),
        visual_int(mask), visual_int(stored),
        random_ident('payload_seal'))


def _build_chacha_parts(enabled, names, key, chacha_code, api_codes,
                        netease_guard, manifest_uuid=(False, None)):
    """Build a tiny runtime bridge to NetEase's native ``_chacha`` module."""
    if not enabled:
        return ('', '', None)
    module_name = names['chacha_name']
    key_name = names['chacha_key_name']
    decode_name = names['chacha_decode_name']
    if netease_guard:
        key_setup = build_netease_key_guard(module_name, key_name, key, manifest_uuid)
    else:
        key_setup = '%s = %r\n' % (key_name, key)
    helper = (
        'def %(d)s(%(data)s):\n'
        '    %(create)s = getattr(%(m)s, %(str)s(%(create_code)s))\n'
        '    %(get)s = getattr(%(m)s, %(str)s(%(get_code)s))\n'
        '    %(destroy)s = getattr(%(m)s, %(str)s(%(destroy_code)s))\n'
        '    %(owner)s = type(%(owner_label)r, (object,), {})()\n'
        '    %(handle)s = %(create)s(%(owner)s, %(rounds)s, %(key)s)\n'
        '    try:\n'
        '        return %(get)s(%(handle)s, %(data)s, len(%(data)s))\n'
        '    finally:\n'
        '        try:\n'
        '            %(destroy)s(%(handle)s)\n'
        '        except Exception:\n'
        '            pass\n'
    ) % {
        'd': decode_name, 'data': names['chacha_data_name'],
        'create': names['chacha_create_name'], 'm': module_name,
        'str': names['str_name'], 'create_code': api_codes['create_code'],
        'get': names['chacha_get_name'], 'get_code': api_codes['get_code'],
        'destroy': names['chacha_destroy_name'],
        'destroy_code': api_codes['destroy_code'],
        'owner': names['chacha_owner_name'],
        'owner_label': random_ident('ChaChaOwner'),
        'handle': names['chacha_handle_name'],
        'rounds': visual_int(8), 'key': key_name,
    }
    import_code = '%s = %s(%s)' % (module_name, names['import_name'], chacha_code)
    return (import_code, key_setup + helper, key)


def _build_runtime_import_codes(names):
    """Return encoded module-name rows used by generated dynamic imports."""
    xor_key = random.randint(1, 255)
    names['int_xor_key'] = visual_int(xor_key)
    names['import_builtin_code'] = xor_code_list(
        [95, 95, 105, 109, 112, 111, 114, 116, 95, 95], xor_key)
    for label in ('b64decode_name', 'decompress_name', 'adler_name', 'loads_name'):
        if label in names:
            continue
        names[label] = random_ident(label[:4])
    return {
        'b64decode_code': xor_code_list(
            [98, 54, 52, 100, 101, 99, 111, 100, 101], xor_key),
        'decompress_code': xor_code_list(
            [100, 101, 99, 111, 109, 112, 114, 101, 115, 115], xor_key),
        'adler_code': xor_code_list(
            [97, 100, 108, 101, 114, 51, 50], xor_key),
        'loads_code': xor_code_list(
            [108, 111, 97, 100, 115], xor_key),
        'startswith_code': xor_code_list(
            [115, 116, 97, 114, 116, 115, 119, 105, 116, 104], xor_key),
        'codetype_code': xor_code_list(
            [67, 111, 100, 101, 84, 121, 112, 101], xor_key),
        'modules_code': xor_code_list(
            [109, 111, 100, 117, 108, 101, 115], xor_key),
        'chacha_code': xor_code_list(
            [95, 99, 104, 97, 99, 104, 97], xor_key),
        'b64_code': xor_code_list(
            [98, 97, 115, 101, 54, 52], xor_key),
        'marshal_code': xor_code_list(
            [109, 97, 114, 115, 104, 97, 108], xor_key),
        'zlib_code': xor_code_list(
            [122, 108, 105, 98], xor_key),
        'pickle_code': xor_code_list(
            [99, 80, 105, 99, 107, 108, 101], xor_key),
        'types_code': xor_code_list(
            [116, 121, 112, 101, 115], xor_key),
        'create_code': xor_code_list(
            [99, 114, 101, 97, 116, 101], xor_key),
        'get_code': xor_code_list(
            [103, 101, 116, 95, 101, 110, 99, 114, 121, 112, 116,
             101, 100, 95, 116, 101, 120, 116], xor_key),
        'destroy_code': xor_code_list(
            [100, 101, 115, 116, 114, 111, 121], xor_key),
        'import_code': xor_code_list(
            [95, 95, 105, 109, 112, 111, 114, 116, 95, 95], xor_key),
    }


def make_function_loader(code, options, runtime_opcode_table=None,
                         stored_to_std=None, lazy_capsules=None,
                         lazy_stored_to_std=None):
    if getattr(options, 'compact_cpickle_loader', False):
        return make_compact_cpickle_loader(code, options)
    raw = dumps_code_payload_with_options(code, options, stored_to_std)
    key = random_bytes(options.key_len)
    chacha_enabled = (getattr(options, 'payload_cipher', 'legacy') == 'chacha' or
                      bool(getattr(options, 'anti_debug', False)))
    chacha_key = random_bytes(32) if chacha_enabled else None
    key_mask = random_bytes(len(key))
    masked_key = xor_data(key, key_mask)
    encoded, ops = encode_payload(raw, key, options.compress_level, chacha_key)
    key_tag = random_ident('ktag')
    mask_tag = random_ident('mtag')
    key_chunks = chunk_text(base64.b64encode(zlib.compress(masked_key, 9)), options.chunk_min, options.chunk_max)
    mask_chunks = chunk_text(base64.b64encode(zlib.compress(key_mask, 9)), options.chunk_min, options.chunk_max)
    payload_rows, payload_tags = build_payload_split_rows(encoded, options)
    key_rows = make_table_rows(key_tag, key_chunks, options.extra_key_fakes)
    key_rows.extend(make_table_rows(mask_tag, mask_chunks, options.extra_key_fakes))
    key_rows = encode_multilayer_rows(key_rows)
    trampoline_code, trampoline_entry = build_trampoline_layers(options.trampoline_layers)
    decoy_rows = build_decoy_opcode_rows(options.decoy_opcode_rows)
    # A standard FunctionLoader has no runtime opcode table.  Emitting the
    # default decoy rows in that case creates a large executable module-level
    # tuple table before LoaderInit and has no protective value.
    runtime_decoys = options.runtime_opcode_decoys if runtime_opcode_table else 0
    opcode_rows, opcode_tag, opcode_salt = encode_runtime_opcode_rows(
        runtime_opcode_table or {}, runtime_decoys)
    fake_mcs_rows = build_fake_mcs_rows(options.fake_mcs_tables)

    names = {}
    for key_name in ['payload_name', 'key_name', 'decoy_table_name', 'opcode_table_name', 'fake_mcs_table_name',
                     'join_name', 'rows_arg', 'tag_arg', 'items_name', 'row_name', 'left_name', 'right_name',
                     'item_name',
                     'row_key_name', 'enc_name', 'buf_name', 'str_name', 'codes_arg', 'num_arg', 'import_name',
                     'builtins_name', 'payload_graph_name', 'payload_join_name', 'tag_iter_name', 'xor_name',
                     'data_arg', 'key_arg', 'mask_name', 'out_name', 'key_len_name', 'idx_name', 'ch_name',
                     'add_name', 'roll_name', 'decode_name', 'zlib_name', 'op_name', 'run_name', 'b64_name',
                     'marshal_name', 'raw_name', 'code_arg', 'func_type_name', 'opcode_decode_name',
                     'opcode_map_name', 'flat_opcode_map_name', 'opcode_salt_name', 'opcode_from_name',
                     'opcode_to_name', 'code_id_name', 'active_opcode_map_name', 'counter_name',
                     'opcode_restore_name', 'types_name', 'consts_name', 'const_name', 'src_name',
                     'pos_name', 'opv_name', 'code_tuple_load_name', 'pickle_name', 'tuple_name',
                     'magic_name', 'code_bytes_join_name', 'code_units_join_name', 'seed_name', 'order_item_name',
                     'ref_table_name', 'ref_row_name', 'code_ref_xor_name', 'frag_provider_name',
                     'arena_load_name', 'arena_build_name',
                     'const_arena_name', 'const_provider_name', 'debug_root_name',
                     'facade_module_name', 'facade_flag_name', 'facade_seed_name',
                     'facade_sys_name', 'facade_dict_name', 'facade_key_name', 'facade_value_name',
                     'facade_registry_class_name', 'facade_registry_name', 'facade_registry_map_name',
                      'facade_registry_key_name', 'facade_registry_value_name',
                     'metadata_decoy_name', 'metadata_func_name', 'func_result_name',
                     'chacha_name', 'chacha_key_name', 'chacha_decode_name',
                     'chacha_handle_name', 'chacha_owner_name', 'chacha_data_name',
                     'chacha_create_name', 'chacha_get_name', 'chacha_destroy_name',
                      'module_func_name', 'lazy_table_name', 'lazy_factory_name',
                      'lazy_manager_local', 'lazy_manager_public']:
        names[key_name] = random_ident(key_name[:4])
    if lazy_capsules:
        names['lazy_manager_public'] = lazy_capsules['manager_name']
    for label in ('b64decode_name', 'decompress_name', 'adler_name',
                  'loads_name'):
        names[label] = random_ident(label[:4])

    fake_ref_code = build_fake_reference_chain(options.fake_ref_layers, options.taunt_text, options.taunt_outer_refs)
    api_decoys = build_api_decoy_chain(options.api_decoy_refs, options.taunt_text)
    if api_decoys:
        fake_ref_code = fake_ref_code + '\n' + api_decoys

    # <<< 新增：生成随机异或密钥，并对模块名的 ASCII 码列表异或加密
    int_xor_key = random.randint(1, 255)

    # base64          [98, 97, 115, 101, 54, 52]
    b64_code_str = xor_code_list([98, 97, 115, 101, 54, 52], int_xor_key)
    # marshal         [109, 97, 114, 115, 104, 97, 108]
    marshal_code_str = xor_code_list([109, 97, 114, 115, 104, 97, 108], int_xor_key)
    # cPickle         [99, 80, 105, 99, 107, 108, 101]
    pickle_code_str = xor_code_list([99, 80, 105, 99, 107, 108, 101], int_xor_key)
    # zlib            [122, 108, 105, 98]
    zlib_code_str = xor_code_list([122, 108, 105, 98], int_xor_key)
    # types           [116, 121, 112, 101, 115]
    types_code_str = xor_code_list([116, 121, 112, 101, 115], int_xor_key)
    # sys             [115, 121, 115]
    sys_code_str = xor_code_list([115, 121, 115], int_xor_key)
    random_code_str = xor_code_list([114, 97, 110, 100, 111, 109], int_xor_key)
    # _chacha         [95, 99, 104, 97, 99, 104, 97]
    chacha_code_str = xor_code_list([95, 99, 104, 97, 99, 104, 97], int_xor_key)
    chacha_api_codes = {
        'create_code': xor_code_list([99, 114, 101, 97, 116, 101], int_xor_key),
        'get_code': xor_code_list([103, 101, 116, 95, 101, 110, 99, 114, 121, 112, 116, 101, 100, 95, 116, 101, 120, 116], int_xor_key),
        'destroy_code': xor_code_list([100, 101, 115, 116, 114, 111, 121], int_xor_key),
    }
    # __import__      [95, 95, 105, 109, 112, 111, 114, 116, 95, 95]
    import_builtin_code_str = xor_code_list([95, 95, 105, 109, 112, 111, 114, 116, 95, 95], int_xor_key)
    b64decode_code_str = xor_code_list([98, 54, 52, 100, 101, 99, 111, 100, 101], int_xor_key)
    decompress_code_str = xor_code_list([100, 101, 99, 111, 109, 112, 114, 101, 115, 115], int_xor_key)
    adler_code_str = xor_code_list([97, 100, 108, 101, 114, 51, 50], int_xor_key)
    loads_code_str = xor_code_list([108, 111, 97, 100, 115], int_xor_key)
    startswith_code_str = xor_code_list([115, 116, 97, 114, 116, 115, 119, 105, 116, 104], int_xor_key)
    codetype_code_str = xor_code_list([67, 111, 100, 101, 84, 121, 112, 101], int_xor_key)
    modules_code_str = xor_code_list([109, 111, 100, 117, 108, 101, 115], int_xor_key)

    names['debug_enabled'] = bool(options.debug)
    names.update(build_loader_debug_parts(options.debug, 'FunctionLoader'))
    names.update({
        'loads_code': loads_code_str,
        'startswith_code': startswith_code_str,
        'codetype_code': codetype_code_str,
        'modules_code': modules_code_str,
        'b64decode_code': b64decode_code_str,
        'decompress_code': decompress_code_str,
        'adler_code': adler_code_str,
    })
    chacha_import_code, chacha_helper_code, _ = _build_chacha_parts(
        chacha_enabled, names, chacha_key, chacha_code_str, chacha_api_codes,
        bool(getattr(options, 'anti_debug', False)),
        getattr(options, 'anti_debug_manifest_uuid', None))
    names.update({'chacha_import_code': chacha_import_code,
                  'chacha_helper_code': chacha_helper_code})
    if options.code_tuple_payload:
        code_tuple_loader_code = build_code_tuple_loader_code(names, _loader_dialect(options))
        fused_runtime = bool(options.code_fused_restore and runtime_opcode_table)
        if fused_runtime:
            fused_debug_line = ''
            if options.debug:
                fused_debug_line = "    print('[DEBUG] MCP CodeTuple FusedRestoreMap Loaded')\n"
            payload_load_code = (
                '    %s = %s(%s)\n'
                '    %s = %s(%s)\n'
                '    %s = getattr(%s, %s(%s))\n'
                '    %s = %s()\n'
                '    %s = [0]\n'
                '%s'
                '    %s = %s(%s, %s, %s, None, None, None, %s, %s, %r)'
            ) % (
                names['pickle_name'], names['import_name'], pickle_code_str,
                names['types_name'], names['import_name'], types_code_str,
                names['loads_name'], names['pickle_name'], names['str_name'],
                loads_code_str,
                names['opcode_map_name'], names['opcode_decode_name'],
                names['counter_name'],
                fused_debug_line,
                names['code_arg'], names['code_tuple_load_name'], names['raw_name'],
                names['pickle_name'], names['types_name'], names['opcode_map_name'],
                names['counter_name'], bool(options.per_code_runtime_opcode),
            )
        else:
            payload_load_code = (
                '    %s = %s(%s)\n'
                '    %s = %s(%s)\n'
                '    %s = getattr(%s, %s(%s))\n'
                '    %s = %s(%s, %s, %s)'
            ) % (
                names['pickle_name'], names['import_name'], pickle_code_str,
                names['types_name'], names['import_name'], types_code_str,
                names['loads_name'], names['pickle_name'], names['str_name'],
                loads_code_str,
                names['code_arg'], names['code_tuple_load_name'], names['raw_name'],
                names['pickle_name'], names['types_name'],
            )
        runtime_types_import_code = ''
    else:
        code_tuple_loader_code = ''
        payload_load_code = (
            '    %s = %s(%s)\n'
            '    %s = getattr(%s, %s(%s))\n'
            '    %s = %s(%s)'
        ) % (
            names['marshal_name'], names['import_name'], marshal_code_str,
            names['loads_name'], names['marshal_name'], names['str_name'],
            loads_code_str,
            names['code_arg'], names['loads_name'], names['raw_name'],
        )
        runtime_types_import_code = '        %s = %s(%s)' % (
            names['types_name'], names['import_name'], types_code_str,
        )

    if options.debug:
        payload_kind = 'CodeTuplePayload' if options.code_tuple_payload else 'MarshalPayload'
        payload_load_code = debug_print_code(
            True, 'MCP FunctionLoader %s' % payload_kind, 4) + '\n' + payload_load_code

    names.update({
        'payload_rows': rows_repr_any(payload_rows),
        'key_rows': rows_repr_any(key_rows),
        'decoy_rows': rows_repr(decoy_rows),
        'opcode_rows': rows_repr_any(opcode_rows),
        'fake_mcs_rows': rows_repr_any(fake_mcs_rows),
        'opcode_tag': opcode_tag,
        'opcode_salt': opcode_salt,
        'payload_tags_repr': repr(payload_tags),
        'payload_graph_enabled': bool(options.payload_graph_split),
        'key_tag': key_tag,
        'mask_tag': mask_tag,
        'ops_repr': repr(ops),
        'have_argument': HAVE_ARGUMENT,
        'runtime_opcode_enabled': bool(runtime_opcode_table),
        'fused_code_restore': bool(options.code_fused_restore and runtime_opcode_table and options.code_tuple_payload),
        'per_code_opcode_enabled': bool(options.per_code_runtime_opcode),
        'restore_noise_code': build_restore_noise(options.opcode_restore_noise),
        'loader_noise': build_loader_noise(options.loader_junk),
        'fake_ref_code': fake_ref_code,
        'loader_decoy_tuple_code': build_loader_decoy_tuple_code(
            options.loader_decoy_tuples, options.taunt_text, names, {
                'b64_code': b64_code_str,
                'pickle_code': pickle_code_str,
                'types_code': types_code_str,
                'b64decode_code': b64decode_code_str,
                'loads_code': loads_code_str,
                'startswith_code': startswith_code_str,
                'codetype_code': codetype_code_str,
            }),
        'outer_decompiler_bait_code': build_outer_decompiler_bait_code(
            getattr(options, 'outer_decompiler_baits', 0),
            options.taunt_text,
            getattr(options, 'outer_decompiler_bait_budget', 8192)),
        'trampoline_code': trampoline_code,
        'trampoline_entry': trampoline_entry,
        # <<< 新增：注入加密后的数字列表和密钥
        'int_xor_key': int_xor_key,
        'b64_code': b64_code_str,
        'marshal_code': marshal_code_str,
        'pickle_code': pickle_code_str,
        'zlib_code': zlib_code_str,
        'types_code': types_code_str,
        'sys_code': sys_code_str,
        'import_builtin_code': import_builtin_code_str,
        'b64decode_code': b64decode_code_str,
        'decompress_code': decompress_code_str,
        'adler_code': adler_code_str,
        'loads_code': loads_code_str,
        'startswith_code': startswith_code_str,
        'codetype_code': codetype_code_str,
        'modules_code': modules_code_str,
        'code_tuple_payload': bool(options.code_tuple_payload),
        'code_tuple_magic': CODE_TUPLE_MAGIC,
        'code_tuple_loader_code': code_tuple_loader_code,
        'payload_load_code': payload_load_code,
        'runtime_types_import_code': runtime_types_import_code,
        'payload_seal_code': _build_payload_seal_code(encoded, names),
    })
    names.update(build_anti_debug_parts(
        encoded, raw, getattr(options, 'experimental_anti_debug', False), True,
        names['data_arg'], names['raw_name'], names['code_arg']))
    facade_fake_name = random_ident('facade_import')
    facade_fake_code = xor_code_list(
        [byte_value(char) for char in facade_fake_name], int_xor_key)
    names.update(build_import_facade_parts(
        names, options.import_facade_layer,
        options.module_registry_protection, facade_fake_code,
        random_code_str))
    names.update(build_outer_runtime_parts(names, options))
    names.update(build_lazy_capsule_loader_parts(
        (lazy_capsules or {}).get('entries', []), options, names,
        lazy_stored_to_std, key, names.get('runtime_key_expr')))
    names.update(build_code_capsule_parts(
        names, options.code_capsule_proxy,
        options.code_capsule_protocol_guard, options.debug))
    names['loader_cleanup_code'] = build_loader_cleanup_code(
        names, options.loader_reference_cleanup, options.debug)

    if options.reflection_metadata_decoy:
        names['metadata_decoy_code'] = (
            '    def %s(%s):\n'
            '        try:\n'
            '            %s.__name__ = %r\n'
            '            %s.__module__ = %r\n'
            '            %s.__doc__ = None\n'
            '        except Exception:\n'
            '            pass\n'
            '        return %s\n'
            '    %s = %s(%s)'
        ) % (
            names['metadata_decoy_name'], names['metadata_func_name'],
            names['metadata_func_name'], random_ident('fn'),
            names['metadata_func_name'], random_ident('mod'),
            names['metadata_func_name'], names['metadata_func_name'],
            names['metadata_func_name'], names['metadata_decoy_name'], names['func_result_name'],
        )
    else:
        names['metadata_decoy_code'] = ''

    names.update(build_loader_debug_parts(options.debug, 'FunctionLoader'))
    return FUNC_LOADER_TEMPLATE % names


def _compact_payload_option(options, name, default):
    """Read an optional CodeTuple dial without burdening direct callers."""
    return getattr(options, name, default)


def _dumps_compact_cpickle_payload(code, options):
    return dumps_code_payload(
        code, True,
        _compact_payload_option(options, 'code_bytes_split', False),
        _compact_payload_option(options, 'code_bytes_split_min', 48),
        _compact_payload_option(options, 'code_bytes_split_max_chunks', 6),
        _compact_payload_option(options, 'code_bytes_fake_chunks', 0),
        _compact_payload_option(options, 'code_ref_table', False),
        _compact_payload_option(options, 'code_tuple_field_shuffle', False),
        _compact_payload_option(options, 'code_ref_decoys', 0),
        _compact_payload_option(options, 'code_ref_wide_rows', False),
        _compact_payload_option(options, 'code_ref_mask_markers', False),
        _compact_payload_option(options, 'code_tuple_fragments', False),
        _compact_payload_option(options, 'code_tuple_fragment_providers', False),
        _compact_payload_option(options, 'code_tuple_provider_graph', False),
        _compact_payload_option(options, 'code_tuple_provider_decoys', 0),
        _compact_payload_option(options, 'code_global_arena', False),
        _compact_payload_option(options, 'code_template_delta', False),
        _compact_payload_option(options, 'code_global_arena_decoys', 0),
        _compact_payload_option(options, 'code_block_relocation', False),
        _compact_payload_option(options, 'code_block_reloc_decoys', 0),
        _compact_payload_option(options, 'stored_to_std', None),
        _compact_payload_option(options, 'code_unit_arena', False),
        _compact_payload_option(options, 'code_unit_arena_decoys', 0),
        _compact_payload_option(options, 'code_operand_graph', False),
        _compact_payload_option(options, 'code_const_arena', False),
        _compact_payload_option(options, 'code_const_arena_decoys', 0),
        _compact_payload_option(options, 'code_const_provider_graph', False),
        _compact_payload_option(options, 'code_const_arena_limit', 1024),
        _compact_payload_option(options, 'code_field_descriptors', False),
        _compact_payload_option(options, 'code_provider_context_bind', False))


def make_compact_cpickle_loader(code, options):
    """Build the NetEase-compatible minimal cPickle/CodeTuple loader."""
    raw = _dumps_compact_cpickle_payload(code, options)
    key32 = random_bytes(32)
    nonce24 = random_bytes(24)
    watermark = MCP_SHILED_ART + '\nMCP Shiled V%s OBFED_TIME:%s' % (
        MCP_SHILED_VERSION,
        normalize_output_date(getattr(options, 'output_date', None)))
    watermark_bytes = watermark.encode('utf-8')
    part_a = watermark_bytes[0::2]
    part_b = watermark_bytes[1::2]
    key_a = random_bytes(16)
    key_b = random_bytes(16)
    enc_a = tuple(
        byte_value(part_a[i]) ^ byte_value(key_a[i % len(key_a)])
        for i in range(len(part_a)))
    # Split fragment B into two halves, each XORed with its own 8-byte key
    # slice so the two runtime real hooks decode independently.
    half_b = len(part_b) // 2
    part_b1 = part_b[:half_b]
    part_b2 = part_b[half_b:]
    k1 = tuple(byte_value(ch) for ch in key_b[:8])
    k2 = tuple(byte_value(ch) for ch in key_b[8:])
    b1 = tuple(
        byte_value(part_b1[i]) ^ byte_value(k1[i % len(k1)])
        for i in range(len(part_b1)))
    b2 = tuple(
        byte_value(part_b2[i]) ^ byte_value(k2[i % len(k2)])
        for i in range(len(part_b2)))
    encrypted = encrypt_payload(
        raw, key32, nonce24, watermark_bytes,
        max(1, min(9, int(getattr(options, 'compress_level', 9)))))
    encoded = base64.b64encode(encrypted)
    chunks = chunk_text(encoded, 72, 120)
    names = {}
    for label in (
            'payload', 'key', 'nonce', 'text', 'importer', 'builtins', 'codes', 'name',
            'pickle', 'zlib', 'base64', 'loads', 'decode64', 'decompress',
            'data', 'out', 'index', 'char', 'raw', 'magic', 'restore', 'row',
            'fields', 'consts', 'value', 'code_type', 'function_type', 'code',
            'run', 'result', 'chacha', 'chacha_key', 'chacha_decode',
            'module_scope', 'module_host', 'module_key', 'module_meta',
            'chacha_handle', 'chacha_owner', 'chacha_data', 'chacha_create',
            'chacha_get', 'chacha_destroy', 'prefix', 'types', 'tuple',
            'hook_key', 'hook_decompress', 'hook_parts', 'hook_idx',
            'hook_data', 'hook_char', 'decompress_attr',
            'key_seed', 'key_parts', 'key_idx',
            'code_tuple_load', 'code_bytes_join', 'code_units_join', 'seed',
            'order_item', 'ref_table', 'ref_row', 'code_ref_xor',
            'frag_provider', 'arena_load', 'arena_build', 'const_arena',
            'const_provider', 'debug_root'):
        names[label] = random_ident(label[:4])
    for _label in (
            'code_ref_xor_name', 'raw_name', 'seed_name', 'order_item_name',
            'code_tuple_load_name', 'pickle_name', 'types_name', 'str_name',
            'ref_table_name', 'ref_row_name', 'frag_provider_name',
            'arena_load_name', 'arena_build_name', 'debug_root_name',
            'tuple_name', 'code_bytes_join_name', 'code_units_join_name',
            'const_arena_name', 'const_provider_name',
            'mask_name', 'key_len_name', 'items_name', 'item_name',
            'idx_name', 'pos_name', 'opv_name', 'left_name', 'right_name',
            'out_name', 'src_name', 'data_arg', 'key_arg', 'const_name',
            'consts_name', 'ch_name', 'magic_name', 'code_arg'):
        if _label not in names:
            names[_label] = random_ident(_label[:4])
    # The code_tuple template refers to the loader's string decoder and import
    # results via ``_name``-suffixed keys; unify them with the no-suffix names
    # the loader template defines.
    names['str_name'] = names['text']
    names['pickle_name'] = names['pickle']
    names['types_name'] = names['types']
    # The compact template executes the value produced by flat_run_code;
    # bind its generic code_arg placeholder to that same randomized slot.
    names['code_arg'] = names['code']
    names.update({
        'loads_code': repr(tuple(byte_value(ch) for ch in 'loads')),
        'startswith_code': repr(tuple(byte_value(ch) for ch in 'startswith')),
        'have_argument': HAVE_ARGUMENT,
        'debug_enabled': bool(getattr(options, 'debug', False)),
    })
    compact_debug = build_loader_debug_parts(
        bool(getattr(options, 'debug', False)), 'CPickle')
    code_tuple_loader_code = build_code_tuple_loader_code(names, _loader_dialect(options))
    trampoline_code, trampoline_entry = build_trampoline_layers(
        getattr(options, 'trampoline_layers', 0))
    values = dict(names)
    # Keep compact cPickle source readable and within the target loader's
    # line-size budget even when a chunk contains a long base64 fragment.
    payload_repr = '(\n%s\n)' % ''.join(
        '    %r,\n' % chunk for chunk in chunks)
    (crypto_code, decrypt_fn, d0_name, d1_name, d2_name, d3_name,
     fake0_name, fake1_name, fake2_name, fake3_name, fake4_name) = \
        virtualize_crypto_source(getattr(options, 'loader_vm', False))
    crypto_code = crypto_code.replace(
        "'__MCP_FA_PH__'", repr(enc_a)).replace(
        "'__MCP_KA_PH__'", repr(tuple(byte_value(ch) for ch in key_a)))
    crypto_code = _wrap_numeric_tuple_lines(crypto_code)

    def _frag_decoy(name, piece):
        seed = random.randint(0x10000, 0x7fffffff)
        local = random_ident()
        return (
            'def %s():\n'
            '    %s = %d\n'
            '    if (%s * %s + %s) %% 2 == 0:\n'
            '        return %r\n'
            '    return ()\n'
        ) % (name, local, seed, local, local, local, piece)

    frag_decoys = '\n'.join((
        _frag_decoy(d0_name, b1),
        _frag_decoy(d1_name, b2),
        _frag_decoy(d2_name, k1),
        _frag_decoy(d3_name, k2),
    ))
    values.update({
        'payload_repr': payload_repr,
        'key_repr': repr(tuple(byte_value(ch) for ch in key32)),
        'nonce_repr': repr(tuple(byte_value(ch) for ch in nonce24)),
        'crypto_code': crypto_code,
        'decrypt_fn': decrypt_fn,
        'fake0_fn': fake0_name,
        'fake1_fn': fake1_name,
        'fake2_fn': fake2_name,
        'fake3_fn': fake3_name,
        'fake4_fn': fake4_name,
        'frag_decoys': frag_decoys,
        'pickle_codes': repr(tuple(byte_value(ch) for ch in 'cPickle')),
        'zlib_codes': repr(tuple(byte_value(ch) for ch in 'zlib')),
        'base64_codes': repr(tuple(byte_value(ch) for ch in 'base64')),
        'loads_codes': repr(tuple(byte_value(ch) for ch in 'loads')),
        'decode64_codes': repr(tuple(byte_value(ch) for ch in 'b64decode')),
        'decompress_codes': repr(tuple(byte_value(ch) for ch in 'decompress')),
        'types_codes': repr(tuple(byte_value(ch) for ch in 'types')),
        'prefix_codes': repr(tuple(byte_value(ch) for ch in 'startswith')),
        'import_codes': repr(tuple(byte_value(ch) for ch in '__import__')),
        'magic_repr': repr(CODE_TUPLE_MAGIC),
        'code_tuple_loader_code': code_tuple_loader_code,
        'debug_entry': debug_print_code(
            bool(getattr(options, 'debug', False)),
            'MCP CPickle Entry', 0),
        'debug_payload_b64': debug_print_code(
            bool(getattr(options, 'debug', False)),
            'MCP CPickle PayloadBase64', 4),
        'debug_payload_crypto': debug_print_code(
            bool(getattr(options, 'debug', False)),
            'MCP CPickle PayloadCrypto', 4),
        'debug_payload_xor': debug_print_code(
            bool(getattr(options, 'debug', False)),
            'MCP CPickle PayloadXor', 4),
        'debug_payload_zlib': debug_print_code(
            bool(getattr(options, 'debug', False)),
            'MCP CPickle PayloadZlib', 4),
        'debug_payload_pickle': debug_print_code(
            bool(getattr(options, 'debug', False)),
            'MCP CPickle PayloadPickle', 4),
        'debug_code_object': debug_print_code(
            bool(getattr(options, 'debug', False)),
            'MCP CPickle CodeObjectRebuild', 4),
        'debug_execute_done': debug_print_code(
            bool(getattr(options, 'debug', False)),
            'MCP CPickle ModuleExecuteComplete', 4),
        'trampoline_code': trampoline_code,
        'trampoline_entry': trampoline_entry,
    })
    exec_decoy_source, exec_decoy_holder = build_executable_decoys(
        getattr(options, 'exec_decoys', 8))
    values['decoy_holder'] = exec_decoy_holder or '()'
    compact_outer_code = '\n'.join(part for part in (
        exec_decoy_source,
        build_outer_decompiler_bait_code(
            getattr(options, 'outer_decompiler_baits', 0),
            getattr(options, 'taunt_text', None),
            getattr(options, 'outer_decompiler_bait_budget', 8192)),
        build_loader_noise(getattr(options, 'loader_junk', 0)),
        build_fake_reference_chain(
            getattr(options, 'fake_ref_layers', 0),
            getattr(options, 'taunt_text', None),
            getattr(options, 'taunt_outer_refs', 0)),
    ) if part)
    values['compact_outer_code'] = compact_outer_code
    values.update(compact_debug)
    if bool(getattr(options, 'compact_isolated_globals', False)):
        values['module_execute_code'] = (
            '    %s = globals()\n'
            '    %s = {\'__builtins__\': __builtins__}\n'
            '    for %s in (\'__name__\', \'__file__\', \'__package__\', \'__path__\', \'__loader__\', \'__spec__\'):\n'
            '        if %s in %s:\n'
            '            %s[%s] = %s[%s]\n'
            '    %s = %s(%s, %s, %s)'
        ) % (
            names['module_host'], names['module_scope'],
            names['module_meta'], names['module_meta'], names['module_host'],
            names['module_scope'], names['module_meta'], names['module_host'],
            names['module_meta'], names['result'], trampoline_entry,
            names['function_type'], names['code'], names['module_scope'])
        values['module_export_code'] = (
            '    for %s, %s in %s.items():\n'
            '        if %s != \'__builtins__\':\n'
            '            %s[%s] = %s'
        ) % (
            names['module_key'], names['value'], names['module_scope'],
            names['module_key'], names['module_host'], names['module_key'],
            names['value'])
    else:
        values['module_execute_code'] = (
            '    %s = %s(%s, %s, globals())' % (
                names['result'], trampoline_entry,
                names['function_type'], names['code']))
        values['module_export_code'] = ''
    values['flat_run_code'] = _build_flat_run_code(names, values)
    compact_source = (r'''# -*- coding: utf-8 -*-
%(payload)s = %(payload_repr)s
%(key)s = %(key_repr)s
%(nonce)s = %(nonce_repr)s
%(frag_decoys)s
%(debug_entry)s

%(compact_outer_code)s
%(trampoline_code)s

%(crypto_code)s

def %(text)s(%(codes)s):
    return ''.join(chr(%(value)s) for %(value)s in %(codes)s)

def %(importer)s(%(codes)s):
    %(builtins)s = __builtins__
    %(name)s = %(text)s(%(codes)s)
    if isinstance(%(builtins)s, dict):
        return %(builtins)s[%(text)s(%(import_codes)s)](%(name)s)
    return getattr(%(builtins)s, %(text)s(%(import_codes)s))(%(name)s)

%(pickle)s = %(importer)s(%(pickle_codes)s)
%(types)s = %(importer)s(%(types_codes)s)
%(base64)s = %(importer)s(%(base64_codes)s)
%(loads)s = getattr(%(pickle)s, %(text)s(%(loads_codes)s))
%(decode64)s = getattr(%(base64)s, %(text)s(%(decode64_codes)s))
%(magic)s = %(magic_repr)s
%(code_tuple_loader_code)s
def %(prefix)s(%(value)s, %(codes)s):
    return getattr(%(value)s, %(text)s(%(codes)s))
%(code_type)s = (lambda: None).func_code.__class__
%(function_type)s = (lambda: None).__class__

def %(restore)s(%(row)s):
    %(fields)s = list(%(row)s)
    %(consts)s = []
    for %(value)s in %(fields)s[5]:
        if isinstance(%(value)s, str) and %(prefix)s(%(value)s, %(prefix_codes)s)(%(magic)s):
            %(value)s = %(restore)s(%(loads)s(%(value)s[len(%(magic)s):]))
        %(consts)s.append(%(value)s)
    %(fields)s[5] = tuple(%(consts)s)
    return %(code_type)s(*%(fields)s)

%(flat_run_code)s

%(run)s()
''') % values
    return _wrap_numeric_tuple_lines(compact_source)


def make_source_loader(source, options):
    key = random_bytes(options.key_len)
    chacha_enabled = (getattr(options, 'payload_cipher', 'legacy') == 'chacha' or
                      bool(getattr(options, 'anti_debug', False)))
    chacha_key = random_bytes(32) if chacha_enabled else None
    encoded, ops = encode_payload(source, key, options.compress_level, chacha_key)
    payload_tag = random_ident('ptag')
    key_tag = random_ident('ktag')
    payload_chunks = chunk_text(base64.b64encode(encoded), options.chunk_min, options.chunk_max)
    key_chunks = chunk_text(base64.b64encode(zlib.compress(key, 9)), options.chunk_min, options.chunk_max)
    payload_rows = make_table_rows(payload_tag, payload_chunks, options.extra_payload_fakes)
    key_rows = make_table_rows(key_tag, key_chunks, options.extra_key_fakes)
    names = {}
    for key_name in ('payload_name', 'key_name', 'join_name', 'rows_arg', 'tag_arg', 'items_name', 'row_name', 'left_name', 'right_name', 'item_name', 'str_name', 'codes_arg', 'num_arg', 'import_name', 'builtins_name', 'xor_name', 'data_arg', 'key_arg', 'out_name', 'key_len_name', 'idx_name', 'ch_name', 'add_name', 'roll_name', 'decode_name', 'zlib_name', 'op_name', 'run_name', 'b64_name', 'raw_name', 'chacha_name', 'chacha_key_name', 'chacha_decode_name', 'chacha_handle_name', 'chacha_owner_name', 'chacha_data_name', 'chacha_create_name', 'chacha_get_name', 'chacha_destroy_name'):
        names[key_name] = random_ident(key_name[:4])
    import_codes = _build_runtime_import_codes(names)
    names.update(import_codes)
    chacha_import_code, chacha_helper_code, _ = _build_chacha_parts(
        chacha_enabled, names, chacha_key, import_codes['chacha_code'],
        import_codes, bool(getattr(options, 'anti_debug', False)),
        getattr(options, 'anti_debug_manifest_uuid', None))
    names.update({
        'payload_rows': rows_repr(payload_rows),
        'key_rows': rows_repr(key_rows),
        'payload_tag': payload_tag,
        'key_tag': key_tag,
        'ops_repr': repr(ops),
        'loader_noise': build_loader_noise(options.loader_junk),
        'chacha_import_code': chacha_import_code,
        'chacha_helper_code': chacha_helper_code,
        'payload_seal_code': _build_payload_seal_code(encoded, names),
    })
    names.update(build_anti_debug_parts(
        encoded, source, getattr(options, 'experimental_anti_debug', False),
        False, names['data_arg'], names['raw_name'], None))
    names.update(build_loader_debug_parts(options.debug, 'SourceLoader'))
    return SOURCE_LOADER_TEMPLATE % names


def make_loader(code, options):
    if options.inner_opcode_tunnel:
        code, opcode_table = tunnel_code_object(
            code, options.opcode_runtime, options.mcs_opmap_version)
    else:
        opcode_table = {}
    raw = dumps_code_payload_with_options(code, options, None)
    key = random_bytes(options.key_len)
    chacha_enabled = (getattr(options, 'payload_cipher', 'legacy') == 'chacha' or
                      bool(getattr(options, 'anti_debug', False)))
    chacha_key = random_bytes(32) if chacha_enabled else None
    encoded, ops = encode_payload(raw, key, options.compress_level, chacha_key)
    payload_tag = random_ident('ptag')
    key_tag = random_ident('ktag')
    payload_chunks = chunk_text(base64.b64encode(encoded), options.chunk_min, options.chunk_max)
    key_chunks = chunk_text(base64.b64encode(zlib.compress(key, 9)), options.chunk_min, options.chunk_max)
    payload_rows = make_table_rows(payload_tag, payload_chunks, options.extra_payload_fakes)
    key_rows = make_table_rows(key_tag, key_chunks, options.extra_key_fakes)
    table_rows, table_tag, table_salt = encode_opcode_table(
        opcode_table, options.extra_key_fakes)
    names = {}
    for key_name in ('payload_name', 'key_name', 'table_name', 'join_name', 'rows_arg', 'tag_arg', 'items_name', 'row_name', 'left_name', 'right_name', 'item_name', 'str_name', 'codes_arg', 'num_arg', 'import_name', 'builtins_name', 'xor_name', 'data_arg', 'key_arg', 'mask_name', 'out_name', 'key_len_name', 'idx_name', 'ch_name', 'add_name', 'roll_name', 'decode_name', 'zlib_name', 'op_name', 'table_decode_name', 'tbl_name', 'salt_name', 'restore_name', 'code_arg', 'table_arg', 'types_name', 'consts_name', 'const_name', 'src_name', 'pos_name', 'opv_name', 'run_name', 'b64_name', 'marshal_name', 'raw_name', 'code_tuple_load_name', 'pickle_name', 'tuple_name', 'magic_name', 'code_bytes_join_name', 'code_units_join_name', 'seed_name', 'order_item_name', 'ref_table_name', 'ref_row_name', 'code_ref_xor_name', 'frag_provider_name', 'arena_load_name', 'arena_build_name', 'const_arena_name', 'const_provider_name', 'debug_root_name', 'chacha_name', 'chacha_key_name', 'chacha_decode_name', 'chacha_handle_name', 'chacha_owner_name', 'chacha_data_name', 'chacha_create_name', 'chacha_get_name', 'chacha_destroy_name'):
        names[key_name] = random_ident(key_name[:4])
    import_codes = _build_runtime_import_codes(names)
    names.update(import_codes)
    chacha_import_code, chacha_helper_code, _ = _build_chacha_parts(
        chacha_enabled, names, chacha_key, import_codes['chacha_code'],
        import_codes, bool(getattr(options, 'anti_debug', False)),
        getattr(options, 'anti_debug_manifest_uuid', None))
    names['debug_enabled'] = bool(options.debug)
    names.update(build_loader_debug_parts(options.debug, 'MarshalLoader'))
    loads_code_str = names['loads_code']
    names.update(build_anti_debug_parts(
        encoded, raw, getattr(options, 'experimental_anti_debug', False),
        bool(getattr(options, 'experimental_anti_debug', False)),
        names['data_arg'], names['raw_name'], names['code_arg']))
    if options.code_tuple_payload:
        payload_load_code = (
            '    %s = %s(%s)\n'
            '    %s = %s(%s)\n'
            '    %s = getattr(%s, %s(%s))\n'
            '    %s = %s(%s, %s, %s)'
        ) % (
            names['pickle_name'], names['import_name'], pickle_code_str,
            names['types_name'], names['import_name'], types_code_str,
            names['loads_name'], names['pickle_name'], names['str_name'],
            loads_code_str,
            names['code_arg'], names['code_tuple_load_name'], names['raw_name'],
            names['pickle_name'], names['types_name'])
    else:
        marshal_code_str = names['marshal_code']
        payload_load_code = (
            '    %s = %s(%s)\n'
            '    %s = getattr(%s, %s(%s))\n'
            '    %s = %s(%s)'
        ) % (
            names['marshal_name'], names['import_name'], marshal_code_str,
            names['loads_name'], names['marshal_name'], names['str_name'],
            loads_code_str,
            names['code_arg'], names['loads_name'], names['raw_name'])
    if options.debug:
        payload_load_code = debug_print_code(
            True, 'MCP MarshalLoader', 4) + '\n' + payload_load_code
    names.update({
        'payload_rows': rows_repr(payload_rows),
        'key_rows': rows_repr(key_rows),
        'table_rows': rows_repr(table_rows),
        'payload_tag': payload_tag,
        'key_tag': key_tag,
        'table_tag': table_tag,
        'table_salt': table_salt,
        'ops_repr': repr(ops),
        'have_argument': HAVE_ARGUMENT,
        'tunnel_enabled': bool(options.inner_opcode_tunnel),
        'loader_noise': build_loader_noise(options.loader_junk),
        'code_tuple_payload': bool(options.code_tuple_payload),
        'code_tuple_magic': CODE_TUPLE_MAGIC,
        'code_tuple_loader_code': build_code_tuple_loader_code(names, _loader_dialect(options)),
        'payload_load_code': payload_load_code,
        'tunnel_types_import_code': '',
        'chacha_import_code': chacha_import_code,
        'chacha_helper_code': chacha_helper_code,
        'payload_seal_code': _build_payload_seal_code(encoded, names),
        'payload_load_code': payload_load_code,
    })
    return LOADER_TEMPLATE % names\n