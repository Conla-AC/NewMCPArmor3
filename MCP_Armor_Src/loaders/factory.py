# -*- coding: utf-8 -*-
"""Final source, marshal and function loader assembly."""
from __future__ import absolute_import, print_function

import base64
import random
import zlib

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
)

from MCP_Armor_Src.loaders.builders import (
    build_api_decoy_chain,
    build_decoy_opcode_rows,
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


def _build_payload_seal_code(encoded, names):
    mask = random.randint(1, 0x7fffffff)
    actual = zlib.adler32(encoded) & 0x7fffffff
    stored = actual ^ mask
    return (
        '    if (((%s(%s) & %s) ^ %s) != %s):\n'
        '        raise ValueError(%r)'
    ) % (
        names['adler_name'], names['data_arg'], visual_int(0x7fffffff),
        visual_int(mask), visual_int(stored), random_ident('payload_seal'))


def _build_chacha_parts(enabled, names, key, chacha_code, api_codes,
                        netease_guard=False, manifest_uuid=None):
    """Build a tiny runtime bridge to NetEase's native ``_chacha`` module."""
    if not enabled:
        return '', '', None
    module_name = names['chacha_name']
    key_name = names['chacha_key_name']
    decode_name = names['chacha_decode_name']
    if netease_guard:
        key_setup = build_netease_key_guard(
            module_name, key_name, key, manifest_uuid)
    else:
        key_setup = '%s = %r\n' % (key_name, key)
    helper = key_setup + (
        'def %s(%s):\n'
        '    %s = getattr(%s, %s(%s))\n'
        '    %s = getattr(%s, %s(%s))\n'
        '    %s = getattr(%s, %s(%s))\n'
        '    %s = type(%r, (object,), {})()\n'
        '    %s = %s(%s, %s, %s)\n'
        '    try:\n'
        '        return %s(%s, %s, len(%s))\n'
        '    finally:\n'
        '        try:\n'
        '            %s(%s)\n'
        '        except Exception:\n'
        '            pass\n'
    ) % (
        decode_name, names['chacha_data_name'],
        names['chacha_create_name'], module_name, names['str_name'], api_codes['create_code'],
        names['chacha_get_name'], module_name, names['str_name'], api_codes['get_code'],
        names['chacha_destroy_name'], module_name, names['str_name'], api_codes['destroy_code'],
        names['chacha_owner_name'], random_ident('ChaChaOwner'),
        names['chacha_handle_name'], names['chacha_create_name'],
        names['chacha_owner_name'], visual_int(8), key_name,
        names['chacha_get_name'], names['chacha_handle_name'], names['chacha_data_name'],
        names['chacha_data_name'], names['chacha_destroy_name'], names['chacha_handle_name'])
    import_code = '%s = %s(%s)' % (
        module_name, names['import_name'], chacha_code)
    return import_code, helper, key


def _build_runtime_import_codes(names):
    """Return encoded module-name rows used by generated dynamic imports."""
    xor_key = random.randint(1, 255)
    names['int_xor_key'] = visual_int(xor_key)
    names['import_builtin_code'] = xor_code_list(
        [95, 95, 105, 109, 112, 111, 114, 116, 95, 95], xor_key)
    for label in ('b64decode_name', 'decompress_name', 'adler_name',
                  'loads_name'):
        if label not in names:
            names[label] = random_ident(label[:4])
    return {
        'b64_code': xor_code_list([98, 97, 115, 101, 54, 52], xor_key),
        'zlib_code': xor_code_list([122, 108, 105, 98], xor_key),
        'marshal_code': xor_code_list(
            [109, 97, 114, 115, 104, 97, 108], xor_key),
        'pickle_code': xor_code_list(
            [99, 80, 105, 99, 107, 108, 101], xor_key),
        'types_code': xor_code_list([116, 121, 112, 101, 115], xor_key),
        'chacha_code': xor_code_list(
            [95, 99, 104, 97, 99, 104, 97], xor_key),
        'create_code': xor_code_list([99, 114, 101, 97, 116, 101], xor_key),
        'get_code': xor_code_list(
            [103, 101, 116, 95, 101, 110, 99, 114, 121, 112, 116,
             101, 100, 95, 116, 101, 120, 116], xor_key),
        'destroy_code': xor_code_list(
            [100, 101, 115, 116, 114, 111, 121], xor_key),
        'b64decode_code': xor_code_list(
            [98, 54, 52, 100, 101, 99, 111, 100, 101], xor_key),
        'decompress_code': xor_code_list(
            [100, 101, 99, 111, 109, 112, 114, 101, 115, 115], xor_key),
        'adler_code': xor_code_list(
            [97, 100, 108, 101, 114, 51, 50], xor_key),
        'loads_code': xor_code_list([108, 111, 97, 100, 115], xor_key),
        'startswith_code': xor_code_list(
            [115, 116, 97, 114, 116, 115, 119, 105, 116, 104], xor_key),
        'codetype_code': xor_code_list(
            [67, 111, 100, 101, 84, 121, 112, 101], xor_key),
        'modules_code': xor_code_list(
            [109, 111, 100, 117, 108, 101, 115], xor_key),
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
        code_tuple_loader_code = build_code_tuple_loader_code(names)
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
        [ord(char) for char in facade_fake_name], int_xor_key)
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


def make_compact_cpickle_loader(code, options):
    """Build the NetEase-compatible minimal cPickle/CodeTuple loader.

    This intentionally omits the generic arena, descriptor, opcode, capsule and
    outer-runtime restorers.  It reconstructs the plain recursive CodeTuple
    directly through the two Python 2 lambda type chains.
    """
    raw = dumps_code_payload(code, True)
    key = random_bytes(max(8, min(32, int(getattr(options, 'key_len', 16)))))
    packed = zlib.compress(raw, max(1, min(9, int(options.compress_level))))
    encoded = base64.b64encode(xor_data(packed, key))
    chunks = chunk_text(encoded, 72, 120)
    names = {}
    for label in (
            'payload', 'key', 'text', 'importer', 'builtins', 'codes', 'name',
            'pickle', 'zlib', 'base64', 'loads', 'decode64', 'decompress',
            'data', 'out', 'index', 'char', 'raw', 'magic', 'restore', 'row',
            'fields', 'consts', 'value', 'code_type', 'function_type', 'code',
            'run', 'result'):
        names[label] = random_ident(label[:4])
    values = dict(names)
    values.update({
        'payload_repr': repr(tuple(chunks)),
        'key_repr': repr(tuple(ord(ch) for ch in key)),
        'pickle_codes': repr(tuple(ord(ch) for ch in 'cPickle')),
        'zlib_codes': repr(tuple(ord(ch) for ch in 'zlib')),
        'base64_codes': repr(tuple(ord(ch) for ch in 'base64')),
        'loads_codes': repr(tuple(ord(ch) for ch in 'loads')),
        'decode64_codes': repr(tuple(ord(ch) for ch in 'b64decode')),
        'decompress_codes': repr(tuple(ord(ch) for ch in 'decompress')),
        'import_codes': repr(tuple(ord(ch) for ch in '__import__')),
        'magic_repr': repr(CODE_TUPLE_MAGIC),
    })
    return (r'''# -*- coding: utf-8 -*-
%(payload)s = %(payload_repr)s
%(key)s = %(key_repr)s

def %(text)s(%(codes)s):
    return ''.join(chr(%(value)s) for %(value)s in %(codes)s)

def %(importer)s(%(codes)s):
    %(builtins)s = __builtins__
    %(name)s = %(text)s(%(codes)s)
    if isinstance(%(builtins)s, dict):
        return %(builtins)s[%(text)s(%(import_codes)s)](%(name)s)
    return getattr(%(builtins)s, %(text)s(%(import_codes)s))(%(name)s)

%(pickle)s = %(importer)s(%(pickle_codes)s)
%(zlib)s = %(importer)s(%(zlib_codes)s)
%(base64)s = %(importer)s(%(base64_codes)s)
%(loads)s = getattr(%(pickle)s, %(text)s(%(loads_codes)s))
%(decode64)s = getattr(%(base64)s, %(text)s(%(decode64_codes)s))
%(decompress)s = getattr(%(zlib)s, %(text)s(%(decompress_codes)s))
%(magic)s = %(magic_repr)s
%(code_type)s = (lambda: None).func_code.__class__
%(function_type)s = (lambda: None).__class__

def %(restore)s(%(row)s):
    %(fields)s = list(%(row)s)
    %(consts)s = []
    for %(value)s in %(fields)s[5]:
        if isinstance(%(value)s, str) and %(value)s.startswith(%(magic)s):
            %(value)s = %(restore)s(%(loads)s(%(value)s[len(%(magic)s):]))
        %(consts)s.append(%(value)s)
    %(fields)s[5] = tuple(%(consts)s)
    return %(code_type)s(*%(fields)s)

def %(run)s():
    %(data)s = %(decode64)s(''.join(%(payload)s))
    %(out)s = []
    for %(index)s, %(char)s in enumerate(%(data)s):
        %(out)s.append(chr(ord(%(char)s) ^ %(key)s[%(index)s %% len(%(key)s)]))
    %(raw)s = %(decompress)s(''.join(%(out)s))
    if not %(raw)s.startswith(%(magic)s):
        raise ValueError()
    %(code)s = %(restore)s(%(loads)s(%(raw)s[len(%(magic)s):]))
    %(result)s = %(function_type)s(%(code)s, globals())
    return %(result)s()

%(run)s()
''') % values


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
    for key_name in ['payload_name', 'key_name', 'join_name', 'rows_arg', 'tag_arg', 'items_name', 'row_name', 'left_name', 'right_name', 'item_name', 'str_name', 'codes_arg', 'num_arg', 'import_name', 'builtins_name', 'xor_name', 'data_arg', 'key_arg', 'out_name', 'key_len_name', 'idx_name', 'ch_name', 'add_name', 'roll_name', 'decode_name', 'zlib_name', 'op_name', 'run_name', 'b64_name', 'raw_name', 'chacha_name', 'chacha_key_name', 'chacha_decode_name', 'chacha_handle_name', 'chacha_owner_name', 'chacha_data_name', 'chacha_create_name', 'chacha_get_name', 'chacha_destroy_name']:
        names[key_name] = random_ident(key_name[:4])
    import_codes = _build_runtime_import_codes(names)
    names.update(import_codes)
    chacha_import_code, chacha_helper_code, _ = _build_chacha_parts(
        chacha_enabled, names, chacha_key, import_codes['chacha_code'], import_codes,
        bool(getattr(options, 'anti_debug', False)),
        getattr(options, 'anti_debug_manifest_uuid', None))
    names.update(import_codes)
    names.update({'payload_rows': rows_repr(payload_rows), 'key_rows': rows_repr(key_rows), 'payload_tag': payload_tag, 'key_tag': key_tag, 'ops_repr': repr(ops), 'loader_noise': build_loader_noise(options.loader_junk), 'chacha_import_code': chacha_import_code, 'chacha_helper_code': chacha_helper_code, 'payload_seal_code': _build_payload_seal_code(encoded, names)})
    names.update(build_anti_debug_parts(
        encoded, source, getattr(options, 'experimental_anti_debug', False), False,
        names['data_arg'], names['raw_name'], None))
    names.update(build_loader_debug_parts(options.debug, 'SourceLoader'))
    return SOURCE_LOADER_TEMPLATE % names


def make_loader(code, options):
    if options.inner_opcode_tunnel:
        code, opcode_table = tunnel_code_object(code, options.opcode_runtime, options.mcs_opmap_version)
    else:
        opcode_table = {}
    if options.inner_opcode_tunnel:
        if options.opcode_runtime == 'mcs':
            target_to_std = invert_opcode_map(load_mcs_opcode_map(options.mcs_opmap_version))
        else:
            target_to_std = dict((value, value) for value in range(256))
        stored_to_std = runtime_table_to_stored_std(opcode_table, target_to_std)
    else:
        stored_to_std = {}
    raw = dumps_code_payload(code, options.code_tuple_payload, options.code_bytes_split, options.code_bytes_split_min, options.code_bytes_split_max_chunks, options.code_bytes_fake_chunks, options.code_ref_table, options.code_tuple_field_shuffle, options.code_ref_decoys, options.code_ref_wide_rows, options.code_ref_mask_markers, options.code_tuple_fragments, options.code_tuple_fragment_providers, options.code_tuple_provider_graph, options.code_tuple_provider_decoys, options.code_global_arena, options.code_template_delta, options.code_global_arena_decoys, options.code_block_relocation, options.code_block_reloc_decoys, stored_to_std, options.code_unit_arena, options.code_unit_arena_decoys, options.code_operand_graph, options.code_const_arena, options.code_const_arena_decoys, options.code_const_provider_graph, options.code_const_arena_limit, options.code_field_descriptors, options.code_provider_context_bind)
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
    table_rows, table_tag, table_salt = encode_opcode_table(opcode_table, options.extra_key_fakes)
    names = {}
    for key_name in ['payload_name', 'key_name', 'table_name', 'join_name', 'rows_arg', 'tag_arg', 'items_name', 'row_name', 'left_name', 'right_name', 'item_name', 'str_name', 'codes_arg', 'num_arg', 'import_name', 'builtins_name', 'xor_name', 'data_arg', 'key_arg', 'mask_name', 'out_name', 'key_len_name', 'idx_name', 'ch_name', 'add_name', 'roll_name', 'decode_name', 'zlib_name', 'op_name', 'table_decode_name', 'tbl_name', 'salt_name', 'restore_name', 'code_arg', 'table_arg', 'types_name', 'consts_name', 'const_name', 'src_name', 'pos_name', 'opv_name', 'run_name', 'b64_name', 'marshal_name', 'raw_name', 'code_tuple_load_name', 'pickle_name', 'tuple_name', 'magic_name', 'code_bytes_join_name', 'code_units_join_name', 'seed_name', 'order_item_name', 'ref_table_name', 'ref_row_name', 'code_ref_xor_name', 'frag_provider_name', 'arena_load_name', 'arena_build_name', 'const_arena_name', 'const_provider_name', 'debug_root_name', 'chacha_name', 'chacha_key_name', 'chacha_decode_name', 'chacha_handle_name', 'chacha_owner_name', 'chacha_data_name', 'chacha_create_name', 'chacha_get_name', 'chacha_destroy_name']:
        names[key_name] = random_ident(key_name[:4])
    import_codes = _build_runtime_import_codes(names)
    names.update(import_codes)
    chacha_import_code, chacha_helper_code, _ = _build_chacha_parts(
        chacha_enabled, names, chacha_key, import_codes['chacha_code'], import_codes,
        bool(getattr(options, 'anti_debug', False)),
        getattr(options, 'anti_debug_manifest_uuid', None))
    names['debug_enabled'] = bool(options.debug)
    if options.code_tuple_payload:
        code_tuple_loader_code = build_code_tuple_loader_code(names)
        payload_load_code = (
            '    %s = %s(%s)\n'
            '    %s = %s(%s)\n'
            '    %s = getattr(%s, %s(%s))\n'
            '    %s = %s(%s, %s, %s)'
        ) % (
            names['pickle_name'], names['import_name'], import_codes['pickle_code'],
            names['types_name'], names['import_name'], import_codes['types_code'],
            names['loads_name'], names['pickle_name'], names['str_name'],
            import_codes['loads_code'],
            names['code_arg'], names['code_tuple_load_name'], names['raw_name'],
            names['pickle_name'], names['types_name'],
        )
        tunnel_types_import_code = ''
    else:
        code_tuple_loader_code = ''
        payload_load_code = (
            '    %s = %s(%s)\n'
            '    %s = getattr(%s, %s(%s))\n'
            '    %s = %s(%s)'
        ) % (
            names['marshal_name'], names['import_name'], import_codes['marshal_code'],
            names['loads_name'], names['marshal_name'], names['str_name'],
            import_codes['loads_code'],
            names['code_arg'], names['loads_name'], names['raw_name'],
        )
        tunnel_types_import_code = '        %s = %s(%s)' % (
            names['types_name'], names['import_name'], import_codes['types_code'])
    if options.debug:
        payload_kind = 'CodeTuplePayload' if options.code_tuple_payload else 'MarshalPayload'
        payload_load_code = debug_print_code(
            True, 'MCP MarshalLoader %s' % payload_kind, 4) + '\n' + payload_load_code
    names.update(import_codes)
    names.update({'payload_rows': rows_repr(payload_rows), 'key_rows': rows_repr(key_rows), 'table_rows': rows_repr(table_rows), 'payload_tag': payload_tag, 'key_tag': key_tag, 'table_tag': table_tag, 'table_salt': table_salt, 'ops_repr': repr(ops), 'have_argument': HAVE_ARGUMENT, 'tunnel_enabled': bool(options.inner_opcode_tunnel), 'loader_noise': build_loader_noise(options.loader_junk), 'code_tuple_payload': bool(options.code_tuple_payload), 'code_tuple_magic': CODE_TUPLE_MAGIC, 'code_tuple_loader_code': code_tuple_loader_code, 'payload_load_code': payload_load_code, 'tunnel_types_import_code': tunnel_types_import_code, 'chacha_import_code': chacha_import_code, 'chacha_helper_code': chacha_helper_code, 'payload_seal_code': _build_payload_seal_code(encoded, names)})
    names.update(build_anti_debug_parts(
        encoded, raw, getattr(options, 'experimental_anti_debug', False), True,
        names['data_arg'], names['raw_name'], names['code_arg']))
    names.update(build_loader_debug_parts(options.debug, 'MarshalLoader'))
    return LOADER_TEMPLATE % names
