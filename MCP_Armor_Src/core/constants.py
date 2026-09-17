# -*- coding: utf-8 -*-
"""Opcode constants, presets and NetEase compatibility profiles."""


from MCP_Armor_Src.core import py27_opcode as opcode
import sys


PY2 = sys.version_info[0] == 2


HAVE_ARGUMENT = opcode.HAVE_ARGUMENT


NOP = opcode.opmap.get('NOP', 9)


LOAD_CONST = opcode.opmap.get('LOAD_CONST', 100)


LOAD_FAST = opcode.opmap.get('LOAD_FAST', 124)


COMPARE_OP = opcode.opmap.get('COMPARE_OP', 107)


POP_TOP = opcode.opmap.get('POP_TOP', 1)


STORE_FAST = opcode.opmap.get('STORE_FAST', 125)


DELETE_FAST = opcode.opmap.get('DELETE_FAST', 126)


JUMP_FORWARD = opcode.opmap.get('JUMP_FORWARD', 110)


EXTENDED_ARG = opcode.opmap.get('EXTENDED_ARG', 143)


JUMP_ABSOLUTE = opcode.opmap.get('JUMP_ABSOLUTE', 113)


RETURN_VALUE = opcode.opmap.get('RETURN_VALUE', 83)


POP_JUMP_IF_FALSE = opcode.opmap.get('POP_JUMP_IF_FALSE', 114)


POP_JUMP_IF_TRUE = opcode.opmap.get('POP_JUMP_IF_TRUE', 115)


BINARY_SUBSCR = opcode.opmap.get('BINARY_SUBSCR', 25)


CO_OPTIMIZED = 0x0001


CO_NEWLOCALS = 0x0002


CO_VARARGS = 0x0004


CO_VARKEYWORDS = 0x0008


CO_GENERATOR = 0x0020


NAME_INDEX_OPS = set([opcode.opmap[name] for name in (
    'STORE_NAME', 'DELETE_NAME', 'LOAD_NAME',
    'STORE_ATTR', 'DELETE_ATTR', 'LOAD_ATTR',
    'STORE_GLOBAL', 'DELETE_GLOBAL', 'LOAD_GLOBAL',
    'IMPORT_NAME', 'IMPORT_FROM')
    if name in opcode.opmap])


FAST_INDEX_OPS = set([opcode.opmap[name] for name in (
    'LOAD_FAST', 'STORE_FAST', 'DELETE_FAST')
    if name in opcode.opmap])


DEFAULT_NAMESPACE = 'Script_NeteaseMod'


DEFAULT_PACKAGE = 'NeteaseMod'


DEFAULT_TAUNT_TEXT = 'ShitArmor_DEOBF'


CODE_TUPLE_MAGIC = '\xa0\x85\xab\x93'


CODE_BYTES_SPLIT_MAGIC = 'BCS1'


CODE_REF_TABLE_MAGIC = 'COREF1'


CODE_TUPLE_SHUFFLE_MAGIC = 'COTSH1'


CODE_REF_MASK_MAGIC = 'CORM1'


CODE_TUPLE_FRAG_MAGIC = 'COTFR1'


CODE_TUPLE_PROVIDER_MAGIC = 'COTPV1'


CODE_TUPLE_PROVIDER_GRAPH_MAGIC = 'COTPG1'


CODE_FIELD_OBJECT_MAGIC = 'COFO1'


CODE_FIELD_DESCRIPTOR_MAGIC = 'COFD1'


CODE_FIELD_PROVIDER_MAGIC = 'COFPV1'


CODE_FIELD_ARENA_CONTEXT_MAGIC = 'COFAC1'


CODE_GLOBAL_ARENA_MAGIC = 'COGAR1'


CODE_GLOBAL_ARENA_REF_MAGIC = 'COGARREF1'


CODE_GLOBAL_ARENA_NODE_MAGIC = 'COGARN1'


CODE_GLOBAL_ARENA_ROW_MAGIC = 'COGARR1'


CODE_BLOCK_RELOC_MAGIC = 'COBR1'


CODE_BLOCK_RELOC_ROW_MAGIC = 'COBRR1'


CODE_UNIT_ARENA_MAGIC = 'COUA1'


CODE_UNIT_ARENA_ROW_MAGIC = 'COUAR1'


CODE_CONST_ARENA_REF_MAGIC = 'COCARREF1'


CODE_CONST_ARENA_ROW_MAGIC = 'COCARR1'


CODE_CONST_PROVIDER_MAGIC = 'COCAPV1'


MCP_SHILED_VERSION = '1.0'


MCP_SHILED_ART = r'''88b           d88    ,ad8888ba,   88888888ba        ad88888ba   88           88  88                       88
888b         d888   d8"'    `"8b  88      "8b      d8"     "8b  88           ""  88                       88
88`8b       d8'88  d8'            88      ,8P      Y8,          88               88                       88
88 `8b     d8' 88  88             88aaaaaa8P'      `Y8aaaaa,    88,dPPYba,   88  88   ,adPPYba,   ,adPPYb,88
88  `8b   d8'  88  88             88""""""'          `"""""8b,  88P'    "8a  88  88  a8P_____88  a8"    `Y88
88   `8b d8'   88  Y8,            88                       `8b  88       88  88  88  8PP"""""""  8b       88
88    `888'    88   Y8a.    .a8P  88               Y8a     a8P  88       88  88  88  "8b,   ,aa  "8a,   ,d88
88     `8'     88    `"Y8888Y"'   88                "Y88888P"   88       88  88  88   `"Ybbd8"'   `"8bbdP"Y8'''


def is_function_code(co):
    return bool((co.co_flags & CO_OPTIMIZED) and (co.co_flags & CO_NEWLOCALS))


PRESETS = {
    'none': {'const_noise': 0, 'tail_noise': 0, 'extra_payload_fakes': 0, 'extra_key_fakes': 0, 'loader_junk': 0, 'trampoline_layers': 0, 'decoy_opcode_rows': 0, 'fake_ref_layers': 0, 'chunk_min': 48, 'chunk_max': 96, 'compress_level': 6, 'source_linearize_calls': False, 'source_schedule': False, 'source_schedule_max_exprs': 4, 'source_schedule_window': 8},
    'safe': {'const_noise': 3, 'tail_noise': 1, 'extra_payload_fakes': 3, 'extra_key_fakes': 3, 'loader_junk': 1, 'trampoline_layers': 1, 'decoy_opcode_rows': 8, 'fake_ref_layers': 2, 'chunk_min': 32, 'chunk_max': 76, 'compress_level': 6, 'source_linearize_calls': False, 'source_schedule': False, 'source_schedule_max_exprs': 4, 'source_schedule_window': 8},
    'strong': {'const_noise': 7, 'tail_noise': 2, 'extra_payload_fakes': 12, 'extra_key_fakes': 9, 'loader_junk': 3, 'trampoline_layers': 2, 'decoy_opcode_rows': 24, 'fake_ref_layers': 5, 'chunk_min': 20, 'chunk_max': 58, 'compress_level': 9, 'source_linearize_calls': False, 'source_schedule': False, 'source_schedule_max_exprs': 5, 'source_schedule_window': 10},
    'max': {'const_noise': 12, 'tail_noise': 3, 'extra_payload_fakes': 24, 'extra_key_fakes': 16, 'loader_junk': 6, 'trampoline_layers': 3, 'decoy_opcode_rows': 48, 'fake_ref_layers': 9, 'chunk_min': 12, 'chunk_max': 40, 'compress_level': 9, 'source_linearize_calls': False, 'source_schedule': False, 'source_schedule_max_exprs': 6, 'source_schedule_window': 12},
    'experimental': {'const_noise': 16, 'tail_noise': 4, 'extra_payload_fakes': 36, 'extra_key_fakes': 24, 'loader_junk': 9, 'trampoline_layers': 4, 'decoy_opcode_rows': 72, 'fake_ref_layers': 12, 'chunk_min': 8, 'chunk_max': 32, 'compress_level': 9, 'source_linearize_calls': False, 'source_schedule': False, 'source_schedule_max_exprs': 8, 'source_schedule_window': 14},
}


NETEASE_PROFILES = {
    'none': {},
    # Selected high-value layers: cold-function AST VM, verified ByteCode_Flow
    # dispatch, recursive constant providers, and per-code template variation.
    # This deliberately leaves opcode replacement off for Python 2/NetEase
    # compatibility; callers can opt into it separately.
    'priority': {
        'preset': 'strong',
        'loader_mode': 'cpickle',
        'code_tuple_payload': True,
        'source_project_analysis': True,
        'source_flow_hardening': True,
        'source_vm': True,
        'source_vm_full': False,
        'source_vm_ratio': 32,
        'source_vm_min_ops': 8,
        'source_vm_max_ops': 220,
        'source_vm_max_functions': 8,
        'source_vm_allow_loops': False,
        'source_vm_dialects': 4,
        'source_vm_flow_constants': True,
        'source_internal_predicates': True,
        'source_internal_predicate_ratio': 55,
        'bytecode_flow': True,
        'bytecode_flow_ratio': 60,
        'bytecode_flow_max_edges': 10,
        'bytecode_flow_loop_dispatch': False,
        'bytecode_flow_block_seeds': True,
        'bytecode_flow_block_seed_ratio': 55,
        'bytecode_flow_block_shuffle': True,
        'bytecode_flow_block_shuffle_ratio': 45,
        'bytecode_strategy_variation': True,
        'bytecode_strategy_seed': 0,
        'code_tuple_field_shuffle': True,
        'code_tuple_fragments': True,
        'code_tuple_fragment_providers': True,
        'code_tuple_provider_graph': True,
        'code_tuple_provider_decoys': 4,
        'code_const_arena': True,
        'code_const_provider_graph': True,
        'code_const_arena_decoys': 4,
        'code_const_arena_limit': 1024,
        'code_field_descriptors': True,
        'code_provider_context_bind': True,
        'code_fused_restore': True,
        'loader_reference_cleanup': True,
        'source_identity_variation': True,
        'source_identity_weave': True,
        'source_identity_ratio': 35,
        'source_identity_max': 8,
    },
    'safe': {
        'preset': 'safe',
        'loader_mode': 'netease-func',
        'opcode_replacement': True,
        'mcs_opmap_version': 1,
        'code_tuple_payload': True,
        'source_linearize_calls': True,
        'source_schedule': True,
        'source_schedule_max_exprs': 4,
        'source_schedule_window': 8,
        'source_only': ['NeteaseClientSystem.py', 'uiScript/*.py'],
        'fake_code_objects': 1,
        'fake_code_nop_bloat': 12,
        'fake_code_stop_bloat': 6,
        'root_const_swamp': 96,
        'dead_bad_bytecode': 1,
        'dead_bad_units': 1,
        'dead_nop_bloat': 12,
        'dead_stop_bloat': 6,
        'dead_arg_poison': 1,
        'dead_exception_poison': 0,
        'dead_call_poison': 0,
        'bytecode_opaque_predicates': True,
        'bytecode_opaque_interval': 32,
        'bytecode_opaque_width': 1,
        'bytecode_opaque_limit': 1,
        'index_pool_shuffle': True,
        'index_pool_mirrors': 4,
        'loader_decoy_tuples': 1,
        'const_ref_chains': 4,
    },
    'strong': {
        'preset': 'safe',
        'loader_mode': 'netease-func',
        'opcode_replacement': True,
        'mcs_opmap_version': 1,
        'code_tuple_payload': True,
        'source_linearize_calls': True,
        'source_schedule': True,
        'source_schedule_max_exprs': 4,
        'source_schedule_window': 8,
        'source_dead_flow': True,
        'source_dead_flow_blocks': 1,
        'source_only': ['NeteaseClientSystem.py', 'uiScript/*.py'],
        'fake_code_objects': 2,
        'fake_code_nop_bloat': 24,
        'fake_code_stop_bloat': 12,
        'root_const_swamp': 192,
        'metadata_poison': True,
        'metadata_binary': True,
        'metadata_name_poison': True,
        'dead_bad_bytecode': 1,
        'dead_bad_units': 2,
        'dead_nop_bloat': 24,
        'dead_stop_bloat': 12,
        'dead_arg_poison': 2,
        'dead_exception_poison': 1,
        'dead_call_poison': 1,
        'bytecode_opaque_predicates': True,
        'bytecode_opaque_interval': 28,
        'bytecode_opaque_width': 2,
        'bytecode_opaque_limit': 2,
        'index_pool_shuffle': True,
        'index_pool_mirrors': 8,
        'loader_decoy_tuples': 3,
        'const_ref_chains': 12,
    },
    'diagnostic': {
        'preset': 'safe',
        'filename_mode': 'keep',
        'loader_mode': 'netease-func',
        'opcode_replacement': True,
        'mcs_opmap_version': 1,
        'code_tuple_payload': True,
        'source_linearize_calls': True,
        'source_schedule': True,
        'source_schedule_max_exprs': 4,
        'source_schedule_window': 8,
        'source_only': ['NeteaseClientSystem.py', 'uiScript/*.py'],
        'fake_code_objects': 2,
        'fake_code_nop_bloat': 24,
        'fake_code_stop_bloat': 12,
        'root_const_swamp': 192,
        'metadata_poison': False,
        'metadata_binary': False,
        'metadata_name_poison': False,
        'dead_bad_bytecode': 1,
        'dead_bad_units': 2,
        'dead_nop_bloat': 24,
        'dead_stop_bloat': 12,
        'dead_arg_poison': 2,
        'dead_exception_poison': 1,
        'dead_call_poison': 1,
        'bytecode_opaque_predicates': True,
        'bytecode_opaque_interval': 28,
        'bytecode_opaque_width': 2,
        'bytecode_opaque_limit': 2,
        'index_pool_shuffle': True,
        'index_pool_mirrors': 8,
        'loader_decoy_tuples': 2,
        'const_ref_chains': 8,
    },
    'strong-plus': {
        'preset': 'safe',
        'loader_mode': 'netease-func',
        'opcode_replacement': True,
        'mcs_opmap_version': 1,
        'code_tuple_payload': True,
        'source_linearize_calls': True,
        'source_schedule': True,
        'source_schedule_max_exprs': 4,
        'source_schedule_window': 8,
        'source_only': ['NeteaseClientSystem.py', 'uiScript/*.py'],
        'fake_code_objects': 2,
        'fake_code_nop_bloat': 24,
        'fake_code_stop_bloat': 12,
        'root_const_swamp': 192,
        'metadata_poison': True,
        'metadata_binary': True,
        'metadata_name_poison': True,
        'dead_bad_bytecode': 1,
        'dead_bad_units': 2,
        'dead_nop_bloat': 24,
        'dead_stop_bloat': 12,
        'dead_arg_poison': 2,
        'dead_exception_poison': 1,
        'dead_call_poison': 1,
        'bytecode_opaque_predicates': True,
        'bytecode_opaque_interval': 28,
        'bytecode_opaque_width': 2,
        'bytecode_opaque_limit': 2,
        'index_pool_shuffle': True,
        'index_pool_mirrors': 8,
        'loader_decoy_tuples': 3,
        'const_ref_chains': 12,
        'code_bytes_split': True,
        'code_bytes_split_min': 48,
        'code_bytes_split_max_chunks': 6,
        'code_bytes_fake_chunks': 4,
        'code_ref_table': True,
        'code_ref_decoys': 8,
        'code_ref_wide_rows': True,
        'code_ref_mask_markers': True,
        'code_tuple_field_shuffle': True,
        'code_tuple_fragments': True,
        'code_tuple_fragment_providers': True,
        'code_tuple_provider_graph': True,
        'code_tuple_provider_decoys': 6,
        'code_capsule_proxy': True,
        'code_capsule_protocol_guard': True,
        'code_field_descriptors': True,
        'code_provider_context_bind': True,
        'code_fused_restore': True,
        'loader_reference_cleanup': True,
        'runtime_opcode_layer': True,
        'bytecode_stack_pad': 8,
        'bytecode_lnotab_noise': 6,
        'bytecode_const_salts': 10,
        'bytecode_name_chaff': 12,
        'bytecode_entry_noise': 0,
        'bytecode_exception_decoys': 0,
        'import_facade_layer': False,
        'slot_mirage': True,
        'slot_mirage_limit': 8,
        'source_tuple_arg_decoys': 2,
        'source_dotzero_relay': True,
        'source_default_capsule': True,
        'source_identity_weave': True,
        'source_identity_ratio': 45,
        'source_identity_max': 12,
        'source_identity_variation': True,
        'source_decompiler_carriers': 1,
        'source_exception_lattice': True,
        'source_class_body_trap': True,
        # Outer Internal Signature Ensemble stage 1: use genuine Python 2
        # tuple-argument slots and a fragmented closure-cell lattice.
        'outer_tuple_gateway': True,
        'outer_closure_index_mirage': True,
        'outer_generator_frame_mirage': True,
        'outer_method_descriptor_mirage': True,
        'outer_defaults_dict_doppelganger': True,
        # Lazy Capsule 2.0: selected cold functions keep an independent
        # encrypted Code Tuple payload and are materialized on first use.
        'lazy_function_capsules': True,
        'lazy_capsule_ratio': 20,
        'lazy_capsule_max_functions': 8,
        'lazy_capsule_mode': 'adaptive',
        'lazy_capsule_retain_calls': 4,
        # Lazy Capsule 3.0: bind independent function keys to the outer
        # module key during bootstrap, then rotate the encrypted record after
        # each hydration.  Only cold functions are selected by default.
        'lazy_capsule_cross_key': True,
        'lazy_capsule_rotate_payload': False,
        'lazy_capsule_rotate_max_bytes': 262144,
        'lazy_capsule_carrier_swap': False,
        'lazy_capsule_manager_proxy': True,
        'lazy_capsule_carrier_route_rotation': False,
        'lazy_capsule_include': [],
        'lazy_capsule_exclude': ['On*', '*Tick*', '*Update*', '*Timer*', '*Frame*', '*Render*', 'Listen*', 'Notify*', 'NeteaseMod*', '__*__'],
        'lazy_capsule_debug': False,
    },
}


NETEASE_PROFILE_ALIASES = {
    'netease-priority': 'priority',
    'priority-strong': 'priority',
    'netease-safe': 'safe',
    'netease-strong': 'strong',
    'netease-strong-plus': 'strong-plus',
    'netease-diagnostic': 'diagnostic',
}
