# -*- coding: utf-8 -*-
"""Independent AST and bytecode profiles for MCP Armor Easy UI."""

import os


AST_LEVEL_ORDER = ('关闭', '低强度', '中强度', '高强度')
# The bytecode layer is always enabled in Easy UI; levels only change density.
BYTECODE_LEVEL_ORDER = ('低强度', '中强度', '高强度')
PROFILE_ORDER = BYTECODE_LEVEL_ORDER  # compatibility with the first Easy UI
VOLUME_LEVEL_ORDER = ('紧凑', '平衡', '扩展')
TARGET_MODE_ORDER = ('网易模式', '原生模式')
INPUT_MODE_ORDER = ('多文件夹', '单个 PY')
_AST_LEVEL_KEYS = dict(zip(AST_LEVEL_ORDER, ('off', 'low', 'medium', 'high')))
_BYTECODE_LEVEL_KEYS = dict(zip(BYTECODE_LEVEL_ORDER, ('low', 'medium', 'high')))

AST_FEATURE_LABELS = (
    ('global_rename', '全局名称 Rename'),
    ('module_rename', '文件/文件夹 Rename'),
    ('string_xor', '动态 XOR 字符串加密'),
    ('string_split', '字符串分割'),
    ('linearize_calls', '链式调用拆分'),
    ('schedule', '表达式安全调度'),
    ('constant_pool', '常量池'),
    ('constant_rewrite', '整数常量改写'),
    ('exception_shell', '轻量异常壳'),
    ('dead_flow', '不可达假分支'),
    ('vm', 'AST VM 虚拟化'),
    ('parenthesis_noise', '括号视觉噪声'),
    ('comment_noise', '注释视觉噪声'),
)
AST_FEATURE_KEYS = tuple(key for key, _label in AST_FEATURE_LABELS)
AST_TUNABLE_KEYS = ('vm_ratio',)

# These controls expose the newer structural layers without forcing them on
# every Easy UI profile.  They deliberately map to proven option groups.
ADVANCED_FEATURE_LABELS = (
    ('interprocedural_flow', '跨函数流绑定'),
    ('provider_graph', '常量 Provider 图'),
    ('template_variation', '模板多态'),
)
ADVANCED_FEATURE_KEYS = tuple(key for key, _label in ADVANCED_FEATURE_LABELS)


_COMMON = {
    'project': {
        'folder': True,
        'obfuscate_init': False,
        'emit_pyc': False,
        'target_side': 'all',
        'include': ['*.py'],
        'exclude': ['modMain.py', 'config.py', '__init__.py'],
        'clean_output': True,
        'copy_pyc': False,
    },
    'netease': {
        'profile': 'none',
        'fix_register': True,
        'package_name': 'NeteaseMod',
        'namespace': 'Script_NeteaseMod',
    },
    'basic': {
        'preset': 'none',
        'resource_profile': 'balanced',
        'loader_mode': 'cpickle',
        'payload_cipher': 'legacy',
        'anti_debug': False,
        'experimental_anti_debug': False,
        'key_len': 16,
        'filename_mode': 'module',
        'header_mode': 'docstring',
        'debug': False,
    },
    'source': {
        'global_rename': False,
        'module_rename': False,
        'module_rename_exclude': ['modMain.py', 'config.py', '__init__.py'],
        'project_analysis': True,
        'linearize_calls': False,
        'schedule': False,
        'schedule_max_exprs': 4,
        'schedule_window': 8,
        'string_split': False,
        'string_split_parts': 2,
        'string_xor': False,
        'string_xor_mode': 'random',
        'string_xor_text': 'MCP_Shiled',
        'string_xor_number': 173,
        'string_xor_min_length': 4,
        'string_xor_limit': 128,
        'string_xor_variants': 2,
        'string_xor_decoys': 1,
        'string_xor_debug': False,
        'constant_pool': False,
        'constant_pool_min': 4,
        'constant_pool_max': 64,
        'constant_rewrite': False,
        'constant_rewrite_limit': 4,
        'exception_shell': False,
        'parenthesis_noise': False,
        'comment_noise': False,
        'comment_noise_count': 1,
        'dead_flow': False,
        'dead_flow_blocks': 1,
        'vm': False,
        'vm_full': False,
        'vm_ratio': 0,
        'vm_min_ops': 8,
        'vm_max_ops': 80,
        'vm_max_functions': 24,
        'vm_allow_loops': False,
        'flow_hardening': False,
        'internal_predicates': False,
        'internal_predicate_ratio': 55,
        'vm_dialects': 1,
        'vm_flow_constants': False,
        'reference_obf': False,
        'tuple_arg_decoys': 0,
        'dotzero_relay': False,
        'default_capsule': False,
        'identity_weave': False,
        'identity_ratio': 35,
        'identity_max': 8,
        'identity_variation': False,
        'decompiler_carriers': 0,
        'decoy_docstrings': False,
        'exception_lattice': False,
        'class_body_trap': False,
    },
    'bytecode': {
        'enabled': True,
        'loader_mode': 'cpickle',
        'code_tuple_payload': True,
        'opcode_replacement': True,
        'opcode_runtime': 'mcs',
        'mcs_opmap_version': 1,
        'runtime_opcode_layer': False,
        'per_code_runtime_opcode': False,
        'inner_opcode_tunnel': False,
        'opcode_exclude': [],
        'code_bytes_split': False,
        'code_ref_table': False,
        'code_tuple_field_shuffle': False,
        'code_tuple_fragments': False,
        'code_tuple_fragment_providers': False,
        'code_tuple_provider_graph': False,
        'code_tuple_provider_decoys': 0,
        'code_field_descriptors': False,
        'code_provider_context_bind': False,
        'code_fused_restore': False,
        'loader_reference_cleanup': False,
        'code_capsule_proxy': False,
        'code_capsule_protocol_guard': False,
        'code_global_arena': False,
        'code_block_relocation': False,
        'code_unit_arena': False,
        'code_operand_graph': False,
        'code_const_arena': False,
        'code_const_arena_decoys': 0,
        'code_const_provider_graph': False,
        'code_const_arena_limit': 1024,
        'stack_pad': 0,
        'lnotab_noise': 0,
        'const_salts': 0,
        'name_chaff': 0,
        'entry_noise': 0,
        'exception_decoys': 0,
        'stack_noise': False,
        'jump_inversion': False,
        'jump_trampolines': False,
        'strategy_variation': False,
        'delayed_const_access': False,
        'extended_arg_prefix': False,
        'slot_mirage': False,
        'bytecode_flow': False,
        'bytecode_flow_ratio': 0,
        'bytecode_flow_max_edges': 0,
        'bytecode_flow_loop_dispatch': False,
        'bytecode_flow_block_seeds': False,
        'bytecode_flow_block_seed_ratio': 0,
        'bytecode_flow_block_seed_max_blocks': 32,
        'bytecode_flow_block_shuffle': False,
        'bytecode_flow_block_shuffle_ratio': 0,
        'bytecode_flow_block_shuffle_max_blocks': 96,
        'bytecode_taken_jump_poison': False,
        'safe_dead_blocks': False,
        'safe_dead_interval': 40,
        'safe_dead_width': 2,
        'safe_dead_limit': 1,
        'oparg_poison': False,
        'real_block_reorder': False,
        'real_block_reorder_limit': 2,
        'bytecode_opaque_predicates': False,
        'bytecode_opaque_interval': 36,
        'bytecode_opaque_width': 2,
        'bytecode_opaque_limit': 2,
        'bytecode_decoy_islands': False,
        'bytecode_decoy_island_ratio': 12,
        'bytecode_decoy_island_limit': 1,
        'bytecode_decoy_island_width': 3,
        'bytecode_decoy_island_growth': 8,
        'index_pool_shuffle': False,
        'index_pool_mirrors': 0,
        'const_ref_chains': 0,
        'bytecode_stack_noise': False,
        'bytecode_stack_noise_interval': 24,
        'bytecode_stack_noise_limit': 2,
        'bytecode_jump_inversion': False,
        'bytecode_jump_inversion_limit': 2,
        'bytecode_jump_trampolines': False,
        'bytecode_jump_trampoline_limit': 2,
        'bytecode_delayed_const_access': False,
        'bytecode_delayed_const_limit': 3,
        'bytecode_entry_noise': 0,
        'bytecode_exception_decoys': 0,
        'slot_mirage': False,
        'slot_mirage_limit': 8,
        'bytecode_strategy_variation': False,
        'bytecode_strategy_seed': 0,
    },
    'outer': {
        'payload_splits': 1,
        'loader_junk': 0,
        'trampoline_layers': 0,
        'fake_payload_mirrors': 0,
        'payload_graph_split': False,
        'payload_graph_decoys': 0,
        'outer_decompiler_baits': 0,
    },
}


_AST_LEVELS = {
    'off': {},
    'low': {
        'global_rename': True,
        'module_rename': True,
        'string_xor': True,
        'string_split': True,
    },
    'medium': {
        'global_rename': True,
        'module_rename': True,
        'string_xor': True,
        'string_split': True,
        'linearize_calls': True,
        'schedule': True,
        'constant_pool': True,
        'vm': True,
        'vm_ratio': 12,
        'vm_min_ops': 8,
        'vm_max_ops': 80,
        'vm_max_functions': 16,
        'string_split_parts': 3,
        'string_xor_limit': 256,
        'string_xor_variants': 3,
    },
    'high': {
        'global_rename': True,
        'module_rename': True,
        'string_xor': True,
        'string_split': True,
        'linearize_calls': True,
        'schedule': True,
        'constant_pool': True,
        'constant_rewrite': True,
        'exception_shell': True,
        'dead_flow': True,
        'vm': True,
        'vm_ratio': 28,
        'vm_min_ops': 5,
        'vm_max_ops': 160,
        'vm_max_functions': 48,
        'parenthesis_noise': True,
        'comment_noise': True,
        'string_split_parts': 4,
        'string_xor_limit': 512,
        'string_xor_variants': 4,
        'string_xor_decoys': 2,
        'constant_rewrite_limit': 6,
        'comment_noise_count': 2,
        # One cold type/descriptor carrier mirrors the proven Python-2
        # introspection anchors without touching live NetEase objects.
        'decompiler_carriers': 1,
    },
}


BYTECODE_OPTION_KEYS = (
    'bytecode_flow_ratio',
    'bytecode_flow_max_edges',
    'bytecode_flow_block_seeds',
    'bytecode_flow_block_seed_ratio',
    'bytecode_flow_block_shuffle',
    'bytecode_flow_block_shuffle_ratio',
    'bytecode_flow_loop_dispatch',
)


_BYTECODE_LEVELS = {
    'low': {
        'basic': {'resource_profile': 'compact', 'loader_mode': 'cpickle'},
        'bytecode': {
            'bytecode_flow': True,
            'bytecode_flow_ratio': 25,
            'bytecode_flow_max_edges': 2,
            'bytecode_taken_jump_poison': True,
            'safe_dead_blocks': True,
            'safe_dead_interval': 40,
            'safe_dead_width': 2,
            'safe_dead_limit': 1,
            'oparg_poison': True,
            'bytecode_stack_noise': True,
            'bytecode_stack_noise_interval': 30,
            'bytecode_stack_noise_limit': 1,
            'bytecode_jump_inversion': True,
            'bytecode_jump_inversion_limit': 1,
            'bytecode_strategy_variation': True,
            'stack_pad': 2,
            'lnotab_noise': 1,
            'const_salts': 4,
            'name_chaff': 4,
        },
    },
    'medium': {
        'basic': {'resource_profile': 'balanced', 'loader_mode': 'cpickle'},
        'bytecode': {
            'bytecode_flow': True,
            'bytecode_flow_ratio': 50,
            'bytecode_flow_max_edges': 4,
            'bytecode_flow_block_seeds': True,
            'bytecode_flow_block_seed_ratio': 35,
            'bytecode_flow_block_seed_max_blocks': 32,
            'bytecode_taken_jump_poison': True,
            'safe_dead_blocks': True,
            'safe_dead_interval': 28,
            'safe_dead_width': 3,
            'safe_dead_limit': 2,
            'oparg_poison': True,
            'bytecode_stack_noise': True,
            'bytecode_stack_noise_interval': 24,
            'bytecode_stack_noise_limit': 2,
            'bytecode_jump_inversion': True,
            'bytecode_jump_inversion_limit': 2,
            'bytecode_jump_trampolines': True,
            'bytecode_jump_trampoline_limit': 2,
            'bytecode_opaque_predicates': True,
            'bytecode_opaque_interval': 36,
            'bytecode_opaque_width': 2,
            'bytecode_opaque_limit': 2,
            'bytecode_decoy_islands': True,
            'bytecode_decoy_island_ratio': 12,
            'bytecode_decoy_island_limit': 1,
            'bytecode_decoy_island_width': 3,
            'bytecode_decoy_island_growth': 8,
            'bytecode_strategy_variation': True,
            'code_bytes_split': True,
            'code_ref_table': True,
            'code_ref_decoys': 3,
            'code_ref_wide_rows': False,
            'code_ref_mask_markers': True,
            'code_tuple_field_shuffle': True,
            'loader_reference_cleanup': True,
            'stack_pad': 4,
            'lnotab_noise': 2,
            'const_salts': 8,
            'name_chaff': 8,
        },
        'outer': {'loader_junk': 1, 'trampoline_layers': 1},
    },
    'high': {
        'basic': {'resource_profile': 'strong', 'loader_mode': 'cpickle'},
        'bytecode': {
            'bytecode_flow': True,
            'bytecode_flow_ratio': 75,
            'bytecode_flow_max_edges': 6,
            'bytecode_flow_block_seeds': True,
            'bytecode_flow_block_seed_ratio': 65,
            'bytecode_flow_block_seed_max_blocks': 64,
            'bytecode_flow_block_shuffle': True,
            'bytecode_flow_block_shuffle_ratio': 45,
            'bytecode_flow_block_shuffle_max_blocks': 128,
            'bytecode_taken_jump_poison': True,
            'safe_dead_blocks': True,
            'safe_dead_interval': 20,
            'safe_dead_width': 4,
            'safe_dead_limit': 3,
            'oparg_poison': True,
            'real_block_reorder': False,
            'real_block_reorder_limit': 2,
            'bytecode_stack_noise': True,
            'bytecode_stack_noise_interval': 18,
            'bytecode_stack_noise_limit': 4,
            'bytecode_jump_inversion': True,
            'bytecode_jump_inversion_limit': 4,
            'bytecode_jump_trampolines': True,
            'bytecode_jump_trampoline_limit': 4,
            'bytecode_opaque_predicates': True,
            'bytecode_opaque_interval': 28,
            'bytecode_opaque_width': 3,
            'bytecode_opaque_limit': 3,
            'bytecode_decoy_islands': True,
            'bytecode_decoy_island_ratio': 25,
            'bytecode_decoy_island_limit': 2,
            'bytecode_decoy_island_width': 4,
            'bytecode_decoy_island_growth': 12,
            'index_pool_shuffle': True,
            'index_pool_mirrors': 4,
            'const_ref_chains': 2,
            'bytecode_delayed_const_access': True,
            'bytecode_delayed_const_limit': 3,
            'bytecode_entry_noise': 1,
            'bytecode_exception_decoys': 1,
            'slot_mirage': True,
            'slot_mirage_limit': 4,
            'bytecode_strategy_variation': True,
            'code_bytes_split': True,
            'code_bytes_split_min': 48,
            'code_bytes_split_max_chunks': 6,
            'code_bytes_fake_chunks': 2,
            'code_ref_table': True,
            'code_ref_decoys': 8,
            'code_ref_wide_rows': True,
            'code_ref_mask_markers': True,
            'code_tuple_field_shuffle': True,
            'code_tuple_fragments': True,
            'code_tuple_fragment_providers': True,
            'code_tuple_provider_graph': True,
            'code_tuple_provider_decoys': 4,
            'code_fused_restore': True,
            'loader_reference_cleanup': True,
            'code_capsule_proxy': True,
            'code_capsule_protocol_guard': True,
            'stack_pad': 6,
            'lnotab_noise': 3,
            'const_salts': 12,
            'name_chaff': 12,
            'strategy_variation': True,
            'strategy_seed': 0,
        },
        'outer': {
            'loader_junk': 2,
            'trampoline_layers': 1,
            'payload_splits': 2,
        },
    },
}


_VOLUME_LEVELS = {
    # Volume changes density and payload shape only.  The advanced feature
    # switches below still decide whether an optional feature family is used.
    '紧凑': {
        'basic': {'resource_profile': 'compact'},
        'source': {
            'string_xor_limit': 128,
            'string_xor_variants': 2,
            'string_xor_decoys': 0,
            'vm_max_functions': 8,
            'comment_noise_count': 1,
        },
        'bytecode': {
            'code_tuple_provider_decoys': 0,
            'code_const_arena_decoys': 0,
        },
        'outer': {'payload_splits': 1, 'loader_junk': 0},
    },
    '平衡': {
        'basic': {'resource_profile': 'balanced'},
        'source': {
            'string_xor_limit': 256,
            'string_xor_variants': 3,
            'string_xor_decoys': 1,
            'vm_max_functions': 16,
            'comment_noise_count': 1,
        },
        'bytecode': {
            'code_tuple_provider_decoys': 2,
            'code_const_arena_decoys': 2,
        },
        'outer': {'payload_splits': 1, 'loader_junk': 1},
    },
    '扩展': {
        'basic': {'resource_profile': 'strong'},
        'source': {
            'string_xor_limit': 512,
            'string_xor_variants': 4,
            'string_xor_decoys': 2,
            'vm_max_functions': 32,
            'comment_noise_count': 2,
        },
        'bytecode': {
            'code_tuple_provider_decoys': 6,
            'code_const_arena_decoys': 8,
        },
        'outer': {'payload_splits': 2, 'loader_junk': 2},
    },
}


def _copy_tree(value):
    if isinstance(value, dict):
        return dict((key, _copy_tree(item)) for key, item in value.items())
    if isinstance(value, list):
        return list(value)
    return value


def _merge(target, patch):
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge(target[key], value)
        else:
            target[key] = _copy_tree(value)


def ast_defaults(level):
    if level not in _AST_LEVEL_KEYS:
        raise ValueError('unknown AST level: %s' % level)
    source = dict((key, False) for key in AST_FEATURE_KEYS)
    for key, value in _AST_LEVELS[_AST_LEVEL_KEYS[level]].items():
        if key in source:
            source[key] = value
    return source


def ast_tunable_defaults(level):
    """Return numeric AST controls associated with a strength preset."""
    if level not in _AST_LEVEL_KEYS:
        raise ValueError('unknown AST level: %s' % level)
    patch = _AST_LEVELS[_AST_LEVEL_KEYS[level]]
    return {
        'vm_ratio': int(patch.get('vm_ratio', _COMMON['source']['vm_ratio'])),
    }


def bytecode_defaults(level):
    """Return the visible ByteCode_Flow controls for one strength level."""
    if level not in _BYTECODE_LEVEL_KEYS:
        raise ValueError('unknown bytecode level: %s' % level)
    patch = _BYTECODE_LEVELS[_BYTECODE_LEVEL_KEYS[level]]['bytecode']
    return dict((key, patch.get(key, _COMMON['bytecode'].get(key)))
                for key in BYTECODE_OPTION_KEYS)


def advanced_defaults(ast_level, bytecode_level, volume_level='平衡'):
    """Return the visible structural-layer defaults for an Easy UI preset."""
    if ast_level not in _AST_LEVEL_KEYS:
        raise ValueError('unknown AST level: %s' % ast_level)
    if bytecode_level not in _BYTECODE_LEVEL_KEYS:
        raise ValueError('unknown bytecode level: %s' % bytecode_level)
    if volume_level not in VOLUME_LEVEL_ORDER:
        raise ValueError('unknown volume level: %s' % volume_level)
    return {
        'interprocedural_flow': _AST_LEVEL_KEYS[ast_level] == 'high',
        'provider_graph': _BYTECODE_LEVEL_KEYS[bytecode_level] == 'high',
        'template_variation': _BYTECODE_LEVEL_KEYS[bytecode_level] in (
            'medium', 'high'),
    }


def build_profile(ast_level='中强度', bytecode_level=None, input_path='',
                  output_path='', debug=False, ast_options=None,
                  target_mode='网易模式', input_mode='多文件夹',
                  bytecode_options=None, exclude_patterns=None,
                  anti_debug=False, advanced_options=None,
                  volume_level='平衡', python27='', static_check=False):
    """Build a complete config with independently selectable layers.

    ``bytecode_level=None`` keeps compatibility with the original one-level
    Easy UI API by applying ``ast_level`` to both layers.
    """
    if bytecode_level is None:
        bytecode_level = ast_level if ast_level in _BYTECODE_LEVEL_KEYS else '中强度'
    if ast_level not in _AST_LEVEL_KEYS:
        raise ValueError('unknown AST level: %s' % ast_level)
    if bytecode_level not in _BYTECODE_LEVEL_KEYS:
        raise ValueError('unknown bytecode level: %s' % bytecode_level)
    if target_mode not in TARGET_MODE_ORDER:
        raise ValueError('unknown target mode: %s' % target_mode)
    if input_mode not in INPUT_MODE_ORDER:
        raise ValueError('unknown input mode: %s' % input_mode)
    if volume_level not in VOLUME_LEVEL_ORDER:
        raise ValueError('unknown volume level: %s' % volume_level)
    config = _copy_tree(_COMMON)
    config['source'].update(_AST_LEVELS[_AST_LEVEL_KEYS[ast_level]])
    _merge(config, _BYTECODE_LEVELS[_BYTECODE_LEVEL_KEYS[bytecode_level]])
    _merge(config, _VOLUME_LEVELS[volume_level])
    if ast_options:
        for key in AST_FEATURE_KEYS:
            if key in ast_options:
                config['source'][key] = bool(ast_options[key])
        if 'vm_ratio' in ast_options:
            config['source']['vm_ratio'] = max(
                0, min(100, int(ast_options['vm_ratio'])))
    if bytecode_options:
        for key in BYTECODE_OPTION_KEYS:
            if key in bytecode_options:
                config['bytecode'][key] = bytecode_options[key]
    for pattern in exclude_patterns or ():
        pattern = str(pattern).strip().replace('\\', '/')
        if pattern and pattern not in config['project']['exclude']:
            config['project']['exclude'].append(pattern)
    # Full VM and its coupled experimental layers stay outside Easy UI.  The
    # bounded AST VM above is enabled by medium/high strength profiles.
    for key in ('vm_full', 'flow_hardening', 'internal_predicates',
                'reference_obf', 'identity_weave'):
        config['source'][key] = False
    # ``None`` retains compatibility with callers of the first Easy UI
    # profile API.  The current UI always sends an explicit three-switch map.
    if advanced_options is not None:
        source = config['source']
        bytecode = config['bytecode']
        if bool(advanced_options.get('interprocedural_flow')):
            source['flow_hardening'] = True
            source['internal_predicates'] = True
            source['internal_predicate_ratio'] = 55
            source['vm'] = True
            source['vm_dialects'] = max(4, int(source['vm_dialects']))
            source['vm_flow_constants'] = True
        else:
            source['flow_hardening'] = False
            source['internal_predicates'] = False
            source['vm_flow_constants'] = False

        if bool(advanced_options.get('provider_graph')):
            bytecode['code_tuple_field_shuffle'] = True
            bytecode['code_tuple_fragments'] = True
            bytecode['code_tuple_fragment_providers'] = True
            bytecode['code_tuple_provider_graph'] = True
            bytecode['code_const_arena'] = True
            bytecode['code_const_provider_graph'] = True
            bytecode['code_field_descriptors'] = True
            bytecode['code_provider_context_bind'] = True
            bytecode['code_fused_restore'] = True
            bytecode['loader_reference_cleanup'] = True
        else:
            for key in ('code_tuple_fragments', 'code_tuple_fragment_providers',
                        'code_tuple_provider_graph', 'code_const_arena',
                        'code_const_provider_graph', 'code_field_descriptors',
                        'code_provider_context_bind', 'code_fused_restore'):
                bytecode[key] = False
            bytecode['code_tuple_provider_decoys'] = 0
            bytecode['code_const_arena_decoys'] = 0

        if bool(advanced_options.get('template_variation')):
            bytecode['strategy_variation'] = True
            bytecode['bytecode_strategy_variation'] = True
            source['identity_weave'] = True
            source['identity_variation'] = True
            source['identity_ratio'] = 35
            source['identity_max'] = 8
            source['default_capsule'] = True
        else:
            bytecode['strategy_variation'] = False
            bytecode['bytecode_strategy_variation'] = False
            source['identity_weave'] = False
            source['identity_variation'] = False
    # Easy UI invariants: bytecode, ByteCode_Flow and both poison forms remain
    # enabled even when the visible density controls are adjusted.
    config['bytecode']['enabled'] = True
    config['bytecode']['bytecode_flow'] = True
    config['bytecode']['bytecode_taken_jump_poison'] = True
    config['bytecode']['safe_dead_blocks'] = True
    config['bytecode']['oparg_poison'] = True
    if target_mode == '原生模式':
        config['netease']['fix_register'] = False
        config['basic']['loader_mode'] = 'function'
        config['bytecode']['opcode_replacement'] = False
        config['bytecode']['opcode_runtime'] = 'std'
        config['bytecode']['mcs_opmap_version'] = 0
        anti_debug = False
    config['basic']['anti_debug'] = bool(anti_debug)
    config['basic']['payload_cipher'] = (
        'chacha' if anti_debug else 'legacy')
    if input_mode == '单个 PY':
        config['project']['folder'] = False
        config['project']['exclude'] = []
        config['source']['module_rename'] = False
    config['project']['input'] = os.path.abspath(input_path) if input_path else ''
    config['project']['output'] = os.path.abspath(output_path) if output_path else ''
    config['basic']['debug'] = bool(debug)
    if python27:
        config['runtime'] = {'python27': os.path.abspath(python27)}
    config['static_check'] = {'enabled': bool(static_check)}
    return config


def _yaml_scalar(value):
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if value is None:
        return 'null'
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value).replace('\\', '/').replace('"', '\\"')
    return '"%s"' % text


def render_yaml(config):
    lines = ['# generated by MCP_Armor_Easy_UI']
    def emit(mapping, indent):
        for key, value in mapping.items():
            pad = ' ' * indent
            if isinstance(value, dict):
                lines.append('%s%s:' % (pad, key))
                emit(value, indent + 2)
            elif isinstance(value, list):
                lines.append('%s%s:' % (pad, key))
                if value:
                    for item in value:
                        lines.append('%s  - %s' % (pad, _yaml_scalar(item)))
                else:
                    lines.append('%s  []' % pad)
            else:
                lines.append('%s%s: %s' % (pad, key, _yaml_scalar(value)))
    emit(config, 0)
    return '\n'.join(lines) + '\n'


# Optional controls added after the original profile table so older saved
# profiles remain loadable while Easy UI exposes function splitting and the
# deterministic output watermark date.
if not any(key == 'function_split' for key, _label in AST_FEATURE_LABELS):
    AST_FEATURE_LABELS = AST_FEATURE_LABELS + (('function_split', 'Function Split'),)
    AST_FEATURE_KEYS = tuple(key for key, _label in AST_FEATURE_LABELS)
_COMMON['basic']['output_date'] = '2012-03-15'
_COMMON['source']['function_split'] = False


def profile_summary(ast_level, bytecode_level=None):
    if bytecode_level is None:
        bytecode_level = ast_level if ast_level in _BYTECODE_LEVEL_KEYS else '中强度'
    enabled = sum(1 for value in ast_defaults(ast_level).values() if value)
    bytecode = {
        '低强度': 'ByteCode_Flow 25% + JMP 花指令/oparg 错位',
        '中强度': 'ByteCode_Flow 50% + 块种子 + JMP 花指令/oparg 错位',
        '高强度': 'ByteCode_Flow 75% + 块重排 + JMP 花指令/oparg 错位',
    }[bytecode_level]
    return 'AST：%s（%d 项）  ·  字节码：%s' % (ast_level, enabled, bytecode)
