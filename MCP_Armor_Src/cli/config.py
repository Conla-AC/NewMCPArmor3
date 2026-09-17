# -*- coding: utf-8 -*-
"""YAML parsing, option aliases and NetEase profile application."""


from MCP_Armor_Src.core.constants import (
    NETEASE_PROFILES,
    NETEASE_PROFILE_ALIASES,
)

from MCP_Armor_Src.utils.filesystem import (
    read_file,
)


def parse_scalar(value):
    value = value.strip()
    if value == '':
        return ''
    low = value.lower()
    if low in ('true', 'yes', 'on'):
        return True
    if low in ('false', 'no', 'off'):
        return False
    if low == 'null':
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.startswith('[') and value.endswith(']'):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part.strip()) for part in inner.split(',')]
    try:
        if value.startswith('0x') or value.startswith('0X'):
            return int(value, 16)
        return int(value)
    except Exception:
        return value


def read_config_file(path):
    data = {}
    stack = [(-1, data)]
    pending_list = {}
    source = read_file(path)
    if not isinstance(source, type('')):
        source = source.decode('utf-8-sig')
    for raw in source.splitlines():
        line = raw.split('#', 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(' '))
        text = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if text.startswith('- '):
            key = pending_list.get(indent)
            if key is not None:
                parent = stack[-1][1]
                if not isinstance(parent.get(key), list):
                    parent[key] = []
                parent[key].append(parse_scalar(text[2:].strip()))
            continue
        if ':' not in text:
            continue
        key, value = text.split(':', 1)
        key = key.strip().replace('-', '_')
        value = value.strip()
        if value == '':
            child = {}
            parent[key] = child
            stack.append((indent, child))
            pending_list[indent + 2] = key
        else:
            parent[key] = parse_scalar(value)
            pending_list[indent + 2] = key
    return data


def flatten_config(config, prefix=''):
    flat = {}
    for key, value in list(config.items()):
        name = (prefix + '_' + key) if prefix else key
        if isinstance(value, dict):
            flat.update(flatten_config(value, name))
        else:
            flat[name] = value
            flat[key] = value
    return flat


def collect_provided_options(argv):
    provided = set()
    mapping = {
        '--output-date': 'output_date',
        '--folder': 'folder', '--obfuscate-init': 'obfuscate_init', '--emit-pyc': 'emit_pyc', '-o': 'output', '--output': 'output', '--preset': 'preset', '--resource-profile': 'resource_profile',
        '--debug': 'debug', '--header-mode': 'header_mode',
        '--banner-mode': 'header_mode',
        '--static-check': 'static_check', '--no-static-check': 'static_check',
        '--netease-profile': 'netease_profile',
        '--key-len': 'key_len', '--payload-cipher': 'payload_cipher', '--anti-debug': 'anti_debug', '--experimental-anti-debug': 'experimental_anti_debug', '--const-noise': 'const_noise', '--tail-noise': 'tail_noise',
        '--loader-junk': 'loader_junk', '--trampoline-layers': 'trampoline_layers',
        '--decoy-opcode-rows': 'decoy_opcode_rows', '--fake-ref-layers': 'fake_ref_layers',
        '--dead-bad-bytecode': 'dead_bad_bytecode', '--dead-bad-units': 'dead_bad_units',
        '--dead-nop-bloat': 'dead_nop_bloat', '--dead-stop-bloat': 'dead_stop_bloat',
        '--dead-arg-poison': 'dead_arg_poison', '--dead-exception-poison': 'dead_exception_poison', '--dead-call-poison': 'dead_call_poison',
        '--metadata-poison': 'metadata_poison', '--metadata-binary': 'metadata_binary', '--metadata-name-poison': 'metadata_name_poison',
        '--adaptive-strength': 'adaptive_strength', '--adaptive-max-scale': 'adaptive_max_scale', '--fake-mcs-tables': 'fake_mcs_tables', '--payload-splits': 'payload_splits',
        '--taunt-text': 'taunt_text', '--taunt-inner-consts': 'taunt_inner_consts', '--taunt-outer-refs': 'taunt_outer_refs',
        '--bytecode-split-gates': 'bytecode_split_gates', '--bytecode-split-interval': 'bytecode_split_interval', '--bytecode-split-bad-units': 'bytecode_split_bad_units', '--bytecode-split-nop-bloat': 'bytecode_split_nop_bloat',
        '--fake-code-objects': 'fake_code_objects', '--fake-code-nop-bloat': 'fake_code_nop_bloat', '--fake-code-stop-bloat': 'fake_code_stop_bloat',
        '--ghost-names': 'ghost_names', '--payload-graph-split': 'payload_graph_split', '--split-adaptive': 'split_adaptive', '--loop-shadow-gates': 'loop_shadow_gates',
        '--fake-payload-mirrors': 'fake_payload_mirrors', '--payload-graph-decoys': 'payload_graph_decoys', '--opcode-restore-noise': 'opcode_restore_noise', '--const-swamp': 'const_swamp', '--root-const-swamp': 'root_const_swamp', '--api-decoy-refs': 'api_decoy_refs',
        '--loader-decoy-tuples': 'loader_decoy_tuples', '--outer-decompiler-baits': 'outer_decompiler_baits', '--outer-decompiler-bait-budget': 'outer_decompiler_bait_budget', '--const-ref-chains': 'const_ref_chains',
        '--import-facade-layer': 'import_facade_layer',
        '--reflection-metadata-decoy': 'reflection_metadata_decoy',
        '--module-registry-protection': 'module_registry_protection',
        '--outer-closure-vault': 'outer_closure_vault',
        '--outer-tuple-gateway': 'outer_tuple_gateway',
        '--outer-closure-index-mirage': 'outer_closure_index_mirage',
        '--outer-generator-frame-mirage': 'outer_generator_frame_mirage',
        '--outer-method-descriptor-mirage': 'outer_method_descriptor_mirage',
        '--outer-defaults-dict-doppelganger': 'outer_defaults_dict_doppelganger',
        '--outer-dynamic-method': 'outer_dynamic_method',
        '--outer-dynamic-class': 'outer_dynamic_class',
        '--outer-callable-proxy': 'outer_callable_proxy',
        '--outer-frame-namespace': 'outer_frame_namespace',
        '--outer-generator-stages': 'outer_generator_stages',
        '--outer-exception-state': 'outer_exception_state',
        '--outer-no-sys-import': 'outer_no_sys_import',
        '--code-bytes-split': 'code_bytes_split', '--code-bytes-split-min': 'code_bytes_split_min',
        '--code-bytes-split-max-chunks': 'code_bytes_split_max_chunks', '--code-bytes-fake-chunks': 'code_bytes_fake_chunks',
        '--code-ref-table': 'code_ref_table', '--code-ref-decoys': 'code_ref_decoys',
        '--code-ref-wide-rows': 'code_ref_wide_rows', '--code-ref-mask-markers': 'code_ref_mask_markers',
        '--code-tuple-field-shuffle': 'code_tuple_field_shuffle', '--code-tuple-fragments': 'code_tuple_fragments',
        '--code-tuple-fragment-providers': 'code_tuple_fragment_providers',
        '--code-tuple-provider-graph': 'code_tuple_provider_graph', '--code-tuple-provider-decoys': 'code_tuple_provider_decoys',
        '--code-capsule-proxy': 'code_capsule_proxy', '--code-capsule-protocol-guard': 'code_capsule_protocol_guard',
        '--lazy-function-capsules': 'lazy_function_capsules',
        '--lazy-capsule-ratio': 'lazy_capsule_ratio',
        '--lazy-capsule-max-functions': 'lazy_capsule_max_functions',
        '--lazy-capsule-mode': 'lazy_capsule_mode',
        '--lazy-capsule-retain-calls': 'lazy_capsule_retain_calls',
        '--lazy-capsule-cross-key': 'lazy_capsule_cross_key',
        '--lazy-capsule-rotate-payload': 'lazy_capsule_rotate_payload',
        '--lazy-capsule-rotate-max-bytes': 'lazy_capsule_rotate_max_bytes',
        '--lazy-capsule-carrier-swap': 'lazy_capsule_carrier_swap',
        '--lazy-capsule-manager-proxy': 'lazy_capsule_manager_proxy',
        '--lazy-capsule-carrier-route-rotation': 'lazy_capsule_carrier_route_rotation',
        '--lazy-capsule-include': 'lazy_capsule_include',
        '--lazy-capsule-exclude': 'lazy_capsule_exclude',
        '--lazy-capsule-debug': 'lazy_capsule_debug',
        '--code-field-descriptors': 'code_field_descriptors',
        '--code-provider-context-bind': 'code_provider_context_bind',
        '--code-fused-restore': 'code_fused_restore',
        '--loader-reference-cleanup': 'loader_reference_cleanup',
        '--code-global-arena': 'code_global_arena', '--code-template-delta': 'code_template_delta',
        '--code-global-arena-decoys': 'code_global_arena_decoys',
        '--code-block-relocation': 'code_block_relocation',
        '--code-block-reloc-decoys': 'code_block_reloc_decoys',
        '--code-unit-arena': 'code_unit_arena',
        '--code-unit-arena-decoys': 'code_unit_arena_decoys',
        '--code-operand-graph': 'code_operand_graph',
        '--code-const-arena': 'code_const_arena',
        '--code-const-arena-decoys': 'code_const_arena_decoys',
        '--code-const-provider-graph': 'code_const_provider_graph',
        '--code-const-arena-limit': 'code_const_arena_limit',
        '--bytecode-stack-pad': 'bytecode_stack_pad', '--bytecode-lnotab-noise': 'bytecode_lnotab_noise',
        '--bytecode-const-salts': 'bytecode_const_salts', '--bytecode-name-chaff': 'bytecode_name_chaff',
        '--bytecode-entry-noise': 'bytecode_entry_noise', '--bytecode-exception-decoys': 'bytecode_exception_decoys',
        '--bytecode-stack-noise': 'bytecode_stack_noise', '--bytecode-stack-noise-interval': 'bytecode_stack_noise_interval',
        '--bytecode-stack-noise-limit': 'bytecode_stack_noise_limit',
        '--bytecode-jump-inversion': 'bytecode_jump_inversion', '--bytecode-conditional-jump-inversion': 'bytecode_jump_inversion',
        '--bytecode-jump-inversion-limit': 'bytecode_jump_inversion_limit',
        '--bytecode-jump-trampolines': 'bytecode_jump_trampolines',
        '--bytecode-jump-trampoline-limit': 'bytecode_jump_trampoline_limit',
        '--bytecode-cfg-flow': 'bytecode_flow',
        '--bytecode-cfg-flow-ratio': 'bytecode_flow_ratio',
        '--bytecode-cfg-flow-max-edges': 'bytecode_flow_max_edges',
        '--bytecode-cfg-loop-dispatch': 'bytecode_flow_loop_dispatch',
        '--bytecode-cfg-block-seeds': 'bytecode_flow_block_seeds',
        '--bytecode-cfg-block-seed-ratio': 'bytecode_flow_block_seed_ratio',
        '--bytecode-cfg-block-seed-max-blocks': 'bytecode_flow_block_seed_max_blocks',
        '--bytecode-cfg-block-shuffle': 'bytecode_flow_block_shuffle',
        '--bytecode-cfg-block-shuffle-ratio': 'bytecode_flow_block_shuffle_ratio',
        '--bytecode-cfg-block-shuffle-max-blocks': 'bytecode_flow_block_shuffle_max_blocks',
        '--bytecode-flow': 'bytecode_flow',
        '--bytecode-flow-ratio': 'bytecode_flow_ratio',
        '--bytecode-flow-max-edges': 'bytecode_flow_max_edges',
        '--bytecode-flow-loop-dispatch': 'bytecode_flow_loop_dispatch',
        '--bytecode-flow-block-seeds': 'bytecode_flow_block_seeds',
        '--bytecode-flow-block-seed-ratio': 'bytecode_flow_block_seed_ratio',
        '--bytecode-flow-block-seed-max-blocks': 'bytecode_flow_block_seed_max_blocks',
        '--bytecode-flow-block-shuffle': 'bytecode_flow_block_shuffle',
        '--bytecode-flow-block-shuffle-ratio': 'bytecode_flow_block_shuffle_ratio',
        '--bytecode-flow-block-shuffle-max-blocks': 'bytecode_flow_block_shuffle_max_blocks',
        '--bytecode-strategy-variation': 'bytecode_strategy_variation',
        '--bytecode-strategy-seed': 'bytecode_strategy_seed',
        '--bytecode-delayed-const-access': 'bytecode_delayed_const_access',
        '--bytecode-delayed-constants': 'bytecode_delayed_const_access',
        '--bytecode-delayed-const-limit': 'bytecode_delayed_const_limit',
        '--bytecode-extended-arg-prefix': 'bytecode_extended_arg_prefix',
        '--bytecode-extended-arg-interval': 'bytecode_extended_arg_interval',
        '--bytecode-extended-arg-limit': 'bytecode_extended_arg_limit',
        '--slot-mirage': 'slot_mirage', '--slot-mirage-limit': 'slot_mirage_limit',
        '--real-block-reorder': 'real_block_reorder', '--real-block-reorder-limit': 'real_block_reorder_limit',
        '--safe-dead-blocks': 'safe_dead_blocks', '--safe-dead-interval': 'safe_dead_interval', '--safe-dead-width': 'safe_dead_width', '--safe-dead-limit': 'safe_dead_limit', '--oparg-poison': 'oparg_poison',
        '--bytecode-decoy-islands': 'bytecode_decoy_islands', '--bytecode-decoy-island-ratio': 'bytecode_decoy_island_ratio', '--bytecode-decoy-island-limit': 'bytecode_decoy_island_limit', '--bytecode-decoy-island-width': 'bytecode_decoy_island_width', '--bytecode-decoy-island-growth': 'bytecode_decoy_island_growth',
        '--bytecode-taken-jump-poison': 'bytecode_taken_jump_poison',
        '--bytecode-opaque-predicates': 'bytecode_opaque_predicates', '--bytecode-opaque-interval': 'bytecode_opaque_interval', '--bytecode-opaque-width': 'bytecode_opaque_width', '--bytecode-opaque-limit': 'bytecode_opaque_limit',
        '--index-pool-shuffle': 'index_pool_shuffle', '--index-pool-mirrors': 'index_pool_mirrors',
        '--source-linearize-calls': 'source_linearize_calls',
        '--source-global-rename': 'source_global_rename',
        '--no-source-global-rename': 'source_global_rename',
        '--source-module-rename': 'source_module_rename',
        '--no-source-module-rename': 'source_module_rename',
        '--source-module-rename-exclude': 'source_module_rename_exclude',
        '--write-rename-mapping': 'write_rename_mapping',
        '--no-write-rename-mapping': 'write_rename_mapping',
        '--source-function-split': 'source_function_split',
        '--no-source-function-split': 'source_function_split',
        '--source-string-split': 'source_string_split', '--source-string-split-parts': 'source_string_split_parts',
        '--source-string-xor': 'source_string_xor', '--source-string-xor-mode': 'source_string_xor_mode',
        '--source-string-xor-text': 'source_string_xor_text', '--source-string-xor-number': 'source_string_xor_number',
        '--source-string-xor-min-length': 'source_string_xor_min_length', '--source-string-xor-limit': 'source_string_xor_limit',
        '--source-string-xor-variants': 'source_string_xor_variants', '--source-string-xor-decoys': 'source_string_xor_decoys',
        '--source-string-xor-debug': 'source_string_xor_debug',
        '--source-constant-pool': 'source_constant_pool', '--source-constant-pool-min': 'source_constant_pool_min', '--source-constant-pool-max': 'source_constant_pool_max',
        '--source-constant-rewrite': 'source_constant_rewrite', '--source-constant-rewrite-limit': 'source_constant_rewrite_limit',
        '--source-exception-shell': 'source_exception_shell',
        '--source-parenthesis-noise': 'source_parenthesis_noise',
        '--source-comment-noise': 'source_comment_noise', '--source-comment-noise-count': 'source_comment_noise_count',
        '--source-vm': 'source_vm', '--source-vm-ir': 'source_vm_ir', '--source-vm-extension': 'source_vm_extension', '--source-vm-full': 'source_vm_full', '--source-vm-ratio': 'source_vm_ratio',
        '--source-vm-min-ops': 'source_vm_min_ops', '--source-vm-max-ops': 'source_vm_max_ops',
        '--source-vm-max-functions': 'source_vm_max_functions',
        '--source-vm-include': 'source_vm_include', '--source-vm-exclude': 'source_vm_exclude',
        '--source-vm-allow-loops': 'source_vm_allow_loops', '--source-vm-debug': 'source_vm_debug',
        '--source-flow-hardening': 'source_flow_hardening',
        '--source-project-analysis': 'source_project_analysis',
        '--source-internal-predicates': 'source_internal_predicates',
        '--source-internal-predicate-ratio': 'source_internal_predicate_ratio',
        '--source-hot-pattern': 'source_hot_pattern',
        '--source-vm-dialects': 'source_vm_dialects',
        '--source-vm-flow-constants': 'source_vm_flow_constants',
        '--source-vm-exception-trap-ratio': 'source_vm_exception_trap_ratio',
        '--source-reference-obf': 'source_reference_obf', '--source-reference-obf-ratio': 'source_reference_obf_ratio',
        '--source-reference-obf-exclude': 'source_reference_obf_exclude',
        '--source-tuple-arg-decoys': 'source_tuple_arg_decoys',
        '--source-dotzero-relay': 'source_dotzero_relay',
        '--source-default-capsule': 'source_default_capsule',
        '--source-identity-weave': 'source_identity_weave',
        '--source-identity-ratio': 'source_identity_ratio',
        '--source-identity-max': 'source_identity_max',
        '--source-identity-variation': 'source_identity_variation',
        '--source-decompiler-carriers': 'source_decompiler_carriers',
        '--source-decoy-docstrings': 'source_decoy_docstrings', '--source-decoy-docstring-min': 'source_decoy_docstring_min',
        '--source-decoy-docstring-max': 'source_decoy_docstring_max',
        '--source-exception-lattice': 'source_exception_lattice',
        '--source-class-body-trap': 'source_class_body_trap',
        '--source-dead-flow': 'source_dead_flow', '--source-dead-flow-blocks': 'source_dead_flow_blocks',
        '--source-schedule': 'source_schedule', '--source-schedule-max-exprs': 'source_schedule_max_exprs', '--source-schedule-window': 'source_schedule_window',
        '--no-bytecode-obf': 'no_bytecode_obf', '--source-only': 'source_only', '--ast-exclude': 'ast_exclude',
        '--control-flow-flatten': 'control_flow_flatten', '--control-flow-max-blocks': 'control_flow_max_blocks',
        '--opcode-replacement': 'opcode_replacement', '--runtime-opcode-layer': 'runtime_opcode_layer', '--per-code-runtime-opcode': 'per_code_runtime_opcode',
        '--runtime-opcode-decoys': 'runtime_opcode_decoys', '--opcode-exclude': 'opcode_exclude', '--loader-mode': 'loader_mode', '--loader-dialect': 'loader_dialect',
        '--code-tuple-payload': 'code_tuple_payload', '--legacy-marshal-payload': 'code_tuple_payload',
        '--no-code-tuple-payload': 'code_tuple_payload',
        '--filename-mode': 'filename_mode', '--include': 'include', '--exclude': 'exclude',
        '--obfuscate-modmain': 'obfuscate_modmain', '--target-side': 'target_side',
        '--clean-output': 'clean_output', '--copy-pyc': 'copy_pyc', '--deploy-target': 'deploy_target', '--fix-netease-register': 'fix_netease_register',
        '--python27': 'python27',
        '--package-name': 'package_name', '--namespace': 'namespace', '--inner-opcode-tunnel': 'inner_opcode_tunnel',
        '--opcode-runtime': 'opcode_runtime', '--mcs-opmap-version': 'mcs_opmap_version',
    }
    for item in argv:
        if item in mapping:
            provided.add(mapping[item])
    return provided


def apply_config(args, config):
    flat = flatten_config(config or {})
    aliases = {
        'input': 'input', 'output': 'output', 'folder': 'folder', 'obfuscate_init': 'obfuscate_init', 'project_obfuscate_init': 'obfuscate_init', 'emit_pyc': 'emit_pyc', 'preset': 'preset', 'resource_profile': 'resource_profile',
        'python27': 'python27', 'runtime_python27': 'python27',
        'static_check': 'static_check',
        'static_check_enabled': 'static_check',
        'netease_profile': 'netease_profile', 'profile': 'netease_profile',
        'debug': 'debug', 'debug_enabled': 'debug', 'basic_debug': 'debug',
        'header_mode': 'header_mode', 'banner_mode': 'header_mode',
        'output_date': 'output_date', 'watermark_date': 'output_date',
        'key_len': 'key_len', 'payload_cipher': 'payload_cipher', 'anti_debug': 'anti_debug',
        'experimental_anti_debug': 'experimental_anti_debug',
        'experimental_loader_anti_debug': 'experimental_anti_debug',
        'loader_anti_debug': 'anti_debug', 'anti_tamper_runtime': 'anti_debug',
        'const_noise': 'const_noise', 'tail_noise': 'tail_noise',
        'loader_junk': 'loader_junk', 'trampoline_layers': 'trampoline_layers',
        'decoy_opcode_rows': 'decoy_opcode_rows', 'fake_ref_layers': 'fake_ref_layers',
        'dead_bad_bytecode': 'dead_bad_bytecode', 'dead_bad_units': 'dead_bad_units',
        'dead_nop_bloat': 'dead_nop_bloat', 'dead_stop_bloat': 'dead_stop_bloat',
        'dead_arg_poison': 'dead_arg_poison', 'dead_exception_poison': 'dead_exception_poison', 'dead_call_poison': 'dead_call_poison',
        'metadata_poison': 'metadata_poison', 'metadata_binary': 'metadata_binary', 'metadata_name_poison': 'metadata_name_poison',
        'adaptive_strength': 'adaptive_strength', 'adaptive_max_scale': 'adaptive_max_scale', 'fake_mcs_tables': 'fake_mcs_tables', 'payload_splits': 'payload_splits',
        'taunt_text': 'taunt_text', 'taunt_inner_consts': 'taunt_inner_consts', 'taunt_outer_refs': 'taunt_outer_refs',
        'bytecode_split_gates': 'bytecode_split_gates', 'bytecode_split_interval': 'bytecode_split_interval', 'bytecode_split_bad_units': 'bytecode_split_bad_units', 'bytecode_split_nop_bloat': 'bytecode_split_nop_bloat',
        'fake_code_objects': 'fake_code_objects', 'fake_code_nop_bloat': 'fake_code_nop_bloat', 'fake_code_stop_bloat': 'fake_code_stop_bloat',
        'ghost_names': 'ghost_names', 'payload_graph_split': 'payload_graph_split', 'split_adaptive': 'split_adaptive', 'loop_shadow_gates': 'loop_shadow_gates',
        'fake_payload_mirrors': 'fake_payload_mirrors', 'payload_graph_decoys': 'payload_graph_decoys', 'opcode_restore_noise': 'opcode_restore_noise', 'const_swamp': 'const_swamp', 'root_const_swamp': 'root_const_swamp', 'api_decoy_refs': 'api_decoy_refs',
        'loader_decoy_tuples': 'loader_decoy_tuples', 'outer_decompiler_baits': 'outer_decompiler_baits', 'outer_decompiler_bait_budget': 'outer_decompiler_bait_budget', 'const_ref_chains': 'const_ref_chains',
        'outer_loader_decoy_tuples': 'loader_decoy_tuples', 'bytecode_const_ref_chains': 'const_ref_chains',
        'import_facade_layer': 'import_facade_layer', 'outer_import_facade_layer': 'import_facade_layer',
        'reflection_metadata_decoy': 'reflection_metadata_decoy',
        'outer_reflection_metadata_decoy': 'reflection_metadata_decoy',
        'module_registry_protection': 'module_registry_protection',
        'outer_module_registry_protection': 'module_registry_protection',
        'outer_closure_vault': 'outer_closure_vault',
        'outer_tuple_gateway': 'outer_tuple_gateway',
        'outer_closure_index_mirage': 'outer_closure_index_mirage',
        'outer_generator_frame_mirage': 'outer_generator_frame_mirage',
        'outer_method_descriptor_mirage': 'outer_method_descriptor_mirage',
        'outer_defaults_dict_doppelganger': 'outer_defaults_dict_doppelganger',
        'outer_dynamic_method': 'outer_dynamic_method',
        'outer_dynamic_class': 'outer_dynamic_class',
        'outer_callable_proxy': 'outer_callable_proxy',
        'outer_frame_namespace': 'outer_frame_namespace',
        'outer_generator_stages': 'outer_generator_stages',
        'outer_exception_state': 'outer_exception_state',
        'outer_no_sys_import': 'outer_no_sys_import',
        'code_bytes_split': 'code_bytes_split', 'code_bytes_split_min': 'code_bytes_split_min',
        'code_bytes_split_max_chunks': 'code_bytes_split_max_chunks', 'code_bytes_fake_chunks': 'code_bytes_fake_chunks',
        'code_ref_table': 'code_ref_table', 'code_ref_decoys': 'code_ref_decoys',
        'code_ref_wide_rows': 'code_ref_wide_rows', 'code_ref_mask_markers': 'code_ref_mask_markers',
        'code_tuple_field_shuffle': 'code_tuple_field_shuffle', 'code_tuple_fragments': 'code_tuple_fragments',
        'code_tuple_fragment_providers': 'code_tuple_fragment_providers',
        'code_tuple_provider_graph': 'code_tuple_provider_graph', 'code_tuple_provider_decoys': 'code_tuple_provider_decoys',
        'code_capsule_proxy': 'code_capsule_proxy', 'code_capsule_protocol_guard': 'code_capsule_protocol_guard',
        'lazy_function_capsules': 'lazy_function_capsules',
        'lazy_capsule_ratio': 'lazy_capsule_ratio',
        'lazy_capsule_max_functions': 'lazy_capsule_max_functions',
        'lazy_capsule_mode': 'lazy_capsule_mode',
        'lazy_capsule_retain_calls': 'lazy_capsule_retain_calls',
        'lazy_capsule_cross_key': 'lazy_capsule_cross_key',
        'lazy_capsule_rotate_payload': 'lazy_capsule_rotate_payload',
        'lazy_capsule_rotate_max_bytes': 'lazy_capsule_rotate_max_bytes',
        'lazy_capsule_carrier_swap': 'lazy_capsule_carrier_swap',
        'lazy_capsule_manager_proxy': 'lazy_capsule_manager_proxy',
        'lazy_capsule_carrier_route_rotation': 'lazy_capsule_carrier_route_rotation',
        'lazy_capsule_include': 'lazy_capsule_include',
        'lazy_capsule_exclude': 'lazy_capsule_exclude',
        'lazy_capsule_debug': 'lazy_capsule_debug',
        'bytecode_lazy_function_capsules': 'lazy_function_capsules',
        'bytecode_lazy_capsule_ratio': 'lazy_capsule_ratio',
        'bytecode_lazy_capsule_max_functions': 'lazy_capsule_max_functions',
        'bytecode_lazy_capsule_mode': 'lazy_capsule_mode',
        'bytecode_lazy_capsule_retain_calls': 'lazy_capsule_retain_calls',
        'bytecode_lazy_capsule_cross_key': 'lazy_capsule_cross_key',
        'bytecode_lazy_capsule_rotate_payload': 'lazy_capsule_rotate_payload',
        'bytecode_lazy_capsule_rotate_max_bytes': 'lazy_capsule_rotate_max_bytes',
        'bytecode_lazy_capsule_carrier_swap': 'lazy_capsule_carrier_swap',
        'bytecode_lazy_capsule_manager_proxy': 'lazy_capsule_manager_proxy',
        'bytecode_lazy_capsule_carrier_route_rotation': 'lazy_capsule_carrier_route_rotation',
        'bytecode_lazy_capsule_include': 'lazy_capsule_include',
        'bytecode_lazy_capsule_exclude': 'lazy_capsule_exclude',
        'bytecode_lazy_capsule_debug': 'lazy_capsule_debug',
        'code_field_descriptors': 'code_field_descriptors',
        'code_provider_context_bind': 'code_provider_context_bind',
        'code_fused_restore': 'code_fused_restore',
        'loader_reference_cleanup': 'loader_reference_cleanup',
        'code_global_arena': 'code_global_arena', 'code_template_delta': 'code_template_delta',
        'code_global_arena_decoys': 'code_global_arena_decoys',
        'code_block_relocation': 'code_block_relocation', 'code_block_reloc_decoys': 'code_block_reloc_decoys',
        'code_unit_arena': 'code_unit_arena', 'code_unit_arena_decoys': 'code_unit_arena_decoys',
        'code_operand_graph': 'code_operand_graph',
        'code_const_arena': 'code_const_arena', 'code_const_arena_decoys': 'code_const_arena_decoys',
        'code_const_provider_graph': 'code_const_provider_graph', 'code_const_arena_limit': 'code_const_arena_limit',
        'bytecode_stack_pad': 'bytecode_stack_pad', 'bytecode_lnotab_noise': 'bytecode_lnotab_noise',
        'bytecode_const_salts': 'bytecode_const_salts', 'bytecode_name_chaff': 'bytecode_name_chaff',
        'bytecode_entry_noise': 'bytecode_entry_noise', 'bytecode_exception_decoys': 'bytecode_exception_decoys',
        'bytecode_stack_noise': 'bytecode_stack_noise', 'bytecode_stack_noise_interval': 'bytecode_stack_noise_interval',
        'bytecode_stack_noise_limit': 'bytecode_stack_noise_limit',
        'bytecode_jump_inversion': 'bytecode_jump_inversion', 'bytecode_conditional_jump_inversion': 'bytecode_jump_inversion',
        'bytecode_jump_inversion_limit': 'bytecode_jump_inversion_limit',
        'bytecode_jump_trampolines': 'bytecode_jump_trampolines',
        'bytecode_jump_trampoline_limit': 'bytecode_jump_trampoline_limit',
        'bytecode_cfg_flow': 'bytecode_flow', 'cfg_flow': 'bytecode_flow',
        'bytecode_flow': 'bytecode_flow', 'flow': 'bytecode_flow',
        'bytecode_control_flow_graph': 'bytecode_flow',
        'bytecode_cfg_flow_ratio': 'bytecode_flow_ratio', 'cfg_flow_ratio': 'bytecode_flow_ratio',
        'bytecode_flow_ratio': 'bytecode_flow_ratio', 'flow_ratio': 'bytecode_flow_ratio',
        'bytecode_cfg_flow_max_edges': 'bytecode_flow_max_edges', 'cfg_flow_max_edges': 'bytecode_flow_max_edges',
        'bytecode_flow_max_edges': 'bytecode_flow_max_edges', 'flow_max_edges': 'bytecode_flow_max_edges',
        'bytecode_cfg_loop_dispatch': 'bytecode_flow_loop_dispatch', 'cfg_loop_dispatch': 'bytecode_flow_loop_dispatch',
        'bytecode_flow_loop_dispatch': 'bytecode_flow_loop_dispatch', 'flow_loop_dispatch': 'bytecode_flow_loop_dispatch',
        'bytecode_cfg_block_seeds': 'bytecode_flow_block_seeds', 'cfg_block_seeds': 'bytecode_flow_block_seeds',
        'bytecode_flow_block_seeds': 'bytecode_flow_block_seeds', 'flow_block_seeds': 'bytecode_flow_block_seeds',
        'bytecode_cfg_block_seed_ratio': 'bytecode_flow_block_seed_ratio', 'cfg_block_seed_ratio': 'bytecode_flow_block_seed_ratio',
        'bytecode_flow_block_seed_ratio': 'bytecode_flow_block_seed_ratio', 'flow_block_seed_ratio': 'bytecode_flow_block_seed_ratio',
        'bytecode_cfg_block_seed_max_blocks': 'bytecode_flow_block_seed_max_blocks', 'cfg_block_seed_max_blocks': 'bytecode_flow_block_seed_max_blocks',
        'bytecode_flow_block_seed_max_blocks': 'bytecode_flow_block_seed_max_blocks', 'flow_block_seed_max_blocks': 'bytecode_flow_block_seed_max_blocks',
        'bytecode_cfg_block_shuffle': 'bytecode_flow_block_shuffle', 'cfg_block_shuffle': 'bytecode_flow_block_shuffle',
        'bytecode_flow_block_shuffle': 'bytecode_flow_block_shuffle', 'flow_block_shuffle': 'bytecode_flow_block_shuffle',
        'bytecode_cfg_block_shuffle_ratio': 'bytecode_flow_block_shuffle_ratio', 'cfg_block_shuffle_ratio': 'bytecode_flow_block_shuffle_ratio',
        'bytecode_flow_block_shuffle_ratio': 'bytecode_flow_block_shuffle_ratio', 'flow_block_shuffle_ratio': 'bytecode_flow_block_shuffle_ratio',
        'bytecode_cfg_block_shuffle_max_blocks': 'bytecode_flow_block_shuffle_max_blocks', 'cfg_block_shuffle_max_blocks': 'bytecode_flow_block_shuffle_max_blocks',
        'bytecode_flow_block_shuffle_max_blocks': 'bytecode_flow_block_shuffle_max_blocks', 'flow_block_shuffle_max_blocks': 'bytecode_flow_block_shuffle_max_blocks',
        'bytecode_strategy_variation': 'bytecode_strategy_variation', 'bytecode_strategy_seed': 'bytecode_strategy_seed',
        'bytecode_delayed_const_access': 'bytecode_delayed_const_access',
        'bytecode_delayed_constants': 'bytecode_delayed_const_access',
        'bytecode_delayed_const_limit': 'bytecode_delayed_const_limit',
        'bytecode_extended_arg_prefix': 'bytecode_extended_arg_prefix',
        'bytecode_extended_arg_interval': 'bytecode_extended_arg_interval',
        'bytecode_extended_arg_limit': 'bytecode_extended_arg_limit',
        'slot_mirage': 'slot_mirage', 'slot_mirage_limit': 'slot_mirage_limit',
        'bytecode_code_bytes_split': 'code_bytes_split', 'bytecode_code_bytes_split_min': 'code_bytes_split_min',
        'bytecode_code_bytes_split_max_chunks': 'code_bytes_split_max_chunks', 'bytecode_code_bytes_fake_chunks': 'code_bytes_fake_chunks',
        'bytecode_code_ref_table': 'code_ref_table', 'bytecode_code_ref_decoys': 'code_ref_decoys',
        'bytecode_code_ref_wide_rows': 'code_ref_wide_rows', 'bytecode_code_ref_mask_markers': 'code_ref_mask_markers',
        'bytecode_code_tuple_field_shuffle': 'code_tuple_field_shuffle', 'bytecode_code_tuple_fragments': 'code_tuple_fragments',
        'bytecode_code_tuple_fragment_providers': 'code_tuple_fragment_providers',
        'bytecode_code_tuple_provider_graph': 'code_tuple_provider_graph', 'bytecode_code_tuple_provider_decoys': 'code_tuple_provider_decoys',
        'bytecode_code_capsule_proxy': 'code_capsule_proxy',
        'bytecode_code_capsule_protocol_guard': 'code_capsule_protocol_guard',
        'bytecode_code_field_descriptors': 'code_field_descriptors',
        'bytecode_code_provider_context_bind': 'code_provider_context_bind',
        'bytecode_code_fused_restore': 'code_fused_restore',
        'bytecode_loader_reference_cleanup': 'loader_reference_cleanup',
        'bytecode_code_global_arena': 'code_global_arena', 'bytecode_code_template_delta': 'code_template_delta',
        'bytecode_code_global_arena_decoys': 'code_global_arena_decoys',
        'bytecode_code_block_relocation': 'code_block_relocation',
        'bytecode_code_block_reloc_decoys': 'code_block_reloc_decoys',
        'bytecode_code_unit_arena': 'code_unit_arena',
        'bytecode_code_unit_arena_decoys': 'code_unit_arena_decoys',
        'bytecode_code_operand_graph': 'code_operand_graph',
        'bytecode_code_const_arena': 'code_const_arena',
        'bytecode_code_const_arena_decoys': 'code_const_arena_decoys',
        'bytecode_code_const_provider_graph': 'code_const_provider_graph',
        'bytecode_code_const_arena_limit': 'code_const_arena_limit',
        'bytecode_bytecode_stack_pad': 'bytecode_stack_pad', 'bytecode_bytecode_lnotab_noise': 'bytecode_lnotab_noise',
        'bytecode_bytecode_const_salts': 'bytecode_const_salts', 'bytecode_bytecode_name_chaff': 'bytecode_name_chaff',
        'bytecode_bytecode_entry_noise': 'bytecode_entry_noise', 'bytecode_bytecode_exception_decoys': 'bytecode_exception_decoys',
        'bytecode_bytecode_stack_noise': 'bytecode_stack_noise',
        'bytecode_bytecode_stack_noise_interval': 'bytecode_stack_noise_interval',
        'bytecode_bytecode_stack_noise_limit': 'bytecode_stack_noise_limit',
        'bytecode_bytecode_jump_inversion': 'bytecode_jump_inversion',
        'bytecode_bytecode_conditional_jump_inversion': 'bytecode_jump_inversion',
        'bytecode_bytecode_jump_inversion_limit': 'bytecode_jump_inversion_limit',
        'bytecode_bytecode_jump_trampolines': 'bytecode_jump_trampolines',
        'bytecode_bytecode_jump_trampoline_limit': 'bytecode_jump_trampoline_limit',
        'bytecode_bytecode_cfg_flow': 'bytecode_flow',
        'bytecode_cfg_flow': 'bytecode_flow',
        'bytecode_bytecode_cfg_flow_ratio': 'bytecode_flow_ratio',
        'bytecode_cfg_flow_ratio': 'bytecode_flow_ratio',
        'bytecode_bytecode_cfg_flow_max_edges': 'bytecode_flow_max_edges',
        'bytecode_cfg_flow_max_edges': 'bytecode_flow_max_edges',
        'bytecode_bytecode_cfg_loop_dispatch': 'bytecode_flow_loop_dispatch',
        'bytecode_cfg_loop_dispatch': 'bytecode_flow_loop_dispatch',
        'bytecode_bytecode_cfg_block_seeds': 'bytecode_flow_block_seeds',
        'bytecode_cfg_block_seeds': 'bytecode_flow_block_seeds',
        'bytecode_bytecode_cfg_block_seed_ratio': 'bytecode_flow_block_seed_ratio',
        'bytecode_cfg_block_seed_ratio': 'bytecode_flow_block_seed_ratio',
        'bytecode_bytecode_cfg_block_seed_max_blocks': 'bytecode_flow_block_seed_max_blocks',
        'bytecode_cfg_block_seed_max_blocks': 'bytecode_flow_block_seed_max_blocks',
        'bytecode_bytecode_cfg_block_shuffle': 'bytecode_flow_block_shuffle',
        'bytecode_cfg_block_shuffle': 'bytecode_flow_block_shuffle',
        'bytecode_bytecode_cfg_block_shuffle_ratio': 'bytecode_flow_block_shuffle_ratio',
        'bytecode_cfg_block_shuffle_ratio': 'bytecode_flow_block_shuffle_ratio',
        'bytecode_bytecode_cfg_block_shuffle_max_blocks': 'bytecode_flow_block_shuffle_max_blocks',
        'bytecode_cfg_block_shuffle_max_blocks': 'bytecode_flow_block_shuffle_max_blocks',
        'bytecode_bytecode_strategy_variation': 'bytecode_strategy_variation',
        'bytecode_bytecode_strategy_seed': 'bytecode_strategy_seed',
        'bytecode_bytecode_delayed_const_access': 'bytecode_delayed_const_access',
        'bytecode_bytecode_delayed_constants': 'bytecode_delayed_const_access',
        'bytecode_bytecode_delayed_const_limit': 'bytecode_delayed_const_limit',
        'real_block_reorder': 'real_block_reorder', 'real_block_reorder_limit': 'real_block_reorder_limit',
        'safe_dead_blocks': 'safe_dead_blocks', 'safe_dead_interval': 'safe_dead_interval', 'safe_dead_width': 'safe_dead_width', 'safe_dead_limit': 'safe_dead_limit', 'oparg_poison': 'oparg_poison',
        'bytecode_decoy_islands': 'bytecode_decoy_islands', 'decoy_islands': 'bytecode_decoy_islands',
        'bytecode_decoy_island_ratio': 'bytecode_decoy_island_ratio', 'decoy_island_ratio': 'bytecode_decoy_island_ratio',
        'bytecode_decoy_island_limit': 'bytecode_decoy_island_limit', 'decoy_island_limit': 'bytecode_decoy_island_limit',
        'bytecode_decoy_island_width': 'bytecode_decoy_island_width', 'decoy_island_width': 'bytecode_decoy_island_width',
        'bytecode_decoy_island_growth': 'bytecode_decoy_island_growth', 'decoy_island_growth': 'bytecode_decoy_island_growth',
        'bytecode_taken_jump_poison': 'bytecode_taken_jump_poison',
        'taken_jump_poison': 'bytecode_taken_jump_poison',
        'bytecode_opaque_predicates': 'bytecode_opaque_predicates', 'bytecode_opaque_interval': 'bytecode_opaque_interval', 'bytecode_opaque_width': 'bytecode_opaque_width', 'bytecode_opaque_limit': 'bytecode_opaque_limit',
        'opaque_predicates': 'bytecode_opaque_predicates', 'opaque_interval': 'bytecode_opaque_interval', 'opaque_width': 'bytecode_opaque_width', 'opaque_limit': 'bytecode_opaque_limit',
        'index_pool_shuffle': 'index_pool_shuffle', 'index_pool_mirrors': 'index_pool_mirrors',
        'bytecode_index_pool_shuffle': 'index_pool_shuffle', 'bytecode_index_pool_mirrors': 'index_pool_mirrors',
        'source_linearize_calls': 'source_linearize_calls',
        'source_global_rename': 'source_global_rename',
        'global_rename': 'source_global_rename',
        'source_module_rename': 'source_module_rename',
        'module_rename': 'source_module_rename',
        'source_module_rename_exclude': 'source_module_rename_exclude',
        'module_rename_exclude': 'source_module_rename_exclude',
        'source_string_split': 'source_string_split',
        'source_string_split_parts': 'source_string_split_parts',
        'source_string_xor': 'source_string_xor',
        'source_string_xor_mode': 'source_string_xor_mode',
        'source_string_xor_text': 'source_string_xor_text',
        'source_string_xor_number': 'source_string_xor_number',
        'source_string_xor_min_length': 'source_string_xor_min_length',
        'source_string_xor_limit': 'source_string_xor_limit',
        'source_string_xor_variants': 'source_string_xor_variants',
        'source_string_xor_decoys': 'source_string_xor_decoys',
        'source_string_xor_debug': 'source_string_xor_debug',
        'source_constant_pool': 'source_constant_pool',
        'source_constant_pool_min': 'source_constant_pool_min',
        'source_constant_pool_max': 'source_constant_pool_max',
        'source_constant_rewrite': 'source_constant_rewrite',
        'source_constant_rewrite_limit': 'source_constant_rewrite_limit',
        'source_exception_shell': 'source_exception_shell',
        'source_parenthesis_noise': 'source_parenthesis_noise',
        'source_comment_noise': 'source_comment_noise',
        'source_comment_noise_count': 'source_comment_noise_count',
        'source_vm': 'source_vm', 'source_vm_enabled': 'source_vm',
        'source_vm_ir': 'source_vm_ir', 'vm_ir': 'source_vm_ir',
        'source_vm_extension': 'source_vm_extension', 'vm_extension': 'source_vm_extension',
        'source_vm_full': 'source_vm_full', 'vm_full': 'source_vm_full',
        'source_vm_ratio': 'source_vm_ratio', 'source_vm_min_ops': 'source_vm_min_ops',
        'source_vm_max_ops': 'source_vm_max_ops', 'source_vm_max_functions': 'source_vm_max_functions', 'source_vm_include': 'source_vm_include',
        'source_vm_exclude': 'source_vm_exclude', 'source_vm_allow_loops': 'source_vm_allow_loops', 'source_vm_debug': 'source_vm_debug',
        'source_flow_hardening': 'source_flow_hardening', 'flow_hardening': 'source_flow_hardening',
        'source_project_analysis': 'source_project_analysis', 'project_analysis': 'source_project_analysis',
        'source_internal_predicates': 'source_internal_predicates', 'internal_predicates': 'source_internal_predicates',
        'source_internal_predicate_ratio': 'source_internal_predicate_ratio', 'internal_predicate_ratio': 'source_internal_predicate_ratio',
        'source_hot_pattern': 'source_hot_pattern', 'source_hot_patterns': 'source_hot_pattern', 'hot_patterns': 'source_hot_pattern',
        'source_vm_dialects': 'source_vm_dialects', 'vm_dialects': 'source_vm_dialects',
        'source_vm_flow_constants': 'source_vm_flow_constants', 'vm_flow_constants': 'source_vm_flow_constants',
        'source_vm_exception_trap_ratio': 'source_vm_exception_trap_ratio', 'vm_exception_trap_ratio': 'source_vm_exception_trap_ratio',
        'source_reference_obf': 'source_reference_obf', 'reference_obf': 'source_reference_obf',
        'source_reference_obf_ratio': 'source_reference_obf_ratio', 'reference_obf_ratio': 'source_reference_obf_ratio',
        'source_reference_obf_exclude': 'source_reference_obf_exclude', 'reference_obf_exclude': 'source_reference_obf_exclude',
        'source_tuple_arg_decoys': 'source_tuple_arg_decoys',
        'source_dotzero_relay': 'source_dotzero_relay',
        'source_default_capsule': 'source_default_capsule',
        'source_identity_weave': 'source_identity_weave',
        'source_identity_ratio': 'source_identity_ratio',
        'source_identity_max': 'source_identity_max',
        'source_identity_variation': 'source_identity_variation',
        'source_decompiler_carriers': 'source_decompiler_carriers',
        'source_decoy_docstrings': 'source_decoy_docstrings', 'decoy_docstrings': 'source_decoy_docstrings',
        'source_decoy_docstring_min': 'source_decoy_docstring_min', 'decoy_docstring_min': 'source_decoy_docstring_min',
        'source_decoy_docstring_max': 'source_decoy_docstring_max', 'decoy_docstring_max': 'source_decoy_docstring_max',
        'source_exception_lattice': 'source_exception_lattice',
        'source_class_body_trap': 'source_class_body_trap',
        'source_dead_flow': 'source_dead_flow', 'source_dead_flow_blocks': 'source_dead_flow_blocks',
        'dead_flow': 'source_dead_flow', 'dead_flow_blocks': 'source_dead_flow_blocks',
        'source_schedule': 'source_schedule', 'source_schedule_max_exprs': 'source_schedule_max_exprs', 'source_schedule_window': 'source_schedule_window',
        'no_bytecode_obf': 'no_bytecode_obf', 'source_only': 'source_only', 'ast_exclude': 'ast_exclude',
        'source_ast_exclude': 'ast_exclude', 'ast_disable_for': 'ast_exclude', 'source_disable_for': 'ast_exclude',
        'control_flow_flatten': 'control_flow_flatten', 'control_flow_max_blocks': 'control_flow_max_blocks',
        'opcode_replacement': 'opcode_replacement', 'opcode_replace': 'opcode_replacement',
        'runtime_opcode_layer': 'runtime_opcode_layer', 'per_code_runtime_opcode': 'per_code_runtime_opcode',
        'runtime_opcode_decoys': 'runtime_opcode_decoys', 'opcode_exclude': 'opcode_exclude', 'loader_mode': 'loader_mode', 'loader_vm': 'loader_vm', 'loader_dialect': 'loader_dialect',
        'code_tuple_payload': 'code_tuple_payload', 'payload_code_tuple': 'code_tuple_payload',
        'loader_code_tuple_payload': 'code_tuple_payload',
        'filename_mode': 'filename_mode', 'include': 'include', 'exclude': 'exclude',
        'obfuscate_modmain': 'obfuscate_modmain', 'target_side': 'target_side',
        'clean_output': 'clean_output', 'copy_pyc': 'copy_pyc', 'deploy_target': 'deploy_target', 'fix_netease_register': 'fix_netease_register',
        'package_name': 'package_name', 'namespace': 'namespace', 'inner_opcode_tunnel': 'inner_opcode_tunnel',
        'opcode_runtime': 'opcode_runtime', 'mcs_opmap_version': 'mcs_opmap_version',
        'project_input': 'input', 'project_output': 'output', 'project_folder': 'folder',
        'project_include': 'include', 'project_exclude': 'exclude', 'project_target_side': 'target_side',
        'project_clean_output': 'clean_output', 'project_copy_pyc': 'copy_pyc', 'project_deploy_target': 'deploy_target',
        'netease_fix_register': 'fix_netease_register', 'netease_package_name': 'package_name', 'netease_namespace': 'namespace',
        'basic_preset': 'preset', 'basic_key_len': 'key_len', 'basic_loader_mode': 'loader_mode', 'basic_filename_mode': 'filename_mode',
        'basic_header_mode': 'header_mode', 'basic_banner_mode': 'header_mode',
        'basic_output_date': 'output_date', 'watermark_output_date': 'output_date',
        'bytecode_const_noise': 'const_noise', 'bytecode_tail_noise': 'tail_noise',
        'bytecode_opcode_replacement': 'opcode_replacement',
        'bytecode_runtime_opcode_layer': 'runtime_opcode_layer', 'bytecode_per_code_runtime_opcode': 'per_code_runtime_opcode',
        'bytecode_runtime_opcode_decoys': 'runtime_opcode_decoys', 'bytecode_opcode_exclude': 'opcode_exclude', 'bytecode_mcs_opmap_version': 'mcs_opmap_version',
        'bytecode_code_tuple_payload': 'code_tuple_payload', 'bytecode_payload_code_tuple': 'code_tuple_payload',
        'bytecode_inner_opcode_tunnel': 'inner_opcode_tunnel', 'bytecode_opcode_runtime': 'opcode_runtime',
        'outer_loader_junk': 'loader_junk', 'outer_trampoline_layers': 'trampoline_layers',
        'outer_decoy_opcode_rows': 'decoy_opcode_rows', 'outer_fake_ref_layers': 'fake_ref_layers',
        'bad_dead_bad_bytecode': 'dead_bad_bytecode', 'bad_dead_bad_units': 'dead_bad_units',
        'bad_dead_nop_bloat': 'dead_nop_bloat', 'bad_dead_stop_bloat': 'dead_stop_bloat',
        'bad_dead_arg_poison': 'dead_arg_poison', 'bad_dead_exception_poison': 'dead_exception_poison', 'bad_dead_call_poison': 'dead_call_poison',
        'metadata_poison': 'metadata_poison', 'metadata_enabled': 'metadata_poison', 'metadata_binary': 'metadata_binary', 'metadata_name_poison': 'metadata_name_poison',
        'metadata_adaptive_strength': 'adaptive_strength', 'metadata_adaptive_max_scale': 'adaptive_max_scale',
        'taunt_text': 'taunt_text', 'taunt_inner_consts': 'taunt_inner_consts', 'taunt_outer_refs': 'taunt_outer_refs',
        'taunt_message': 'taunt_text', 'taunt_inner': 'taunt_inner_consts', 'taunt_outer': 'taunt_outer_refs',
        'bytecode_adaptive_strength': 'adaptive_strength', 'bytecode_adaptive_max_scale': 'adaptive_max_scale', 'bytecode_fake_mcs_tables': 'fake_mcs_tables', 'outer_payload_splits': 'payload_splits',
        'bytecode_split_enabled': 'bytecode_split_gates', 'bytecode_split_gates': 'bytecode_split_gates', 'bytecode_split_interval': 'bytecode_split_interval', 'bytecode_split_bad_units': 'bytecode_split_bad_units', 'bytecode_split_nop_bloat': 'bytecode_split_nop_bloat',
        'bytecode_fake_code_objects': 'fake_code_objects', 'bytecode_fake_code_nop_bloat': 'fake_code_nop_bloat', 'bytecode_fake_code_stop_bloat': 'fake_code_stop_bloat',
        'bytecode_ghost_names': 'ghost_names', 'bytecode_split_adaptive': 'split_adaptive', 'bytecode_loop_shadow_gates': 'loop_shadow_gates',
        'bytecode_opcode_restore_noise': 'opcode_restore_noise', 'bytecode_const_swamp': 'const_swamp', 'bytecode_root_const_swamp': 'root_const_swamp',
        'bytecode_real_block_reorder': 'real_block_reorder', 'bytecode_real_block_reorder_limit': 'real_block_reorder_limit',
        'bytecode_safe_dead_blocks': 'safe_dead_blocks', 'bytecode_safe_dead_interval': 'safe_dead_interval', 'bytecode_safe_dead_width': 'safe_dead_width', 'bytecode_safe_dead_limit': 'safe_dead_limit', 'bytecode_oparg_poison': 'oparg_poison',
        'bytecode_bytecode_decoy_islands': 'bytecode_decoy_islands',
        'bytecode_bytecode_decoy_island_ratio': 'bytecode_decoy_island_ratio',
        'bytecode_bytecode_decoy_island_limit': 'bytecode_decoy_island_limit',
        'bytecode_bytecode_decoy_island_width': 'bytecode_decoy_island_width',
        'bytecode_bytecode_decoy_island_growth': 'bytecode_decoy_island_growth',
        'source_linearize_calls': 'source_linearize_calls', 'source_linearize': 'source_linearize_calls',
        'source_global_rename': 'source_global_rename', 'source_rename': 'source_global_rename',
        'source_module_rename': 'source_module_rename', 'module_rename': 'source_module_rename',
        'source_module_rename_exclude': 'source_module_rename_exclude', 'module_rename_exclude': 'source_module_rename_exclude',
        'write_rename_mapping': 'write_rename_mapping', 'rename_mapping': 'write_rename_mapping',
        'source_function_split': 'source_function_split', 'function_split': 'source_function_split',
        'source_dead_flow': 'source_dead_flow', 'source_dead_flow_blocks': 'source_dead_flow_blocks',
        'source_dead': 'source_dead_flow', 'source_dead_blocks': 'source_dead_flow_blocks',
        'source_vm': 'source_vm', 'source_vm_enabled': 'source_vm',
        'source_vm_ir': 'source_vm_ir', 'vm_ir': 'source_vm_ir',
        'source_vm_extension': 'source_vm_extension', 'vm_extension': 'source_vm_extension',
        'source_vm_full': 'source_vm_full', 'vm_full': 'source_vm_full',
        'source_vm_ratio': 'source_vm_ratio', 'source_vm_min_ops': 'source_vm_min_ops',
        'source_vm_max_ops': 'source_vm_max_ops', 'source_vm_max_functions': 'source_vm_max_functions', 'source_vm_include': 'source_vm_include',
        'source_vm_exclude': 'source_vm_exclude', 'source_vm_allow_loops': 'source_vm_allow_loops', 'source_vm_debug': 'source_vm_debug',
        'source_reference_obf': 'source_reference_obf', 'source_reference_obf_ratio': 'source_reference_obf_ratio',
        'source_reference_obf_exclude': 'source_reference_obf_exclude',
        'source_enabled': 'source_schedule', 'source_schedule': 'source_schedule', 'source_schedule_max_exprs': 'source_schedule_max_exprs', 'source_schedule_window': 'source_schedule_window',
        'source_only': 'source_only', 'source_source_only': 'source_only', 'source_ast_exclude': 'ast_exclude',
        'bytecode_disable': 'no_bytecode_obf', 'bytecode_disabled': 'no_bytecode_obf', 'bytecode_source_only': 'source_only', 'bytecode_disable_for': 'source_only',
        'bytecode_control_flow_flatten': 'control_flow_flatten', 'bytecode_control_flow_max_blocks': 'control_flow_max_blocks',
        'outer_payload_graph_split': 'payload_graph_split',
        'outer_fake_payload_mirrors': 'fake_payload_mirrors', 'outer_payload_graph_decoys': 'payload_graph_decoys', 'outer_api_decoy_refs': 'api_decoy_refs',
        'outer_loader_decoy_tuples': 'loader_decoy_tuples',
    }
    provided = getattr(args, '_provided_options', set())
    for key, value in list(flat.items()):
        key_norm = key.replace('-', '_')
        if key_norm == 'bytecode_enabled' and 'no_bytecode_obf' not in provided:
            setattr(args, 'no_bytecode_obf', not bool(value))
            provided.add('no_bytecode_obf')
            continue
        if key_norm in ('loader_mode', 'basic_loader_mode', 'bytecode_loader_mode') and isinstance(value, bool):
            if 'code_tuple_payload' not in provided:
                setattr(args, 'code_tuple_payload', bool(value))
                provided.add('code_tuple_payload')
            continue
        dest = aliases.get(key_norm)
        if dest and dest not in provided and hasattr(args, dest):
            setattr(args, dest, value)
            provided.add(dest)
    args._provided_options = provided
    return args


def normalize_netease_profile(name):
    name = (name or 'none').strip().lower()
    return NETEASE_PROFILE_ALIASES.get(name, name)


def apply_netease_profile(args):
    profile_name = normalize_netease_profile(getattr(args, 'netease_profile', 'none'))
    if profile_name not in NETEASE_PROFILES:
        raise ValueError('unknown netease profile: %s' % getattr(args, 'netease_profile', profile_name))
    if profile_name == 'none':
        return args
    provided = set(getattr(args, '_provided_options', set()))
    profile = NETEASE_PROFILES[profile_name]
    for key, value in list(profile.items()):
        if key in provided:
            continue
        if isinstance(value, list):
            setattr(args, key, list(value))
        else:
            setattr(args, key, value)
    args.netease_profile = profile_name
    return args
