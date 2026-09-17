# -*- coding: utf-8 -*-
"""Preset expansion and validated runtime options."""


from MCP_Armor_Src.core.constants import (
    PRESETS,
)


class Options(object):
    pass


def merge_options(args):
    # The UI's lightweight YAML writer may serialize an unset preset as
    # ``None`` (capitalized) while the CLI parser uses ``none``.  Normalize
    # both forms before indexing the preset table so a saved run_config.yml
    # remains portable between UI and CLI builds.
    preset_name = args.preset
    if preset_name is None:
        preset_name = 'none'
    else:
        preset_name = str(preset_name).strip().lower()
        if preset_name in ('', 'none', 'null'):
            preset_name = 'none'
    if preset_name not in PRESETS:
        raise ValueError('unknown preset: %s' % preset_name)
    preset = PRESETS[preset_name].copy()
    opts = Options()
    for name, value in list(preset.items()):
        setattr(opts, name, value)
    opts.debug = bool(args.debug)
    opts.python27 = getattr(args, 'python27', None)
    opts.static_check = bool(getattr(args, 'static_check', False))
    opts.emit_pyc = bool(args.emit_pyc)
    opts.resource_profile = str(args.resource_profile or 'balanced')
    opts.header_mode = str(args.header_mode or 'docstring').strip().lower()
    if opts.header_mode not in ('comment', 'docstring'):
        raise ValueError('header_mode must be comment or docstring')
    opts.output_date = str(getattr(args, 'output_date', None) or '2012-03-15').strip()
    opts.write_rename_mapping = bool(getattr(args, 'write_rename_mapping', False))
    opts.key_len = args.key_len
    opts.payload_cipher = args.payload_cipher
    opts.anti_debug = bool(args.anti_debug)
    opts.experimental_anti_debug = bool(args.experimental_anti_debug)
    if opts.anti_debug:
        opts.payload_cipher = 'chacha'
    opts.const_noise = args.const_noise if args.const_noise is not None else opts.const_noise
    opts.tail_noise = args.tail_noise if args.tail_noise is not None else opts.tail_noise
    opts.loader_junk = args.loader_junk if args.loader_junk is not None else opts.loader_junk
    opts.trampoline_layers = args.trampoline_layers if args.trampoline_layers is not None else opts.trampoline_layers
    opts.decoy_opcode_rows = args.decoy_opcode_rows if args.decoy_opcode_rows is not None else opts.decoy_opcode_rows
    opts.fake_ref_layers = args.fake_ref_layers if args.fake_ref_layers is not None else opts.fake_ref_layers
    opts.dead_bad_bytecode = args.dead_bad_bytecode
    opts.dead_bad_units = args.dead_bad_units
    opts.dead_nop_bloat = args.dead_nop_bloat
    opts.dead_stop_bloat = args.dead_stop_bloat
    opts.dead_arg_poison = args.dead_arg_poison
    opts.dead_exception_poison = args.dead_exception_poison
    opts.dead_call_poison = args.dead_call_poison
    opts.metadata_poison = args.metadata_poison
    opts.metadata_binary = args.metadata_binary
    opts.metadata_name_poison = args.metadata_name_poison
    opts.adaptive_strength = args.adaptive_strength
    opts.adaptive_max_scale = args.adaptive_max_scale
    opts.fake_mcs_tables = args.fake_mcs_tables
    opts.payload_splits = args.payload_splits
    opts.taunt_text = args.taunt_text
    opts.taunt_inner_consts = args.taunt_inner_consts
    opts.taunt_outer_refs = args.taunt_outer_refs
    opts.bytecode_split_gates = args.bytecode_split_gates
    opts.bytecode_split_interval = args.bytecode_split_interval
    opts.bytecode_split_bad_units = args.bytecode_split_bad_units
    opts.bytecode_split_nop_bloat = args.bytecode_split_nop_bloat
    opts.fake_code_objects = args.fake_code_objects
    opts.fake_code_nop_bloat = args.fake_code_nop_bloat
    opts.fake_code_stop_bloat = args.fake_code_stop_bloat
    opts.ghost_names = args.ghost_names
    opts.payload_graph_split = args.payload_graph_split
    opts.split_adaptive = args.split_adaptive
    opts.loop_shadow_gates = args.loop_shadow_gates
    opts.fake_payload_mirrors = args.fake_payload_mirrors
    opts.payload_graph_decoys = args.payload_graph_decoys
    opts.loader_decoy_tuples = args.loader_decoy_tuples
    opts.outer_decompiler_baits = max(
        0, min(4, int(args.outer_decompiler_baits or 0)))
    opts.outer_decompiler_bait_budget = max(
        0, min(65536, int(args.outer_decompiler_bait_budget or 0)))
    opts.import_facade_layer = args.import_facade_layer
    opts.reflection_metadata_decoy = args.reflection_metadata_decoy
    opts.module_registry_protection = args.module_registry_protection and opts.import_facade_layer
    opts.outer_closure_vault = args.outer_closure_vault
    opts.outer_tuple_gateway = args.outer_tuple_gateway
    opts.outer_closure_index_mirage = args.outer_closure_index_mirage
    opts.outer_generator_frame_mirage = args.outer_generator_frame_mirage
    opts.outer_method_descriptor_mirage = args.outer_method_descriptor_mirage
    opts.outer_defaults_dict_doppelganger = args.outer_defaults_dict_doppelganger
    opts.outer_dynamic_method = args.outer_dynamic_method
    opts.outer_dynamic_class = args.outer_dynamic_class
    opts.outer_callable_proxy = args.outer_callable_proxy
    opts.outer_frame_namespace = args.outer_frame_namespace
    opts.outer_generator_stages = args.outer_generator_stages
    opts.outer_exception_state = args.outer_exception_state
    opts.code_capsule_proxy = args.code_capsule_proxy
    opts.code_capsule_protocol_guard = args.code_capsule_protocol_guard and opts.code_capsule_proxy
    outer_weird_enabled = any((
        opts.outer_closure_vault, opts.outer_tuple_gateway,
        opts.outer_closure_index_mirage,
        opts.outer_generator_frame_mirage,
        opts.outer_method_descriptor_mirage,
        opts.outer_defaults_dict_doppelganger, opts.outer_dynamic_method,
        opts.outer_dynamic_class, opts.outer_callable_proxy,
        opts.outer_frame_namespace, opts.outer_generator_stages,
        opts.outer_exception_state,
    ))
    opts.outer_no_sys_import = args.outer_no_sys_import or outer_weird_enabled
    if opts.outer_no_sys_import:
        opts.import_facade_layer = False
        opts.module_registry_protection = False
    opts.opcode_restore_noise = args.opcode_restore_noise
    opts.const_swamp = args.const_swamp
    opts.root_const_swamp = args.root_const_swamp
    opts.const_ref_chains = args.const_ref_chains
    opts.api_decoy_refs = args.api_decoy_refs
    opts.real_block_reorder = args.real_block_reorder
    opts.real_block_reorder_limit = args.real_block_reorder_limit
    opts.bytecode_taken_jump_poison = bool(args.bytecode_taken_jump_poison)
    opts.safe_dead_blocks = bool(args.safe_dead_blocks or opts.bytecode_taken_jump_poison)
    opts.safe_dead_interval = args.safe_dead_interval
    opts.safe_dead_width = args.safe_dead_width
    opts.safe_dead_limit = args.safe_dead_limit
    opts.bytecode_decoy_islands = bool(args.bytecode_decoy_islands)
    opts.bytecode_decoy_island_ratio = max(
        0, min(100, int(args.bytecode_decoy_island_ratio or 0)))
    opts.bytecode_decoy_island_limit = max(
        0, min(8, int(args.bytecode_decoy_island_limit or 0)))
    opts.bytecode_decoy_island_width = max(
        2, min(8, int(args.bytecode_decoy_island_width or 0)))
    opts.bytecode_decoy_island_growth = max(
        1, min(100, int(args.bytecode_decoy_island_growth or 0)))
    opts.oparg_poison = bool(args.oparg_poison or opts.bytecode_taken_jump_poison)
    opts.bytecode_opaque_predicates = args.bytecode_opaque_predicates
    opts.bytecode_opaque_interval = args.bytecode_opaque_interval
    opts.bytecode_opaque_width = args.bytecode_opaque_width
    opts.bytecode_opaque_limit = args.bytecode_opaque_limit
    opts.index_pool_shuffle = args.index_pool_shuffle
    opts.index_pool_mirrors = args.index_pool_mirrors
    opts.bytecode_stack_pad = args.bytecode_stack_pad
    opts.bytecode_lnotab_noise = args.bytecode_lnotab_noise
    opts.bytecode_const_salts = args.bytecode_const_salts
    opts.bytecode_name_chaff = args.bytecode_name_chaff
    opts.bytecode_entry_noise = args.bytecode_entry_noise
    opts.bytecode_exception_decoys = args.bytecode_exception_decoys
    opts.bytecode_stack_noise = args.bytecode_stack_noise
    opts.bytecode_stack_noise_interval = args.bytecode_stack_noise_interval
    opts.bytecode_stack_noise_limit = args.bytecode_stack_noise_limit
    opts.bytecode_jump_inversion = args.bytecode_jump_inversion
    opts.bytecode_jump_inversion_limit = args.bytecode_jump_inversion_limit
    opts.bytecode_jump_trampolines = args.bytecode_jump_trampolines
    opts.bytecode_jump_trampoline_limit = args.bytecode_jump_trampoline_limit
    opts.bytecode_flow = bool(args.bytecode_flow)
    opts.bytecode_flow_ratio = max(0, min(100, int(args.bytecode_flow_ratio or 0)))
    opts.bytecode_flow_max_edges = max(0, min(64, int(args.bytecode_flow_max_edges or 0)))
    opts.bytecode_flow_loop_dispatch = bool(args.bytecode_flow_loop_dispatch)
    opts.bytecode_flow_block_seeds = bool(args.bytecode_flow_block_seeds)
    opts.bytecode_flow_block_seed_ratio = max(0, min(100, int(args.bytecode_flow_block_seed_ratio or 0)))
    opts.bytecode_flow_block_seed_max_blocks = max(2, min(256, int(args.bytecode_flow_block_seed_max_blocks or 0)))
    opts.bytecode_flow_block_shuffle = bool(args.bytecode_flow_block_shuffle)
    opts.bytecode_flow_block_shuffle_ratio = max(0, min(100, int(args.bytecode_flow_block_shuffle_ratio or 0)))
    opts.bytecode_flow_block_shuffle_max_blocks = max(2, min(512, int(args.bytecode_flow_block_shuffle_max_blocks or 0)))
    opts.bytecode_strategy_variation = args.bytecode_strategy_variation
    opts.bytecode_strategy_seed = args.bytecode_strategy_seed
    opts.bytecode_delayed_const_access = args.bytecode_delayed_const_access
    opts.bytecode_delayed_const_limit = args.bytecode_delayed_const_limit
    opts.bytecode_extended_arg_prefix = args.bytecode_extended_arg_prefix
    opts.bytecode_extended_arg_interval = args.bytecode_extended_arg_interval
    opts.bytecode_extended_arg_limit = args.bytecode_extended_arg_limit
    opts.slot_mirage = bool(args.slot_mirage)
    opts.slot_mirage_limit = max(0, min(64, int(args.slot_mirage_limit or 0)))
    opts.source_linearize_calls = args.source_linearize_calls
    opts.source_schedule = args.source_schedule
    opts.source_schedule_max_exprs = args.source_schedule_max_exprs
    opts.source_schedule_window = args.source_schedule_window
    opts.source_global_rename = bool(args.source_global_rename)
    opts.source_module_rename = bool(args.source_module_rename)
    opts.source_function_split = bool(getattr(args, 'source_function_split', False))
    opts.source_module_rename_exclude = list(
        args.source_module_rename_exclude or ())
    opts.source_string_split = args.source_string_split
    opts.source_string_split_parts = args.source_string_split_parts
    opts.source_string_xor = args.source_string_xor
    opts.source_string_xor_mode = args.source_string_xor_mode
    opts.source_string_xor_text = args.source_string_xor_text
    opts.source_string_xor_number = max(0, min(255, int(args.source_string_xor_number)))
    opts.source_string_xor_min_length = max(1, int(args.source_string_xor_min_length))
    opts.source_string_xor_limit = max(0, int(args.source_string_xor_limit))
    opts.source_string_xor_variants = max(2, min(8, int(args.source_string_xor_variants)))
    opts.source_string_xor_decoys = max(0, min(8, int(args.source_string_xor_decoys)))
    opts.source_string_xor_debug = bool(args.source_string_xor_debug or opts.debug)
    opts.source_string_hash_compare = bool(
        getattr(args, 'source_string_hash_compare', False))
    opts.source_string_hash_mode = getattr(
        args, 'source_string_hash_mode', 'guard')
    opts.source_string_hash_inline = bool(
        getattr(args, 'source_string_hash_inline', False))
    opts.source_string_hash_inline_obfuscate = bool(
        getattr(args, 'source_string_hash_inline_obfuscate', False) and
        opts.source_string_hash_inline)
    opts.source_string_hash_inline_variants = bool(
        getattr(args, 'source_string_hash_inline_variants', False) and
        opts.source_string_hash_inline)
    opts.source_string_hash_min_length = max(
        1, int(getattr(args, 'source_string_hash_min_length', 6)))
    opts.source_string_hash_ratio = max(
        0, min(100, int(getattr(args, 'source_string_hash_ratio', 100))))
    opts.source_string_hash_limit = max(
        0, int(getattr(args, 'source_string_hash_limit', 128)))
    opts.source_string_hash_exclude = list(
        getattr(args, 'source_string_hash_exclude', ()) or ())
    if opts.source_string_hash_mode not in ('guard', 'hash-only'):
        raise ValueError('source_string_hash_mode must be guard or hash-only')
    opts.source_constant_pool = args.source_constant_pool
    opts.source_constant_pool_min = args.source_constant_pool_min
    opts.source_constant_pool_max = args.source_constant_pool_max
    opts.source_constant_rewrite = args.source_constant_rewrite
    opts.source_constant_rewrite_limit = args.source_constant_rewrite_limit
    opts.source_exception_shell = args.source_exception_shell
    opts.source_parenthesis_noise = args.source_parenthesis_noise
    opts.source_comment_noise = args.source_comment_noise
    opts.source_comment_noise_count = args.source_comment_noise_count
    opts.source_dead_flow = args.source_dead_flow
    opts.source_dead_flow_blocks = args.source_dead_flow_blocks
    # Keep the two VM classes independently addressable. VM-IR selects the
    # full coverage profile; VM extension retains the older selective wrapper
    # and may be combined with VM-IR to keep its carrier extensions enabled.
    opts.source_vm_ir = bool(getattr(args, 'source_vm_ir', False))
    opts.source_vm_extension = bool(
        getattr(args, 'source_vm_extension', False) or args.source_vm)
    opts.source_vm_full = bool(args.source_vm_full or opts.source_vm_ir)
    # VM-IR/extension are explicit AST-layer switches. Never infer them from
    # bytecode settings or stale preset state; a false value must stay false.
    if not bool(getattr(args, 'source_vm_ir', False)):
        opts.source_vm_ir = False
    if not bool(getattr(args, 'source_vm_extension', False)) and not bool(getattr(args, 'source_vm', False)):
        opts.source_vm_extension = False
    opts.source_vm_full = bool(getattr(args, 'source_vm_full', False) or opts.source_vm_ir)
    opts.source_vm = bool(opts.source_vm_extension or opts.source_vm_full)
    opts.source_vm_ratio = max(0, min(100, int(args.source_vm_ratio or 0)))
    opts.source_vm_min_ops = max(1, int(args.source_vm_min_ops or 1))
    opts.source_vm_max_ops = max(opts.source_vm_min_ops, int(args.source_vm_max_ops or opts.source_vm_min_ops))
    opts.source_vm_max_functions = max(0, int(args.source_vm_max_functions or 0))
    opts.source_vm_include = args.source_vm_include or []
    opts.source_vm_exclude = args.source_vm_exclude or []
    opts.source_vm_allow_loops = bool(args.source_vm_allow_loops)
    opts.source_vm_debug = bool(args.source_vm_debug or opts.debug)
    opts.source_flow_hardening = bool(args.source_flow_hardening)
    if opts.source_flow_hardening:
        opts.source_vm = True
    opts.source_project_analysis = bool(
        args.source_project_analysis or opts.source_flow_hardening or
        opts.source_global_rename or opts.source_module_rename)
    opts.source_internal_predicates = bool(
        args.source_internal_predicates or opts.source_flow_hardening)
    opts.source_internal_predicate_ratio = max(
        0, min(100, int(args.source_internal_predicate_ratio or 0)))
    opts.source_hot_patterns = args.source_hot_pattern or [
        'On*', '*Tick*', '*Update*', '*Timer*', '*Frame*', '*Render*',
        'Listen*', 'Notify*', 'Callback', 'Destroy', '__*__']
    opts.source_vm_dialects = max(1, min(
        8, int(args.source_vm_dialects or 1)))
    if opts.source_flow_hardening:
        opts.source_vm_dialects = max(4, opts.source_vm_dialects)
    opts.source_vm_flow_constants = bool(
        args.source_vm_flow_constants or opts.source_flow_hardening)
    opts.source_vm_exception_trap_ratio = max(
        0, min(25, int(args.source_vm_exception_trap_ratio or 0)))
    if opts.source_flow_hardening and not args.source_vm_exception_trap_ratio:
        opts.source_vm_exception_trap_ratio = 2
    opts.source_reference_obf = bool(
        args.source_reference_obf or opts.source_flow_hardening)
    opts.source_reference_obf_ratio = max(
        0, min(100, int(args.source_reference_obf_ratio or 0)))
    opts.source_reference_obf_exclude = (
        args.source_reference_obf_exclude or [])
    if opts.source_vm_full:
        opts.source_vm_ratio = 100
        opts.source_vm_min_ops = 1
        opts.source_vm_max_ops = max(2000, opts.source_vm_max_ops)
        opts.source_vm_max_functions = 0
        opts.source_vm_allow_loops = True
        # The VM already owns control flow. Reapplying ByteCode_Flow to its
        # generated runtime only multiplies size and startup cost.
        opts.const_noise = min(1, opts.const_noise)
        opts.tail_noise = 0
        opts.bytecode_flow = False
        opts.bytecode_flow_block_seeds = False
        opts.bytecode_flow_block_shuffle = False
        opts.bytecode_jump_inversion = False
        opts.bytecode_jump_trampolines = False
        opts.bytecode_stack_noise = False
        opts.bytecode_delayed_const_access = False
        opts.bytecode_extended_arg_prefix = False
    opts.source_tuple_arg_decoys = max(0, min(8, int(args.source_tuple_arg_decoys or 0)))
    # VM classes are independent switches. Do not implicitly enable tuple
    # decoys, dotzero relay, default capsules or Identity Weave when VM-IR or
    # the legacy VM extension is selected; each option must be explicit.
    opts.source_dotzero_relay = bool(args.source_dotzero_relay)
    opts.source_default_capsule = bool(args.source_default_capsule)
    opts.source_identity_weave = bool(args.source_identity_weave)
    opts.source_identity_ratio = max(0, min(100, int(args.source_identity_ratio or 0)))
    opts.source_identity_max = max(0, min(64, int(args.source_identity_max or 0)))
    opts.source_identity_variation = bool(args.source_identity_variation)
    opts.source_decompiler_carriers = max(
        0, min(4, int(args.source_decompiler_carriers or 0)))
    opts.source_decoy_docstrings = bool(args.source_decoy_docstrings)
    opts.source_decoy_docstring_min = max(
        64, min(16384, int(args.source_decoy_docstring_min or 64)))
    opts.source_decoy_docstring_max = max(
        opts.source_decoy_docstring_min,
        min(16384, int(args.source_decoy_docstring_max or
                       opts.source_decoy_docstring_min)))
    opts.source_exception_lattice = bool(args.source_exception_lattice)
    opts.source_class_body_trap = bool(args.source_class_body_trap)
    opts.control_flow_flatten = args.control_flow_flatten
    opts.control_flow_max_blocks = args.control_flow_max_blocks
    opts.opcode_replacement = bool(args.opcode_replacement)
    opts.runtime_opcode_layer = args.runtime_opcode_layer
    opts.per_code_runtime_opcode = args.per_code_runtime_opcode
    opts.runtime_opcode_decoys = args.runtime_opcode_decoys
    opts.opcode_exclude = args.opcode_exclude or []
    opts.no_bytecode_obf = args.no_bytecode_obf
    opts.source_only = args.source_only or []
    opts.ast_exclude = args.ast_exclude or []
    opts.compact_cpickle_loader = (args.loader_mode == 'cpickle')
    opts.loader_vm = bool(getattr(args, 'loader_vm', False))
    opts.loader_dialect = str(getattr(args, 'loader_dialect', 'auto') or 'auto')
    if opts.loader_dialect not in ('auto', '0', '1', '2'):
        raise ValueError('loader_dialect must be auto, 0, 1 or 2')
    # cPickle is a payload/loader format, not a target-runtime declaration.
    # Select the concrete function-loader branch after opcode_runtime has been
    # normalized below; STD must never inherit the NetEase opcode alphabet.
    opts.loader_mode = args.loader_mode
    opts.lazy_function_capsules = bool(args.lazy_function_capsules)
    opts.lazy_capsule_ratio = max(0, min(100, int(args.lazy_capsule_ratio or 0)))
    opts.lazy_capsule_max_functions = max(0, min(256, int(args.lazy_capsule_max_functions or 0)))
    opts.lazy_capsule_mode = args.lazy_capsule_mode
    opts.lazy_capsule_retain_calls = max(1, min(1024, int(args.lazy_capsule_retain_calls or 1)))
    opts.lazy_capsule_cross_key = bool(args.lazy_capsule_cross_key)
    opts.lazy_capsule_rotate_payload = bool(args.lazy_capsule_rotate_payload)
    opts.lazy_capsule_rotate_max_bytes = max(
        0, min(16 * 1024 * 1024,
               int(args.lazy_capsule_rotate_max_bytes or 0)))
    opts.lazy_capsule_carrier_swap = bool(args.lazy_capsule_carrier_swap)
    opts.lazy_capsule_manager_proxy = bool(args.lazy_capsule_manager_proxy)
    opts.lazy_capsule_carrier_route_rotation = bool(
        args.lazy_capsule_carrier_route_rotation and
        opts.lazy_capsule_carrier_swap)
    opts.lazy_capsule_include = args.lazy_capsule_include or []
    opts.lazy_capsule_exclude = args.lazy_capsule_exclude or []
    opts.lazy_capsule_debug = bool(args.lazy_capsule_debug or opts.debug)
    # Every lazy function is serialized as its own recursive Code Tuple.
    # Keep this invariant even when an older config requested marshal mode.
    opts.code_tuple_payload = bool(
        args.code_tuple_payload or opts.lazy_function_capsules or
        opts.compact_cpickle_loader)
    opts.code_bytes_split = args.code_bytes_split and opts.code_tuple_payload
    opts.code_bytes_split_min = args.code_bytes_split_min
    opts.code_bytes_split_max_chunks = args.code_bytes_split_max_chunks
    opts.code_bytes_fake_chunks = args.code_bytes_fake_chunks
    opts.code_ref_table = args.code_ref_table and opts.code_tuple_payload
    opts.code_ref_decoys = args.code_ref_decoys if opts.code_ref_table else 0
    opts.code_ref_wide_rows = args.code_ref_wide_rows and opts.code_ref_table
    opts.code_ref_mask_markers = args.code_ref_mask_markers and opts.code_ref_table
    opts.code_tuple_field_shuffle = args.code_tuple_field_shuffle and opts.code_tuple_payload
    opts.code_tuple_fragments = args.code_tuple_fragments and opts.code_tuple_payload
    opts.code_tuple_fragment_providers = args.code_tuple_fragment_providers and opts.code_tuple_fragments
    opts.code_tuple_provider_graph = args.code_tuple_provider_graph and opts.code_tuple_fragment_providers
    opts.code_tuple_provider_decoys = args.code_tuple_provider_decoys if opts.code_tuple_fragment_providers else 0
    opts.code_field_descriptors = args.code_field_descriptors and opts.code_tuple_payload
    opts.code_provider_context_bind = args.code_provider_context_bind and opts.code_field_descriptors
    opts.code_fused_restore = args.code_fused_restore and opts.code_tuple_payload
    opts.loader_reference_cleanup = args.loader_reference_cleanup
    opts.code_global_arena = args.code_global_arena and opts.code_tuple_payload
    opts.code_template_delta = args.code_template_delta and opts.code_global_arena
    opts.code_global_arena_decoys = args.code_global_arena_decoys if opts.code_global_arena else 0
    opts.code_block_relocation = args.code_block_relocation and opts.code_global_arena
    opts.code_block_reloc_decoys = args.code_block_reloc_decoys if opts.code_block_relocation else 0
    opts.code_unit_arena = args.code_unit_arena and opts.code_global_arena
    opts.code_unit_arena_decoys = args.code_unit_arena_decoys if opts.code_unit_arena else 0
    opts.code_operand_graph = args.code_operand_graph and opts.code_unit_arena
    # A provider graph has no useful execution path without the arena that
    # owns its referenced constants.  Treat the graph switch as the user
    # intent and enable the minimal storage dependency automatically.
    opts.code_const_arena = bool(args.code_const_arena or args.code_const_provider_graph)
    opts.code_const_arena_decoys = args.code_const_arena_decoys if opts.code_const_arena else 0
    opts.code_const_provider_graph = bool(args.code_const_provider_graph and opts.code_const_arena)
    opts.code_const_arena_limit = max(0, int(args.code_const_arena_limit or 0))
    opts.filename_mode = args.filename_mode
    opts.inner_opcode_tunnel = args.inner_opcode_tunnel
    opts.opcode_runtime = args.opcode_runtime
    opts.mcs_opmap_version = args.mcs_opmap_version
    if opts.compact_cpickle_loader:
        # The same compact cPickle outer loader supports two execution targets:
        # NetEase receives its mapped bytecode directly, while native Python
        # 2.7 must retain the standard opcode alphabet.  The compact loader has
        # no generic runtime opcode restoration table, so STD replacement is
        # deliberately disabled instead of emitting a CodeType that crashes
        # the interpreter with STATUS_ACCESS_VIOLATION/illegal instruction.
        if opts.opcode_runtime == 'mcs':
            opts.loader_mode = 'netease-func'
            opts.opcode_replacement = True
            opts.mcs_opmap_version = 1
        else:
            opts.loader_mode = 'function'
            opts.opcode_replacement = False
        opts.runtime_opcode_layer = False
        opts.per_code_runtime_opcode = False
        opts.inner_opcode_tunnel = False
    if not opts.opcode_replacement:
        opts.runtime_opcode_layer = False
        opts.per_code_runtime_opcode = False
        opts.inner_opcode_tunnel = False
    if (opts.source_global_rename or opts.source_linearize_calls or opts.source_schedule or opts.source_dead_flow or opts.source_vm or opts.control_flow_flatten or
            opts.source_string_split or opts.source_string_xor or
            opts.source_string_hash_compare or opts.source_constant_pool or
            opts.source_constant_rewrite or opts.source_exception_shell or opts.source_parenthesis_noise or
            opts.source_comment_noise or opts.source_decompiler_carriers or
            opts.source_identity_weave or opts.source_tuple_arg_decoys or
            opts.source_flow_hardening or opts.source_internal_predicates) and opts.loader_mode == 'source':
        opts.loader_mode = 'function'
    if (outer_weird_enabled or opts.code_capsule_proxy or opts.lazy_function_capsules) and opts.loader_mode not in ('netease-func', 'function'):
        opts.loader_mode = 'function'
    if opts.inner_opcode_tunnel and opts.loader_mode not in ('netease-func', 'function'):
        opts.loader_mode = 'marshal'
    return opts
