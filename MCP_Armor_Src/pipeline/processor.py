# -*- coding: utf-8 -*-
"""Single-file and folder obfuscation pipelines."""


import fnmatch
import os
import re
import shutil
import sys
import time
import copy
import tempfile
from MCP_Armor_Src.utils.progress import run_file_with_progress

from MCP_Armor_Src.ast_obf.control_flow import (
    compile_source,
    make_source_only_output,
)

from MCP_Armor_Src.ast_obf.analysis import analyze_source, analyze_source_project
from MCP_Armor_Src.ast_obf.global_rename import build_global_rename_project
from MCP_Armor_Src.ast_obf.module_rename import (
    ModuleLinkError,
    audit_module_links,
    build_module_rename_project,
    rewrite_module_source,
)
from MCP_Armor_Src.ast_obf.function_split import split_project_functions
from MCP_Armor_Src.ast_obf.structure import render_source_tree

from MCP_Armor_Src.bytecode_obf.code_objects import (
    build_lazy_function_capsules,
    obfuscate_code_with_options,
)

from MCP_Armor_Src.opcode_rep_netease.opcode_maps import (
    build_per_code_runtime_opcode_layer,
    build_runtime_opcode_layer,
    invert_opcode_map,
    load_mcs_opcode_map,
    remap_code_object,
    runtime_table_to_stored_std,
)

from MCP_Armor_Src.loaders.factory import (
    make_function_loader,
    make_loader,
    make_source_loader,
)
from MCP_Armor_Src.loaders.netease_guard import find_behavior_pack_uuid

from MCP_Armor_Src.utils.branding import (
    add_mcp_shiled_header,
    output_date_timestamp,
)

from MCP_Armor_Src.utils.encoding import (
    obfuscate_reserved_generated_identifiers,
    random_ident,
    reserve_source_identifiers,
)

from MCP_Armor_Src.utils.filesystem import (
    decode_source_bytes,
    ensure_dir,
    read_file,
    relpath,
    write_file,
)
from MCP_Armor_Src.utils.pyc import build_timestamp_pyc

from MCP_Armor_Src.static_check import (
    BYPASS_FILENAME,
    enforce_source_compliance,
)
from MCP_Armor_Src.compat.target_backend import (
    run_target_job,
    target_worker_required,
)


def opcode_excluded(rel, patterns):
    rel_norm = rel.replace('\\', '/')
    base = os.path.basename(rel_norm)
    for pattern in patterns or []:
        if fnmatch.fnmatch(rel_norm, pattern) or fnmatch.fnmatch(base, pattern):
            return True
    return False


def requires_reflection_bootstrap_compatibility(source):
    """Detect bootstrap code whose live local namespace is part of its API."""
    if not source:
        return False
    if isinstance(source, bytes):
        source = decode_source_bytes(source)
    lowered = source.lower()
    reflection_tokens = (
        '__subclasses__', '__mro__', '__globals__', 'func_globals',
        'f_locals', 'f_globals', '__builtins__',
    )
    execution_tokens = (
        'eval(', 'exec(', 'exec ', 'compile(', '__import__',
    )
    reflection_hits = sum(token in lowered for token in reflection_tokens)
    execution_hits = sum(token in lowered for token in execution_tokens)
    return reflection_hits >= 2 and execution_hits >= 1


def stabilize_reflection_bootstrap_bytecode(options):
    """Keep forced bootstrap wrapping out of CodeType reconstruction modes.

    Reflection bootstraps are allowed to opt into cPickle wrapping for source
    hiding, but their dynamically created classes are especially sensitive to
    reconstructed ``co_argcount``/closure/constant field layouts.  These
    switches only change the payload storage representation; ByteCode_Flow,
    opcode mapping, metadata noise, and payload segmentation remain active.
    """
    safe = copy.copy(options)
    for name in (
            'code_bytes_split', 'code_ref_table', 'code_tuple_field_shuffle',
            'code_tuple_fragments', 'code_tuple_fragment_providers',
            'code_tuple_provider_graph', 'code_field_descriptors',
            'code_provider_context_bind', 'code_global_arena',
            'code_template_delta', 'code_block_relocation',
            'code_unit_arena', 'code_operand_graph', 'code_const_arena',
            'code_const_provider_graph', 'code_capsule_proxy',
            'code_fused_restore', 'loader_reference_cleanup',
            'lazy_function_capsules'):
        setattr(safe, name, False)
    for name in (
            'code_bytes_fake_chunks', 'code_ref_decoys',
            'code_tuple_provider_decoys', 'code_global_arena_decoys',
            'code_block_reloc_decoys', 'code_unit_arena_decoys',
            'code_const_arena_decoys'):
        setattr(safe, name, 0)
    return safe


def write_obfuscated_artifact(dst, source, opts):
    """Write source or a source-less Python 2.7 pyc outer artifact."""
    if not getattr(opts, 'emit_pyc', False):
        write_file(dst, source)
        try:
            stamp = output_date_timestamp(getattr(opts, 'output_date', None))
            os.utime(dst, (stamp, stamp))
        except (OSError, ValueError, TypeError):
            pass
        return
    label = '<%s>' % random_ident('pyc')
    code = compile(source, label, 'exec')
    payload = build_timestamp_pyc(
        code, output_date_timestamp(getattr(opts, 'output_date', None)),
        len(source.encode('utf-8')))
    write_file(dst, payload)
    try:
        stamp = output_date_timestamp(getattr(opts, 'output_date', None))
        os.utime(dst, (stamp, stamp))
    except (OSError, ValueError, TypeError):
        pass


def apply_resource_budget(options, source_size):
    """Clamp transforms that multiply one another's stored representation."""
    profile = getattr(options, 'resource_profile', 'balanced')
    if profile == 'unlimited':
        # Unlimited means that the global governor does not cap the caller's
        # requested settings.  It still used to leave small files with low
        # profile defaults (for example flow ratio 25 or VM minimum ops 8),
        # making them materially weaker than larger files.  Apply a *floor*
        # only to layers the caller already enabled; feature switches remain
        # explicit and all per-CodeObject safety gates remain authoritative.
        opts = copy.copy(options)
        source_size = int(source_size or 0)
        floor_limit = 16384
        boosts = []

        def floor(name, value):
            if not hasattr(opts, name):
                return
            try:
                current = getattr(opts, name)
                value = int(value)
                if int(current) < value:
                    setattr(opts, name, value)
                    boosts.append('%s:%s->%s' % (name, current, value))
            except (TypeError, ValueError):
                return

        def set_if_enabled(flag, name, value):
            if bool(getattr(opts, flag, False)):
                floor(name, value)

        # A small source file has less natural CFG entropy. Raise density and
        # candidate budgets, but preserve explicit false feature switches.
        if source_size <= floor_limit:
            set_if_enabled('source_vm', 'source_vm_ratio', 100)
            if bool(getattr(opts, 'source_vm', False)) and not bool(
                    getattr(opts, 'source_vm_full', False)):
                if hasattr(opts, 'source_vm_min_ops'):
                    current = int(getattr(opts, 'source_vm_min_ops') or 0)
                    if current > 1:
                        setattr(opts, 'source_vm_min_ops', 1)
                        boosts.append('source_vm_min_ops:%s->1' % current)
                if hasattr(opts, 'source_vm_max_functions') and int(
                        getattr(opts, 'source_vm_max_functions') or 0) > 0:
                    current = getattr(opts, 'source_vm_max_functions')
                    setattr(opts, 'source_vm_max_functions', 0)
                    boosts.append('source_vm_max_functions:%s->0' % current)

            set_if_enabled('bytecode_flow', 'bytecode_flow_ratio', 100)
            set_if_enabled('bytecode_flow', 'bytecode_flow_max_edges', 16)
            set_if_enabled('bytecode_flow_block_seeds',
                           'bytecode_flow_block_seed_ratio', 100)
            set_if_enabled('bytecode_flow_block_seeds',
                           'bytecode_flow_block_seed_max_blocks', 128)
            set_if_enabled('bytecode_flow_block_shuffle',
                           'bytecode_flow_block_shuffle_ratio', 100)
            set_if_enabled('bytecode_flow_block_shuffle',
                           'bytecode_flow_block_shuffle_max_blocks', 192)
            set_if_enabled('bytecode_decoy_islands',
                           'bytecode_decoy_island_ratio', 100)
            set_if_enabled('bytecode_decoy_islands',
                           'bytecode_decoy_island_limit', 4)
            set_if_enabled('bytecode_decoy_islands',
                           'bytecode_decoy_island_width', 6)
            set_if_enabled('bytecode_decoy_islands',
                           'bytecode_decoy_island_growth', 35)
            set_if_enabled('bytecode_opaque_predicates',
                           'bytecode_opaque_limit', 6)
            set_if_enabled('bytecode_opaque_predicates',
                           'bytecode_opaque_width', 5)
            set_if_enabled('bytecode_stack_noise',
                           'bytecode_stack_noise_limit', 8)
            set_if_enabled('bytecode_jump_inversion',
                           'bytecode_jump_inversion_limit', 8)
            set_if_enabled('bytecode_jump_trampolines',
                           'bytecode_jump_trampoline_limit', 8)
            set_if_enabled('bytecode_delayed_const_access',
                           'bytecode_delayed_const_limit', 8)
            set_if_enabled('code_bytes_split', 'code_bytes_fake_chunks', 4)
            set_if_enabled('code_ref_table', 'code_ref_decoys', 16)
            set_if_enabled('code_tuple_provider_graph',
                           'code_tuple_provider_decoys', 8)
            set_if_enabled('code_const_arena', 'code_const_arena_decoys', 12)
            set_if_enabled('code_global_arena',
                           'code_global_arena_decoys', 12)
            set_if_enabled('safe_dead_blocks', 'safe_dead_limit', 6)
            set_if_enabled('source_string_xor', 'source_string_xor_limit', 512)
            set_if_enabled('source_string_xor', 'source_string_xor_variants', 4)
            set_if_enabled('source_string_split', 'source_string_split_parts', 4)
            set_if_enabled('source_identity_weave', 'source_identity_max', 8)
            set_if_enabled('source_decompiler_carriers',
                           'source_decompiler_carriers', 2)
            if hasattr(opts, 'const_noise'):
                floor('const_noise', 12)
            if hasattr(opts, 'const_swamp'):
                floor('const_swamp', 16)
            if hasattr(opts, 'root_const_swamp'):
                floor('root_const_swamp', 96)
            if hasattr(opts, 'bytecode_const_salts'):
                floor('bytecode_const_salts', 16)
            if hasattr(opts, 'bytecode_name_chaff'):
                floor('bytecode_name_chaff', 24)
            if hasattr(opts, 'ghost_names'):
                floor('ghost_names', 32)
            if hasattr(opts, 'loader_junk'):
                floor('loader_junk', 4)
            if hasattr(opts, 'trampoline_layers'):
                floor('trampoline_layers', 3)
            if hasattr(opts, 'payload_splits'):
                floor('payload_splits', 4)
            if hasattr(opts, 'payload_graph_decoys'):
                floor('payload_graph_decoys', 12)

        opts.unlimited_floor_applied = bool(boosts)
        opts.unlimited_floor_source_size = source_size
        opts.unlimited_floor_boosts = tuple(boosts)
        return opts
    opts = copy.copy(options)

    def cap(name, limit):
        if hasattr(opts, name):
            setattr(opts, name, min(getattr(opts, name), limit))

    # Limits are per file. Large modules get a slightly tighter cold-function
    # budget because VM/Lazy payloads scale with the number of nested codes.
    large = int(source_size or 0) >= 65536
    if profile == 'compact':
        opts.code_ref_table = False
        opts.code_ref_decoys = 0
        opts.code_ref_wide_rows = False
        opts.code_ref_mask_markers = False
        opts.code_tuple_provider_graph = False
        opts.code_tuple_provider_decoys = 0
        opts.code_field_descriptors = False
        opts.code_provider_context_bind = False
        opts.code_global_arena = False
        opts.code_template_delta = False
        opts.code_unit_arena = False
        opts.code_const_arena = False
        opts.lazy_capsule_rotate_payload = False
        opts.lazy_capsule_carrier_swap = False
        cap('source_vm_ratio', 12)
        cap('source_vm_max_functions', 1)
        cap('lazy_capsule_ratio', 6)
        cap('lazy_capsule_max_functions', 1)
        cap('source_identity_max', 2)
        cap('source_decompiler_carriers', 1)
        cap('code_bytes_fake_chunks', 1)
        cap('fake_code_objects', 0)
        cap('root_const_swamp', 8)
        cap('const_swamp', 3)
        cap('bytecode_const_salts', 3)
        cap('bytecode_name_chaff', 4)
        cap('ghost_names', 6)
        cap('loader_decoy_tuples', 1)
        cap('outer_decompiler_baits', 1)
        cap('outer_decompiler_bait_budget', 2048)
        cap('payload_graph_decoys', 3)
        cap('api_decoy_refs', 6)
    elif profile == 'balanced':
        # RefTable + provider graph + descriptors duplicate the same recursive
        # CodeTuple three times. Keep fragments/shuffle, but only one storage
        # topology in the recommended profile.
        opts.code_ref_table = False
        opts.code_ref_decoys = 0
        opts.code_ref_wide_rows = False
        opts.code_ref_mask_markers = False
        opts.code_tuple_provider_graph = False
        opts.code_tuple_provider_decoys = 0
        opts.code_field_descriptors = False
        opts.code_provider_context_bind = False
        opts.code_global_arena = False
        opts.code_template_delta = False
        opts.code_unit_arena = False
        opts.code_const_arena = False
        opts.lazy_capsule_rotate_payload = False
        cap('source_vm_ratio', 20 if not large else 12)
        cap('source_vm_max_functions', 2 if not large else 1)
        cap('lazy_capsule_ratio', 8 if not large else 5)
        cap('lazy_capsule_max_functions', 2 if not large else 1)
        cap('source_identity_max', 3 if not large else 2)
        cap('source_decompiler_carriers', 1)
        cap('source_decoy_docstring_max', 512)
        cap('code_bytes_fake_chunks', 2)
        cap('fake_code_objects', 0)
        cap('root_const_swamp', 16 if not large else 8)
        cap('const_swamp', 4 if not large else 3)
        cap('bytecode_const_salts', 4)
        cap('bytecode_name_chaff', 6)
        cap('ghost_names', 8)
        cap('loader_decoy_tuples', 2)
        cap('outer_decompiler_baits', 1 if large else 2)
        cap('outer_decompiler_bait_budget', 3072 if large else 4096)
        cap('payload_graph_decoys', 5)
        cap('api_decoy_refs', 10)
    else:  # strong
        opts.code_field_descriptors = False
        opts.code_provider_context_bind = False
        opts.lazy_capsule_rotate_payload = False
        cap('code_ref_decoys', 4)
        cap('code_tuple_provider_decoys', 2)
        cap('source_vm_ratio', 30 if not large else 18)
        cap('source_vm_max_functions', 4 if not large else 2)
        cap('lazy_capsule_ratio', 15 if not large else 10)
        cap('lazy_capsule_max_functions', 5 if not large else 3)
        cap('source_identity_max', 8 if not large else 5)
        cap('source_decompiler_carriers', 2)
        cap('source_decoy_docstring_max', 1024)
        cap('code_bytes_fake_chunks', 3)
        cap('fake_code_objects', 1)
        cap('root_const_swamp', 64 if not large else 32)
        cap('const_swamp', 10 if not large else 6)
        cap('bytecode_const_salts', 10)
        cap('bytecode_name_chaff', 12)
        cap('ghost_names', 18)
        cap('loader_decoy_tuples', 3)
        cap('outer_decompiler_baits', 3 if large else 4)
        cap('outer_decompiler_bait_budget', 8192 if large else 12288)
        cap('payload_graph_decoys', 12)
        cap('api_decoy_refs', 24)

    # NetEase embeds CPython 2.7 inside a native engine.  A malformed or
    # engine-sensitive func_code swap can terminate that process before a
    # Python traceback is produced (the logger then only reports a dropped
    # connection).  Keep these experimental transforms behind the explicit
    # unlimited profile; the normal compatibility profiles retain encrypted
    # lazy capsules and the verified ByteCode_Flow transforms without mutating a live
    # carrier function or executing the module in a synthetic namespace.
    embedded_netease = getattr(opts, 'loader_mode', '') == 'netease-func'
    if embedded_netease and profile in ('compact', 'balanced'):
        opts.lazy_capsule_rotate_payload = False
        opts.lazy_capsule_carrier_swap = False
        opts.lazy_capsule_carrier_route_rotation = False
        opts.import_facade_layer = False
        opts.module_registry_protection = False
        opts.real_block_reorder = False
        opts.bytecode_flow_block_shuffle = False
        opts.bytecode_extended_arg_prefix = False

    micro_limit = 1024 if profile == 'strong' else 4096
    micro = (int(source_size or 0) <= micro_limit and
             profile in ('compact', 'balanced', 'strong'))
    if micro:
        # A full generic CodeTuple/Provider runtime costs more than the whole
        # module at this size. The code object is still transformed and the
        # final marshal blob is still encrypted by the outer loader.
        opts.code_tuple_payload = False
        opts.code_bytes_split = False
        opts.code_bytes_fake_chunks = 0
        opts.code_ref_table = False
        opts.code_tuple_field_shuffle = False
        opts.code_tuple_fragments = False
        opts.code_tuple_fragment_providers = False
        opts.code_tuple_provider_graph = False
        opts.code_capsule_proxy = False
        opts.code_capsule_protocol_guard = False
        opts.code_field_descriptors = False
        opts.code_provider_context_bind = False
        opts.lazy_function_capsules = False
        opts.source_vm = False
        opts.source_vm_full = False
        opts.source_reference_obf = False
        opts.source_flow_hardening = False
        opts.source_internal_predicates = False
        opts.source_identity_weave = False
        opts.source_tuple_arg_decoys = 0
        opts.source_dotzero_relay = False
        opts.source_default_capsule = False
        opts.source_decompiler_carriers = 0
        opts.source_string_xor = False
        opts.source_string_split = False
        opts.source_dead_flow = False
        opts.payload_splits = 1
        opts.payload_graph_split = False
        opts.fake_payload_mirrors = 0
        opts.payload_graph_decoys = 0
        opts.loader_decoy_tuples = 0
        opts.outer_decompiler_baits = 0
        opts.loader_junk = min(opts.loader_junk, 1)
        opts.trampoline_layers = 0
        opts.decoy_opcode_rows = 0
        opts.fake_ref_layers = 0
        opts.api_decoy_refs = 0
        opts.fake_mcs_tables = 0
        opts.taunt_inner_consts = min(opts.taunt_inner_consts, 2)
        opts.taunt_outer_refs = min(opts.taunt_outer_refs, 2)
        opts.outer_closure_vault = False
        opts.outer_tuple_gateway = False
        opts.outer_closure_index_mirage = False
        opts.outer_generator_frame_mirage = False
        opts.outer_method_descriptor_mirage = False
        opts.outer_defaults_dict_doppelganger = False
        opts.outer_dynamic_method = False
        opts.outer_dynamic_class = False
        opts.outer_callable_proxy = False
        opts.outer_frame_namespace = False
        opts.outer_generator_stages = False
        opts.outer_exception_state = False
    return opts


def obfuscate_file(src, dst, opts, rel=None):
    source_data = read_file(src)
    reserve_source_identifiers(source_data)
    opts = apply_resource_budget(opts, os.path.getsize(src))
    if getattr(opts, 'unlimited_floor_applied', False) and getattr(
            opts, 'debug', False):
        print('[DEBUG] Unlimited floor size=%d boosts=%s' % (
            getattr(opts, 'unlimited_floor_source_size', 0),
            ','.join(getattr(opts, 'unlimited_floor_boosts', ()))))
    if (getattr(opts, 'source_global_rename', False) and
            not getattr(opts, 'source_project_analyses', None)):
        prepare_single_global_rename(src, opts)
    if (target_worker_required() and
            (getattr(opts, 'emit_pyc', False) or
             getattr(opts, 'source_global_rename', False) or
             getattr(opts, 'source_module_rename', False))):
        run_target_job('file', src, dst, opts, rel=rel)
        return
    source_analysis = getattr(
        opts, 'source_project_analyses', {}).get(os.path.abspath(src))
    loader_mode = opts.loader_mode
    runtime_opcode_layer = opts.runtime_opcode_layer
    if loader_mode == 'netease-func' and not getattr(
            opts, 'opcode_replacement', False):
        if not getattr(opts, 'compact_cpickle_loader', False):
            loader_mode = 'function'
        runtime_opcode_layer = False
    source_linearize_calls = opts.source_linearize_calls
    source_schedule = opts.source_schedule
    source_dead_flow = opts.source_dead_flow
    source_vm = opts.source_vm
    source_reference_obf = opts.source_reference_obf
    source_flow_hardening = opts.source_flow_hardening
    source_internal_predicates = opts.source_internal_predicates
    control_flow_flatten = opts.control_flow_flatten
    source_string_split = opts.source_string_split
    source_string_xor = opts.source_string_xor
    source_constant_pool = opts.source_constant_pool
    source_constant_rewrite = opts.source_constant_rewrite
    source_exception_shell = opts.source_exception_shell
    source_parenthesis_noise = opts.source_parenthesis_noise
    source_comment_noise = opts.source_comment_noise
    source_decompiler_carriers = opts.source_decompiler_carriers
    source_exception_lattice = opts.source_exception_lattice
    source_class_body_trap = opts.source_class_body_trap
    source_identity_variation = opts.source_identity_variation
    source_tuple_arg_decoys = opts.source_tuple_arg_decoys
    source_dotzero_relay = opts.source_dotzero_relay
    source_default_capsule = opts.source_default_capsule
    source_identity_weave = opts.source_identity_weave
    bootstrap_name = (os.path.basename(rel).lower()
                      if rel is not None else '')
    is_bootstrap = bootstrap_name in ('modmain.py', '__init__.py')
    reflection_bootstrap = requires_reflection_bootstrap_compatibility(
        source_data)
    # Package initializers often enumerate globals and instantiate every
    # class, yet do not necessarily contain the deeper reflection tokens used
    # by ``requires_reflection_bootstrap_compatibility``.  When callers
    # explicitly ask to protect either bootstrap filename, always use the
    # stable payload layout for that entry point.
    forced_bootstrap_bytecode = (
        is_bootstrap and getattr(
            opts, 'force_bootstrap_obfuscation',
            getattr(opts, 'force_modmain_obfuscation', False)))
    if forced_bootstrap_bytecode:
        opts = stabilize_reflection_bootstrap_bytecode(opts)
        # ``__init__.py`` enumerates globals and calls each class; hide loader
        # helpers from that one initializer.  modMain.py deliberately walks
        # the host module/reference graph, so it must retain host globals.
        opts.compact_isolated_globals = bootstrap_name == '__init__.py'
    preserve_inner_code = (
        reflection_bootstrap and not forced_bootstrap_bytecode)
    if preserve_inner_code:
        # Deep-reflection bootstraps execute strings against live module locals
        # and may inspect ``__main__``/builtins while the module is importing.
        # Replaying their module code through FunctionType changes that startup
        # frame and has caused silent NetEase disconnects before modMain loads.
        # Keep the body exact and route it through the source-compatibility
        # branch below; other modules retain the selected bytecode loader.
        source_linearize_calls = False
        source_schedule = False
        source_dead_flow = False
        source_vm = False
        source_reference_obf = False
        source_flow_hardening = False
        source_internal_predicates = False
        if not getattr(opts, 'source_module_rename', False):
            source_analysis = None
        control_flow_flatten = False
        source_string_split = False
        source_string_xor = False
        source_constant_pool = False
        source_constant_rewrite = False
        source_exception_shell = False
        source_parenthesis_noise = False
        source_comment_noise = False
        source_decompiler_carriers = 0
        source_exception_lattice = False
        source_class_body_trap = False
        source_identity_variation = False
        source_tuple_arg_decoys = 0
        source_dotzero_relay = False
        source_default_capsule = False
        source_identity_weave = False
        loader_mode = 'source'
        runtime_opcode_layer = False
        if opts.debug:
            print('[DEBUG] reflection bootstrap source compatibility: %s' % (
                rel or os.path.basename(src)))
    source_only = bool(opts.no_bytecode_obf or preserve_inner_code)
    if rel and opcode_excluded(rel, opts.source_only):
        source_only = True
    if rel and opcode_excluded(rel, opts.ast_exclude):
        source_linearize_calls = False
        source_schedule = False
        source_dead_flow = False
        # Source-only/client files have no bytecode payload to protect them.
        # Keep the explicitly enabled VM as their final executable layer, but
        # never re-enable it for reflection bootstraps whose live module frame
        # is the compatibility boundary.
        source_vm = bool(
            opts.source_vm and source_only and not preserve_inner_code)
        source_reference_obf = False
        source_flow_hardening = False
        source_internal_predicates = False
        if not getattr(opts, 'source_module_rename', False):
            source_analysis = None
        control_flow_flatten = False
        source_string_split = False
        source_string_xor = False
        source_constant_pool = False
        source_constant_rewrite = False
        source_exception_shell = False
        source_parenthesis_noise = False
        source_comment_noise = False
        source_decompiler_carriers = 0
        source_exception_lattice = False
        source_class_body_trap = False
        source_identity_variation = False
    if rel and opcode_excluded(rel, opts.opcode_exclude):
        if loader_mode == 'netease-func':
            loader_mode = 'function'
        runtime_opcode_layer = False
    if source_only:
        source_output = make_source_only_output(src, opts, source_linearize_calls, source_schedule, source_dead_flow, control_flow_flatten,
                                                                     source_string_split, source_string_xor, source_constant_pool,
                                                                     source_constant_rewrite, source_exception_shell, source_parenthesis_noise,
                                                                     source_comment_noise, source_vm,
                                                                      source_tuple_arg_decoys, source_dotzero_relay,
                                                                      source_default_capsule, source_identity_weave,
                                                                      source_decompiler_carriers,
                                                                      source_exception_lattice,
                                                                      source_class_body_trap,
                                                                      source_identity_variation,
                                                                      source_reference_obf,
                                                                      source_analysis,
                                                                      source_flow_hardening,
                                                                      source_internal_predicates)
        if getattr(opts, 'anti_debug', False):
            source_output = make_source_loader(source_output, opts)
        write_obfuscated_artifact(
            dst, add_mcp_shiled_header(
                source_output, opts.header_mode, opts.output_date), opts)
        return
    elif loader_mode == 'source' and not opts.inner_opcode_tunnel:
        loader = make_source_loader(read_file(src), opts)
    else:
        # CPython bytecode and marshal streams are runtime-version specific.
        # Keep orchestration on Python 3.13, but execute this narrow target
        # phase inside the isolated Python 2.7 worker used by NetEase output.
        if target_worker_required():
            run_target_job('file', src, dst, opts, rel=rel)
            return
        code = compile_source(src, opts.filename_mode, control_flow_flatten, opts.control_flow_max_blocks,
                              source_linearize_calls,
                              source_schedule, opts.source_schedule_max_exprs, opts.source_schedule_window,
                              source_dead_flow, opts.source_dead_flow_blocks,
                              opts.metadata_name_poison,
                              source_string_split, opts.source_string_split_parts,
                              source_string_xor, opts.source_string_xor_mode, opts.source_string_xor_text,
                              opts.source_string_xor_number, opts.source_string_xor_min_length, opts.source_string_xor_limit,
                              opts.source_string_xor_variants, opts.source_string_xor_decoys,
                              opts.source_string_xor_debug,
                              source_constant_pool, opts.source_constant_pool_min, opts.source_constant_pool_max,
                              source_constant_rewrite, opts.source_constant_rewrite_limit,
                              source_exception_shell,
                              source_vm, opts.source_vm_ratio, opts.source_vm_min_ops,
                              opts.source_vm_max_ops, opts.source_vm_max_functions, opts.source_vm_include,
                              opts.source_vm_exclude, opts.source_vm_allow_loops,
                              opts.source_vm_debug, source_tuple_arg_decoys,
                              source_dotzero_relay, source_default_capsule,
                               source_identity_weave, opts.source_identity_ratio,
                               opts.source_identity_max, source_identity_variation,
                               source_decompiler_carriers,
                               source_exception_lattice,
                               source_class_body_trap,
                               source_reference_obf,
                               opts.source_reference_obf_ratio,
                               opts.source_reference_obf_exclude,
                               opts.source_decoy_docstrings,
                               opts.source_decoy_docstring_min,
                               opts.source_decoy_docstring_max,
                               source_analysis,
                               source_flow_hardening,
                               source_internal_predicates,
                               opts.source_internal_predicate_ratio,
                               opts.source_hot_patterns,
                               opts.source_vm_dialects,
                               opts.source_vm_flow_constants,
                               opts.source_vm_exception_trap_ratio)
        lazy_capsules = None
        if opts.lazy_function_capsules and not preserve_inner_code:
            manager_name = random_ident('lazy_manager')
            code, lazy_entries = build_lazy_function_capsules(
                code, manager_name, opts.lazy_capsule_ratio,
                opts.lazy_capsule_max_functions, opts.lazy_capsule_include,
                opts.lazy_capsule_exclude, opts.lazy_capsule_mode,
                opts.lazy_capsule_retain_calls)
            if lazy_entries:
                lazy_capsules = {
                    'manager_name': manager_name,
                    'entries': lazy_entries,
                }
        if not preserve_inner_code:
            code = obfuscate_code_with_options(code, opts)
        if lazy_capsules:
            for lazy_entry in lazy_capsules['entries']:
                # These objects were detached before the recursive module pass,
                # so apply the same function-depth transforms independently.
                lazy_entry['code'] = obfuscate_code_with_options(
                    lazy_entry['code'], opts, 1)
        if loader_mode == 'netease-func':
            mcs_map = load_mcs_opcode_map(opts.mcs_opmap_version)
            lazy_stored_to_std = invert_opcode_map(mcs_map)
            if lazy_capsules:
                for lazy_entry in lazy_capsules['entries']:
                    # Lazy functions execute directly in the NetEase VM and do
                    # not depend on the module payload's temporary runtime map.
                    lazy_entry['code'] = remap_code_object(
                        lazy_entry['code'], mcs_map)
            if runtime_opcode_layer:
                if opts.per_code_runtime_opcode:
                    code, runtime_opcode_table = build_per_code_runtime_opcode_layer(
                        code, opts.mcs_opmap_version, opts.opcode_runtime)
                else:
                    code, runtime_opcode_table = build_runtime_opcode_layer(
                        code, opts.mcs_opmap_version, opts.opcode_runtime)
                if opts.opcode_runtime == 'mcs':
                    target_to_std = invert_opcode_map(mcs_map)
                else:
                    target_to_std = dict((value, value) for value in range(256))
                stored_to_std = runtime_table_to_stored_std(runtime_opcode_table, target_to_std)
                loader = make_function_loader(
                    code, opts, runtime_opcode_table, stored_to_std,
                    lazy_capsules, lazy_stored_to_std)
            else:
                if opts.opcode_runtime == 'mcs':
                    code = remap_code_object(code, mcs_map)
                    stored_to_std = invert_opcode_map(mcs_map)
                else:
                    stored_to_std = {}
                loader = make_function_loader(
                    code, opts, None, stored_to_std,
                    lazy_capsules, lazy_stored_to_std)
        elif loader_mode == 'function':
            loader = make_function_loader(
                code, opts, None, {}, lazy_capsules, {})
        else:
            loader = make_loader(code, opts)
    loader = obfuscate_reserved_generated_identifiers(loader)
    write_obfuscated_artifact(
        dst, add_mcp_shiled_header(loader, opts.header_mode, opts.output_date), opts)


def should_include(rel, includes, excludes):
    rel_norm = rel.replace('\\', '/')
    base = os.path.basename(rel_norm)
    included = False
    for pattern in includes:
        if fnmatch.fnmatch(rel_norm, pattern) or fnmatch.fnmatch(base, pattern):
            included = True
            break
    if not included:
        return False
    for pattern in excludes:
        if fnmatch.fnmatch(rel_norm, pattern) or fnmatch.fnmatch(base, pattern):
            return False
    return True


def detect_side(rel):
    low = rel.replace('\\', '/').lower()
    base = os.path.basename(low)
    if base == 'modmain.py':
        return 'modmain'
    if 'clientsystem' in base or '/client/' in low or low.startswith('client/'):
        return 'client'
    if 'serversystem' in base or '/server/' in low or low.startswith('server/'):
        return 'server'
    return 'common'


def side_selected(side, target_side):
    if target_side == 'all':
        return True
    if side == 'common':
        return True
    return side == target_side


def fix_register_source(source, package_name, namespace):
    def fix_path(match):
        quote = match.group(1)
        cls = match.group(2)
        return quote + package_name + '.' + cls + '.' + cls + quote
    source = re.sub(r'''(['"])(?:[A-Za-z_][\w]*\.)*(NeteaseServerSystem)\.NeteaseServerSystem\1''', fix_path, source)
    source = re.sub(r'''(['"])(?:[A-Za-z_][\w]*\.)*(NeteaseClientSystem)\.NeteaseClientSystem\1''', fix_path, source)
    if namespace:
        source = re.sub(r'''(RegisterSystem\s*\(\s*)(['"])[^'"]+\2''', lambda m: m.group(1) + repr(namespace), source)
    return source


def copy_or_fix(src, dst, args, opts=None):
    data = read_file(src)
    if isinstance(data, bytes):
        data = data.decode('utf-8-sig', 'replace')
    if args.fix_netease_register and os.path.basename(src).lower() == 'modmain.py':
        data = fix_register_source(data, args.package_name, args.namespace)
    if opts is not None and getattr(opts, 'source_module_rename', False):
        analysis = getattr(
            opts, 'source_project_analyses', {}).get(os.path.abspath(src))
        plan = getattr(analysis, 'module_rename_plan', None)
        if plan is not None:
            data = rewrite_module_source(data, plan, render_source_tree)
    if os.path.basename(dst).lower().endswith('.py'):
        data = add_mcp_shiled_header(data, args.header_mode,
                                     getattr(opts, 'output_date', None))
        write_file(dst, data)
        try:
            stamp = output_date_timestamp(getattr(opts, 'output_date', None))
            os.utime(dst, (stamp, stamp))
        except (OSError, ValueError, TypeError):
            pass
    else:
        write_file(dst, data)


def ensure_excluded_sources(src_root, dst_root, args, opts,
                            module_project=None):
    """Copy excluded Python ABI files omitted by the target worker.

    The worker intentionally processes only selected source files.  Excluded
    files (package initializers, API shims, mod entry points, configs) still
    belong in the output and must retain their original filenames.
    """
    for root, dirs, files in os.walk(src_root):
        for name in files:
            if not name.lower().endswith('.py'):
                continue
            rel = relpath(os.path.join(root, name), src_root)
            if should_include(rel, args.include or ['*.py'],
                              list(args.exclude or [])):
                continue
            src = os.path.join(root, name)
            output_rel = (module_project.output_rel(rel)
                          if module_project is not None else rel)
            dst = os.path.join(dst_root, output_rel.replace('/', os.sep))
            if os.path.exists(dst):
                continue
            ensure_dir(os.path.dirname(dst))
            if module_project is not None and name != '__init__.py':
                data = read_file(src)
                if isinstance(data, bytes):
                    data = data.decode('utf-8-sig', 'replace')
                plan = module_project.plan_for(os.path.abspath(src))
                if plan is not None:
                    data = rewrite_module_source(data, plan, render_source_tree)
                write_file(dst, add_mcp_shiled_header(
                    data, args.header_mode,
                    getattr(opts, 'output_date', None)))
                try:
                    stamp = output_date_timestamp(getattr(opts, 'output_date', None))
                    os.utime(dst, (stamp, stamp))
                except (OSError, ValueError, TypeError):
                    pass
            else:
                copy_or_fix(src, dst, args, opts)


def ensure_renamed_outputs(src_root, dst_root, args, opts, module_project):
    """Backfill renamed modules skipped by a delegated target worker.

    The Python-2 worker receives the project through a JSON boundary.  When
    function-splitting adds sibling modules, an older worker can finish
    successfully while omitting one of those late files.  Imports then point
    at a generated stem (for example ``aFP``) that is absent from the output.
    Re-run the normal per-file pipeline only for missing mapped outputs; this
    keeps the worker as the source of truth and avoids changing existing
    artifacts.
    """
    if module_project is None:
        return 0
    restored = 0
    for rel, mapped_rel in list(module_project.rel_map.items()):
        src = os.path.join(src_root, rel.replace('/', os.sep))
        dst = os.path.join(dst_root, mapped_rel.replace('/', os.sep))
        if not os.path.isfile(src) or os.path.exists(dst):
            continue
        ensure_dir(os.path.dirname(dst))
        if src.lower().endswith('.py'):
            try:
                obfuscate_file(src, dst, opts, rel)
            except Exception as error:
                if getattr(opts, 'debug', False):
                    print('[DEBUG] renamed module worker fallback %s: %s' %
                          (rel, error))
            if not os.path.exists(dst):
                # A worker may skip an exotic generated sibling without
                # reporting an IPC failure.  Emit a source-linked fallback at
                # the exact mapped path so imports cannot dangle.
                data = read_file(src)
                if isinstance(data, bytes):
                    data = data.decode('utf-8-sig', 'replace')
                plan = module_project.plan_for(os.path.abspath(src))
                if plan is not None:
                    data = rewrite_module_source(data, plan,
                                                 render_source_tree)
                write_file(dst, add_mcp_shiled_header(
                    data, args.header_mode,
                    getattr(opts, 'output_date', None)))
        else:
            copy_or_fix(src, dst, args, opts)
        restored += 1
    if restored and getattr(opts, 'debug', False):
        print('[DEBUG] Restored missing renamed modules=%d' % restored)
    return restored


def write_rename_mapping_report(dst_root, module_project, global_project=None):
    """Write a deterministic ProGuard-style file/class mapping report."""
    if module_project is None:
        return None
    path = os.path.join(dst_root, 'mapping.txt')
    lines = ['# MCPArmor rename mapping', '# format: original -> emitted']
    for old in sorted(module_project.module_map):
        new = module_project.module_map[old]
        if old != new:
            lines.append('%s -> %s' % (old + '.py', new + '.py'))
    if global_project is not None:
        lines.extend(('', '# class mappings'))
        for module in sorted(global_project.modules):
            info = global_project.modules[module]
            mapping = global_project.global_maps.get(module, {})
            for old in sorted(info.classes):
                new = mapping.get(old, old)
                if old != new:
                    lines.append('%s.%s -> %s.%s' % (
                        module or '<root>', old,
                        module_project.mapped_module(module) or '<root>', new))
        lines.extend(('', '# member mappings'))
        for old in sorted(global_project.member_map):
            new = global_project.member_map[old]
            if old != new:
                lines.append('%s -> %s' % (old, new))
    write_file(path, '\n'.join(lines) + '\n')
    return path


def remove_readonly(func, path, exc_info):
    try:
        os.chmod(path, 438)
        func(path)
    except Exception:
        raise


def clean_directory_contents(root):
    """Remove every child while preserving an existing output root.

    Windows tools may keep a directory handle open while still permitting
    its contents to be replaced. Removing the root itself would then fail
    with ERROR_SHARING_VIOLATION after all children had already been deleted.
    """
    if not os.path.isdir(root):
        return
    for name in os.listdir(root):
        path = os.path.join(root, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, onerror=remove_readonly)
        else:
            try:
                os.chmod(path, 438)
            except Exception:
                pass
            os.remove(path)


def deploy_output_folder(src_root, target_root):
    src_root = os.path.abspath(src_root)
    target_root = os.path.abspath(target_root)
    if not os.path.isdir(src_root):
        raise SystemExit('deploy source does not exist: %s' % src_root)
    if not os.path.isdir(target_root):
        ensure_dir(target_root)
    # Safety guard: only deploy to an explicit final mod folder, never a drive root.
    if os.path.basename(target_root).lower() in ('', '.', '..') or len(target_root) < 10:
        raise SystemExit('refuse unsafe deploy target: %s' % target_root)
    clean_directory_contents(target_root)
    for root, dirs, files in os.walk(src_root):
        for name in files:
            if not name.lower().endswith(('.py', '.pyc')):
                continue
            src = os.path.join(root, name)
            rel = relpath(src, src_root)
            dst = os.path.join(target_root, rel.replace('/', os.sep))
            ensure_dir(os.path.dirname(dst))
            shutil.copy2(src, dst)
    return target_root


def process_folder(src_root, dst_root, args, opts):
    # Function splitting operates on a staging copy so the user's source tree
    # remains untouched.  The generated sibling modules are present before
    # static checking, project analysis and module Rename, which keeps imports
    # and registration paths coherent across all later AST passes.
    if (opts is not None and getattr(opts, 'source_function_split', False) and
            not getattr(opts, '_function_split_staged', False)):
        src_root = os.path.abspath(src_root)
        staged_root = tempfile.mkdtemp(prefix='mcparmor_function_split_')
        try:
            try:
                shutil.copytree(src_root, staged_root, dirs_exist_ok=True)
            except TypeError:  # Python 2.7 compatibility
                for current, dirs, files in os.walk(src_root):
                    rel = os.path.relpath(current, src_root)
                    target = staged_root if rel == '.' else os.path.join(staged_root, rel)
                    ensure_dir(target)
                    for directory in dirs:
                        ensure_dir(os.path.join(target, directory))
                    for filename in files:
                        shutil.copy2(os.path.join(current, filename),
                                     os.path.join(target, filename))
            split_count = split_project_functions(
                staged_root, getattr(args, 'include', None),
                getattr(args, 'exclude', None))
            staged_opts = copy.copy(opts)
            staged_opts._function_split_staged = True
            if getattr(opts, 'debug', False):
                print('[DEBUG] Function split extracted=%d staging=%s' %
                      (split_count, staged_root))
            return process_folder(staged_root, dst_root, args, staged_opts)
        finally:
            shutil.rmtree(staged_root, ignore_errors=True)
    # Reflection-heavy entry modules normally remain source-compatible.  An
    # explicit --obfuscate-modmain request is the opt-in that permits the
    # bytecode path for that entry point, including when work is delegated to
    # the Python 2.7 target worker.
    if opts is not None:
        opts.force_modmain_obfuscation = bool(
            getattr(args, 'obfuscate_modmain', False))
        opts.force_bootstrap_obfuscation = bool(
            getattr(args, 'obfuscate_modmain', False) or
            getattr(args, 'obfuscate_init', False))
    if (opts is not None and target_worker_required() and
            (getattr(opts, 'emit_pyc', False) or
             not getattr(opts, 'no_bytecode_obf', False) or
             getattr(opts, 'source_global_rename', False) or
             getattr(opts, 'source_module_rename', False))):
        worker_module_project = None
        worker_global_project = None
        if getattr(opts, 'source_module_rename', False):
            worker_module_project = build_module_rename_project(
                src_root, getattr(opts, 'source_module_rename_exclude', ()))
        if getattr(opts, 'source_global_rename', False):
            worker_global_project = build_global_rename_project(src_root)
        run_target_job('folder', src_root, dst_root, opts, args=args)
        # The target worker may skip excluded files entirely; package
        # initializers are ABI files and must always be present in output.
        ensure_excluded_sources(src_root, dst_root, args, opts,
                                worker_module_project)
        ensure_renamed_outputs(src_root, dst_root, args, opts,
                               worker_module_project)
        if getattr(opts, 'source_module_rename', False):
            # The Python 2 target worker performs its own audit, then the
            # Python 3 controller independently reopens the final files.  This
            # catches worker/deployment drift instead of trusting IPC success.
            module_project = build_module_rename_project(
                src_root,
                getattr(opts, 'source_module_rename_exclude', ()))
            try:
                audit = audit_module_links(
                    dst_root, module_project,
                    wrapped_modules=not bool(opts.no_bytecode_obf))
                if opts.debug:
                    checked = audit.get('checked', {})
                    print('[DEBUG] Controller module link audit modules=%d '
                          'imports=%d attributes=%d registrations=%d '
                          'dynamic=%d dynamic_unresolved=%d issues=%d' % (
                              audit['modules'], checked.get('imports', 0),
                              checked.get('attributes', 0),
                              checked.get('registrations', 0),
                              checked.get('dynamic_imports', 0),
                              audit['dynamic_unresolved'], audit['issues']))
                    for module, lineno, call_name in audit.get(
                            'unresolved_dynamic', ())[:10]:
                        print('[DEBUG] Controller unresolved dynamic '
                              '%s:%s call=%s' % (
                                  module or '<root>', lineno or 0,
                                  call_name))
            except ModuleLinkError as error:
                # The Python 2 worker has already parsed and audited the exact
                # emitted project before returning success.  A Python 3
                # controller may still reject valid target-only syntax such as
                # ``print value`` or tuple parameters.  Treat an all-parse
                # controller result as a cross-version limitation, while
                # retaining every substantive missing-module/symbol failure.
                parse_only = bool(error.issues) and all(
                    issue[2] == 'OUTPUT_PARSE_ERROR'
                    for issue in error.issues)
                if not parse_only:
                    if os.path.isdir(dst_root):
                        clean_directory_contents(dst_root)
                    raise
                if opts.debug:
                    print('[DEBUG] Controller link audit skipped %d '
                          'Python-2-only parse row(s); worker audit passed' %
                          len(error.issues))
            except Exception:
                if os.path.isdir(dst_root):
                    clean_directory_contents(dst_root)
                raise
            if getattr(opts, 'write_rename_mapping', False):
                write_rename_mapping_report(dst_root, module_project,
                                            worker_global_project)
        return _predict_folder_counts(src_root, args)
    src_root = os.path.abspath(src_root)
    dst_root = os.path.abspath(dst_root)
    if getattr(opts, 'anti_debug', False):
        manifest_uuid, manifest_path = find_behavior_pack_uuid(src_root)
        if not manifest_uuid:
            raise ValueError('anti_debug requires a behavior-pack manifest.json with header.uuid near the input folder')
        opts.anti_debug_manifest_uuid = manifest_uuid
        opts.anti_debug_manifest_path = manifest_path
    if getattr(opts, 'static_check', True):
        enforce_source_compliance(
            src_root, True, [dst_root] if dst_root != src_root else None)
    includes = args.include or ['*.py']
    excludes = list(args.exclude or [])
    if not args.obfuscate_modmain and 'modMain.py' not in excludes and 'modmain.py' not in excludes:
        excludes.append('modMain.py')
    if not getattr(args, 'obfuscate_init', False) and '__init__.py' not in excludes:
        excludes.append('__init__.py')
    rename_excluded = set()
    if getattr(opts, 'source_global_rename', False):
        for current, dirs, files in os.walk(src_root):
            for name in files:
                if not name.lower().endswith('.py'):
                    continue
                path = os.path.abspath(os.path.join(current, name))
                rel = relpath(path, src_root)
                side = detect_side(rel)
                if (not should_include(rel, includes, excludes) or
                        not side_selected(side, args.target_side) or
                        opcode_excluded(rel, opts.ast_exclude)):
                    rename_excluded.add(path)
    module_project = None
    if getattr(opts, 'source_module_rename', False):
        module_project = build_module_rename_project(
            src_root, getattr(opts, 'source_module_rename_exclude', ()))
    if opts.source_project_analysis:
        opts.source_project_analyses = analyze_source_project(
            src_root, opts.source_hot_patterns,
            opts.source_internal_predicate_ratio)
        if getattr(opts, 'source_global_rename', False):
            rename_project = build_global_rename_project(
                src_root, rename_excluded)
            for path, analysis in list(
                    opts.source_project_analyses.items()):
                analysis.global_rename_plan = rename_project.plan_for(path)
            if module_project is not None:
                module_project.symbol_maps = rename_project.global_maps
        if module_project is not None:
            for path, analysis in list(
                    opts.source_project_analyses.items()):
                analysis.module_rename_plan = module_project.plan_for(path)
        if opts.debug:
            totals = {'functions': 0, 'hot': 0, 'reachable': 0,
                      'escaped': 0, 'internal': 0}
            for analysis in list(opts.source_project_analyses.values()):
                for key in totals:
                    totals[key] += analysis.stats.get(key, 0)
            print('[DEBUG] Project analysis files=%d functions=%d hot=%d reachable=%d escaped=%d internal=%d' % (
                len(opts.source_project_analyses), totals['functions'],
                totals['hot'], totals['reachable'], totals['escaped'],
                totals['internal']))
            if getattr(opts, 'source_global_rename', False):
                print('[DEBUG] Global rename modules=%d globals=%d members=%d excluded=%d' % (
                    len(rename_project.modules),
                    sum(len(item) for item in
                        list(rename_project.global_maps.values())),
                    len(rename_project.member_map), len(rename_excluded)))
            if module_project is not None:
                print('[DEBUG] Module rename files=%d excluded=%d' % (
                    len(module_project.rel_map),
                    len(module_project.path_modules) - len(module_project.rel_map)))
    if os.path.exists(dst_root) and args.clean_output:
        clean_directory_contents(dst_root)
    ensure_dir(dst_root)
    counts = {'obfuscated': 0, 'copied': 0, 'fixed': 0}
    # Count the same eligible source files as the execution loop; copied and
    # excluded resources do not inflate the obfuscation progress denominator.
    progress_total = sum(
        1 for _root, _dirs, _files in os.walk(src_root) for _name in _files
        if _name != BYPASS_FILENAME and _name.lower().endswith('.py')
        and should_include(relpath(os.path.join(_root, _name), src_root), includes, excludes)
        and side_selected(detect_side(relpath(os.path.join(_root, _name), src_root)), args.target_side))
    progress_index = 0
    for root, dirs, files in os.walk(src_root):
        for name in files:
            if name == BYPASS_FILENAME:
                continue
            if name.lower().endswith(('.pyc', '.pyo')) and not args.copy_pyc:
                continue
            src = os.path.join(root, name)
            rel = relpath(src, src_root)
            is_py = name.lower().endswith('.py')
            output_rel = (module_project.output_rel(rel)
                          if is_py and module_project is not None else rel)
            dst = os.path.join(dst_root, output_rel.replace('/', os.sep))
            side = detect_side(rel)
            if is_py and should_include(rel, includes, excludes) and side_selected(side, args.target_side):
                progress_index += 1
                if getattr(opts, 'emit_pyc', False):
                    dst = os.path.splitext(dst)[0] + '.pyc'
                run_file_with_progress(obfuscate_file, src, dst, opts, rel,
                                       progress_index, progress_total)
                counts['obfuscated'] += 1
            else:
                before = read_file(src) if (is_py and args.fix_netease_register and name.lower() == 'modmain.py') else None
                copy_or_fix(src, dst, args, opts)
                if before is not None and before != read_file(dst):
                    counts['fixed'] += 1
                else:
                    counts['copied'] += 1
    ensure_excluded_sources(src_root, dst_root, args, opts, module_project)
    ensure_renamed_outputs(src_root, dst_root, args, opts, module_project)
    if module_project is not None:
        try:
            audit = audit_module_links(
                dst_root, module_project,
                wrapped_modules=not bool(opts.no_bytecode_obf))
            if opts.debug:
                checked = audit.get('checked', {})
                print('[DEBUG] Module link audit modules=%d imports=%d '
                      'attributes=%d registrations=%d dynamic=%d '
                      'dynamic_unresolved=%d issues=%d' % (
                    audit['modules'],
                    checked.get('imports', 0),
                    checked.get('attributes', 0),
                    checked.get('registrations', 0),
                    checked.get('dynamic_imports', 0),
                    audit['dynamic_unresolved'], audit['issues']))
                for module, lineno, call_name in audit.get(
                        'unresolved_dynamic', ())[:10]:
                    print('[DEBUG] Module link unresolved dynamic '
                          '%s:%s call=%s' % (
                              module or '<root>', lineno or 0, call_name))
        except Exception:
            if os.path.isdir(dst_root):
                clean_directory_contents(dst_root)
            raise
        if getattr(opts, 'write_rename_mapping', False):
            write_rename_mapping_report(dst_root, module_project,
                                        locals().get('rename_project'))
    return counts


def _predict_folder_counts(src_root, args):
    """Reconstruct worker folder counts for the Python 3 host CLI."""
    src_root = os.path.abspath(src_root)
    includes = args.include or ['*.py']
    excludes = list(args.exclude or [])
    if (not args.obfuscate_modmain and 'modMain.py' not in excludes and
            'modmain.py' not in excludes):
        excludes.append('modMain.py')
    if (not getattr(args, 'obfuscate_init', False) and
            '__init__.py' not in excludes):
        excludes.append('__init__.py')
    counts = {'obfuscated': 0, 'copied': 0, 'fixed': 0}
    for root, dirs, files in os.walk(src_root):
        for name in files:
            if name == BYPASS_FILENAME:
                continue
            if (name.lower().endswith(('.pyc', '.pyo')) and
                    not args.copy_pyc):
                continue
            path = os.path.join(root, name)
            rel = relpath(path, src_root)
            is_py = name.lower().endswith('.py')
            side = detect_side(rel)
            if (is_py and should_include(rel, includes, excludes) and
                    side_selected(side, args.target_side)):
                counts['obfuscated'] += 1
            elif (is_py and args.fix_netease_register and
                  name.lower() == 'modmain.py'):
                counts['fixed'] += 1
            else:
                counts['copied'] += 1
    return counts


def process_single(src, dst, args, opts):
    opts.force_modmain_obfuscation = bool(
        getattr(args, 'obfuscate_modmain', False))
    opts.force_bootstrap_obfuscation = bool(
        getattr(args, 'obfuscate_modmain', False) or
        getattr(args, 'obfuscate_init', False))
    if getattr(opts, 'source_function_split', False):
        raise ValueError(
            'source.function_split requires a project directory; pass a folder '
            'input or disable source.function_split for a single .py file')
    if getattr(opts, 'source_module_rename', False):
        raise ValueError(
            'source.module_rename requires a project directory; pass a folder '
            'input or disable source.module_rename for a single .py file')
    if getattr(opts, 'anti_debug', False):
        manifest_uuid, manifest_path = find_behavior_pack_uuid(src)
        if not manifest_uuid:
            raise ValueError('anti_debug requires a behavior-pack manifest.json with header.uuid near the input file')
        opts.anti_debug_manifest_uuid = manifest_uuid
        opts.anti_debug_manifest_path = manifest_path
    if getattr(opts, 'static_check', True):
        enforce_source_compliance(src, False)
    if args.fix_netease_register and os.path.basename(src).lower() == 'modmain.py' and not args.obfuscate_modmain:
        copy_or_fix(src, dst, args, opts)
        return 'fixed/copied'
    run_file_with_progress(obfuscate_file, src, dst, opts, os.path.basename(src), 1, 1)
    return 'obfuscated'


def prepare_single_global_rename(src, opts):
    """Attach a one-file rename plan, preserving sibling files as ABI users."""
    src_abs = os.path.abspath(src)
    root = os.path.dirname(src_abs)
    excluded = set()
    allowed = set([src_abs])
    for name in os.listdir(root):
        path = os.path.abspath(os.path.join(root, name))
        if path != src_abs and name.lower().endswith('.py'):
            excluded.add(path)
            allowed.add(path)
    with open(src_abs, 'rb') as handle:
        source = handle.read()
    try:
        analysis = analyze_source(
            source, src_abs, opts.source_hot_patterns,
            opts.source_internal_predicate_ratio)
    except (SyntaxError, ValueError, TypeError):
        # A Python 2-only source file is compiled by the target worker and
        # cannot be parsed by the Python 3.13 host planner.  Keep it exact;
        # the worker will build the same plan under its native grammar.
        opts.source_project_analyses = {}
        return None
    opts.source_project_analyses = {src_abs: analysis}
    rename_project = build_global_rename_project(
        root, excluded, allowed)
    for path, analysis in list(opts.source_project_analyses.items()):
        analysis.global_rename_plan = rename_project.plan_for(path)
    return rename_project
