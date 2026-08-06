# -*- coding: utf-8 -*-
"""Single-file and folder obfuscation pipelines."""
from __future__ import absolute_import, print_function

import fnmatch
import imp
import marshal
import os
import re
import shutil
import struct
import time
import copy

from MCP_Armor_Src.ast_obf.control_flow import (
    compile_source,
    make_source_only_output,
)

from MCP_Armor_Src.ast_obf.analysis import analyze_source_project

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
)

from MCP_Armor_Src.utils.encoding import (
    obfuscate_reserved_generated_identifiers,
    random_ident,
)

from MCP_Armor_Src.utils.filesystem import (
    ensure_dir,
    read_file,
    relpath,
    write_file,
)

from MCP_Armor_Src.static_check import (
    BYPASS_FILENAME,
    enforce_source_compliance,
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


def write_obfuscated_artifact(dst, source, opts):
    """Write source or a source-less Python 2.7 pyc outer artifact."""
    if not getattr(opts, 'emit_pyc', False):
        write_file(dst, source)
        return
    label = '<%s>' % random_ident('pyc')
    code = compile(source, label, 'exec')
    timestamp = int(time.time()) & 0xffffffff
    payload = imp.get_magic() + struct.pack('<L', timestamp) + marshal.dumps(code)
    write_file(dst, payload)


def apply_resource_budget(options, source_size):
    """Clamp transforms that multiply one another's stored representation."""
    profile = getattr(options, 'resource_profile', 'balanced')
    if profile == 'unlimited':
        return options
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
    # lazy capsules and the verified CFG transforms without mutating a live
    # carrier function or executing the module in a synthetic namespace.
    embedded_netease = getattr(opts, 'loader_mode', '') == 'netease-func'
    if embedded_netease and profile in ('compact', 'balanced'):
        opts.lazy_capsule_rotate_payload = False
        opts.lazy_capsule_carrier_swap = False
        opts.lazy_capsule_carrier_route_rotation = False
        opts.import_facade_layer = False
        opts.module_registry_protection = False
        opts.real_block_reorder = False
        opts.bytecode_cfg_block_shuffle = False
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
    opts = apply_resource_budget(opts, os.path.getsize(src))
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
    source_local_rename = opts.source_local_rename
    source_dead_flow = opts.source_dead_flow
    source_vm = opts.source_vm
    source_reference_obf = opts.source_reference_obf
    source_flow_hardening = opts.source_flow_hardening
    source_internal_predicates = opts.source_internal_predicates
    control_flow_flatten = opts.control_flow_flatten
    source_name_obfuscation = opts.source_name_obfuscation
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
    preserve_inner_code = requires_reflection_bootstrap_compatibility(
        read_file(src))
    if preserve_inner_code:
        # Deep-reflection importers execute strings against live locals. Keep
        # their compiled body exact and apply protection at the outer loader.
        source_linearize_calls = False
        source_schedule = False
        source_local_rename = False
        source_dead_flow = False
        source_vm = False
        source_reference_obf = False
        source_flow_hardening = False
        source_internal_predicates = False
        source_analysis = None
        control_flow_flatten = False
        source_name_obfuscation = False
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
        loader_mode = 'function'
        runtime_opcode_layer = False
        if opts.debug:
            print('[DEBUG] reflection bootstrap compatibility: %s' % (
                rel or os.path.basename(src)))
    source_only = bool(opts.no_bytecode_obf)
    if rel and opcode_excluded(rel, opts.source_only):
        source_only = True
    if rel and opcode_excluded(rel, opts.ast_exclude):
        source_linearize_calls = False
        source_schedule = False
        source_local_rename = False
        source_dead_flow = False
        # Source-only/client files have no bytecode payload to protect them.
        # Keep the explicitly enabled VM as their final executable layer even
        # when the remaining AST transforms are excluded for compatibility.
        source_vm = bool(opts.source_vm and source_only)
        source_reference_obf = False
        source_flow_hardening = False
        source_internal_predicates = False
        source_analysis = None
        control_flow_flatten = False
        source_name_obfuscation = False
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
        source_output = make_source_only_output(src, opts, source_linearize_calls, source_schedule, source_local_rename, source_dead_flow, control_flow_flatten,
                                                                     source_name_obfuscation, source_string_split, source_string_xor, source_constant_pool,
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
            dst, add_mcp_shiled_header(source_output, opts.header_mode), opts)
        return
    elif loader_mode == 'source' and not opts.inner_opcode_tunnel:
        loader = make_source_loader(read_file(src), opts)
    else:
        code = compile_source(src, opts.filename_mode, control_flow_flatten, opts.control_flow_max_blocks,
                              source_linearize_calls,
                              source_schedule, opts.source_schedule_max_exprs, opts.source_schedule_window,
                              source_local_rename, opts.source_local_rename_max,
                              source_dead_flow, opts.source_dead_flow_blocks,
                              opts.metadata_name_poison,
                              source_name_obfuscation, opts.source_name_obfuscation_max,
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
        dst, add_mcp_shiled_header(loader, opts.header_mode), opts)


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


def copy_or_fix(src, dst, args):
    data = read_file(src)
    if args.fix_netease_register and os.path.basename(src).lower() == 'modmain.py':
        data = fix_register_source(data, args.package_name, args.namespace)
    if os.path.basename(dst).lower().endswith('.py'):
        data = add_mcp_shiled_header(data, args.header_mode)
    write_file(dst, data)


def remove_readonly(func, path, exc_info):
    try:
        os.chmod(path, 438)
        func(path)
    except Exception:
        raise


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
    for name in os.listdir(target_root):
        path = os.path.join(target_root, name)
        if os.path.isdir(path):
            shutil.rmtree(path, onerror=remove_readonly)
        else:
            try:
                os.chmod(path, 438)
            except Exception:
                pass
            os.remove(path)
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
    src_root = os.path.abspath(src_root)
    dst_root = os.path.abspath(dst_root)
    if getattr(opts, 'anti_debug', False):
        manifest_uuid, manifest_path = find_behavior_pack_uuid(src_root)
        if not manifest_uuid:
            raise ValueError('anti_debug requires a behavior-pack manifest.json with header.uuid near the input folder')
        opts.anti_debug_manifest_uuid = manifest_uuid
        opts.anti_debug_manifest_path = manifest_path
    enforce_source_compliance(
        src_root, True, [dst_root] if dst_root != src_root else None)
    if opts.source_project_analysis:
        opts.source_project_analyses = analyze_source_project(
            src_root, opts.source_hot_patterns,
            opts.source_internal_predicate_ratio)
        if opts.debug:
            totals = {'functions': 0, 'hot': 0, 'reachable': 0,
                      'escaped': 0, 'internal': 0}
            for analysis in opts.source_project_analyses.values():
                for key in totals:
                    totals[key] += analysis.stats.get(key, 0)
            print('[DEBUG] Project analysis files=%d functions=%d hot=%d reachable=%d escaped=%d internal=%d' % (
                len(opts.source_project_analyses), totals['functions'],
                totals['hot'], totals['reachable'], totals['escaped'],
                totals['internal']))
    if os.path.exists(dst_root) and args.clean_output:
        shutil.rmtree(dst_root, onerror=remove_readonly)
    ensure_dir(dst_root)
    counts = {'obfuscated': 0, 'copied': 0, 'fixed': 0}
    includes = args.include or ['*.py']
    excludes = list(args.exclude or [])
    if not args.obfuscate_modmain and 'modMain.py' not in excludes and 'modmain.py' not in excludes:
        excludes.append('modMain.py')
    if not getattr(args, 'obfuscate_init', False) and '__init__.py' not in excludes:
        excludes.append('__init__.py')
    for root, dirs, files in os.walk(src_root):
        for name in files:
            if name == BYPASS_FILENAME:
                continue
            if name.lower().endswith(('.pyc', '.pyo')) and not args.copy_pyc:
                continue
            src = os.path.join(root, name)
            rel = relpath(src, src_root)
            dst = os.path.join(dst_root, rel.replace('/', os.sep))
            is_py = name.lower().endswith('.py')
            side = detect_side(rel)
            if is_py and should_include(rel, includes, excludes) and side_selected(side, args.target_side):
                if getattr(opts, 'emit_pyc', False):
                    dst = os.path.splitext(dst)[0] + '.pyc'
                obfuscate_file(src, dst, opts, rel)
                counts['obfuscated'] += 1
            else:
                before = read_file(src) if (is_py and args.fix_netease_register and name.lower() == 'modmain.py') else None
                copy_or_fix(src, dst, args)
                if before is not None and before != read_file(dst):
                    counts['fixed'] += 1
                else:
                    counts['copied'] += 1
    return counts


def process_single(src, dst, args, opts):
    if getattr(opts, 'anti_debug', False):
        manifest_uuid, manifest_path = find_behavior_pack_uuid(src)
        if not manifest_uuid:
            raise ValueError('anti_debug requires a behavior-pack manifest.json with header.uuid near the input file')
        opts.anti_debug_manifest_uuid = manifest_uuid
        opts.anti_debug_manifest_path = manifest_path
    enforce_source_compliance(src, False)
    if args.fix_netease_register and os.path.basename(src).lower() == 'modmain.py' and not args.obfuscate_modmain:
        copy_or_fix(src, dst, args)
        return 'fixed/copied'
    obfuscate_file(src, dst, opts, os.path.basename(src))
    return 'obfuscated'
