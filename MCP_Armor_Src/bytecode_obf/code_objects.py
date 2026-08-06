# -*- coding: utf-8 -*-
"""Recursive CodeType transformations and lazy-function extraction."""
from __future__ import absolute_import, print_function

import fnmatch
import os
import random
import re
import types

from MCP_Armor_Src.bytecode_obf.decoys import (
    build_dead_bad_bytecode,
    make_const_reference_chain,
    make_const_swamp,
    make_fake_code_object,
    make_fake_const,
    make_ghost_names,
)

from MCP_Armor_Src.bytecode_obf.instructions import (
    apply_index_pool_shuffle,
    bytecode_conditional_jump_inversion,
    bytecode_delayed_constant_access,
    bytecode_extended_arg_prefixes,
    bytecode_has_exception_control_flow,
    bytecode_jump_trampoline_chains,
    bytecode_opaque_predicates,
    bytecode_reorder_linear_blocks,
    bytecode_safe_dead_blocks,
    bytecode_split_gates,
    bytecode_stack_equivalent_noise,
    bytecode_strategy_variant,
    can_apply_bytecode_opaque_predicates,
    make_index_pool_mirrors,
    prepend_exception_decoys,
    prepend_legal_entry_noise,
)

from MCP_Armor_Src.bytecode_obf.cfg.transform import (
    apply_conditional_edge_proxies,
)
from MCP_Armor_Src.bytecode_obf.cfg.block_seeds import (
    apply_block_seed_flow,
)
from MCP_Armor_Src.bytecode_obf.cfg.block_shuffle import (
    apply_basic_block_shuffle,
)
from MCP_Armor_Src.bytecode_obf.cfg.decoy_islands import (
    apply_decoy_islands,
)
from MCP_Armor_Src.bytecode_obf.cfg.dispatcher import (
    apply_state_dispatcher,
)

from MCP_Armor_Src.bytecode_obf.model import (
    rebuild_code,
)

from MCP_Armor_Src.core.constants import (
    CO_GENERATOR,
    CO_VARARGS,
    CO_VARKEYWORDS,
    JUMP_FORWARD,
    LOAD_CONST,
    NOP,
    POP_TOP,
    is_function_code,
)

from MCP_Armor_Src.utils.encoding import (
    can_poison_real_code_name,
    random_binary_metadata_label,
    random_bytes,
    random_ident,
    random_metadata_label,
)


def append_tail_noise(co, count, bad_count=0, bad_units=3, nop_bloat=0, stop_bloat=0, arg_poison=0, exception_poison=0, call_poison=0, code_bytes=None):
    tail = []
    for _ in range(max(0, count)):
        tail.append(chr(NOP))
        tail.append(chr(LOAD_CONST))
        tail.append('\x00\x00')
        tail.append(chr(POP_TOP))
        if JUMP_FORWARD is not None:
            tail.append(chr(JUMP_FORWARD))
            tail.append('\x00\x00')
    if bad_count > 0:
        tail.append(build_dead_bad_bytecode(bad_count, bad_units, nop_bloat, stop_bloat, arg_poison, exception_poison, call_poison))
    if not tail:
        return co.co_code if code_bytes is None else code_bytes
    return (co.co_code if code_bytes is None else code_bytes) + ''.join(tail)


def lazy_capsule_valid_arg_name(name):
    return bool(isinstance(name, str) and
                re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name))


def lazy_capsule_function_eligible(co, include=None, exclude=None):
    if not is_function_code(co):
        return False
    if co.co_flags & CO_GENERATOR:
        return False
    if co.co_freevars:
        return False
    name = co.co_name or ''
    if not name or name.startswith('<'):
        return False
    include = include or []
    exclude = exclude or []
    if include and not any(fnmatch.fnmatch(name, pattern) for pattern in include):
        return False
    if any(fnmatch.fnmatch(name, pattern) for pattern in exclude):
        return False
    arg_slots = co.co_argcount
    if co.co_flags & CO_VARARGS:
        arg_slots += 1
    if co.co_flags & CO_VARKEYWORDS:
        arg_slots += 1
    if arg_slots > len(co.co_varnames):
        return False
    return all(lazy_capsule_valid_arg_name(value)
               for value in co.co_varnames[:arg_slots])


def make_lazy_capsule_wrapper_code(real_code, manager_name, capsule_id):
    positional = list(real_code.co_varnames[:real_code.co_argcount])
    cursor = real_code.co_argcount
    vararg = None
    kwarg = None
    if real_code.co_flags & CO_VARARGS:
        vararg = real_code.co_varnames[cursor]
        cursor += 1
    if real_code.co_flags & CO_VARKEYWORDS:
        kwarg = real_code.co_varnames[cursor]

    params = list(positional)
    if vararg is not None:
        params.append('*' + vararg)
    if kwarg is not None:
        params.append('**' + kwarg)
    if not positional:
        forwarded = '()'
    elif len(positional) == 1:
        forwarded = '(%s,)' % positional[0]
    else:
        forwarded = '(%s)' % ', '.join(positional)
    if vararg is not None:
        forwarded = '(%s + %s)' % (forwarded, vararg)
    kwargs_expr = kwarg if kwarg is not None else '{}'
    wrapper_name = random_ident('lazy_wrapper')
    source = (
        'def %(wrapper)s(%(params)s):\n'
        '    return %(manager)s(%(capsule)d, %(args)s, %(kwargs)s)\n'
    ) % {
        'wrapper': wrapper_name,
        'params': ', '.join(params),
        'manager': manager_name,
        'capsule': int(capsule_id),
        'args': forwarded,
        'kwargs': kwargs_expr,
    }
    compiled = compile(source, '<lazy-capsule-wrapper>', 'exec', 0, True)
    wrapper = None
    for value in compiled.co_consts:
        if isinstance(value, types.CodeType):
            wrapper = value
            break
    if wrapper is None:
        raise ValueError('cannot compile lazy capsule wrapper for %s' % real_code.co_name)
    wrapper = rebuild_code(
        wrapper, filename=real_code.co_filename, name=real_code.co_name,
        firstlineno=real_code.co_firstlineno)
    if wrapper.co_argcount != real_code.co_argcount:
        raise ValueError('lazy capsule wrapper argcount mismatch for %s' % real_code.co_name)
    return wrapper


def build_lazy_function_capsules(root_code, manager_name, ratio=20,
                                 max_functions=8, include=None, exclude=None,
                                 mode='adaptive', retain_calls=4):
    ratio = max(0, min(100, int(ratio or 0)))
    max_functions = max(0, int(max_functions or 0))
    retain_calls = max(1, min(1024, int(retain_calls or 1)))
    include = list(include or [])
    exclude = list(exclude or [])
    entries = []
    used_ids = set()

    def allocate_id():
        while True:
            value = random.randint(0x10000, 0x7fffffff)
            if value not in used_ids:
                used_ids.add(value)
                return value

    def visit(code):
        changed = False
        consts = []
        for value in code.co_consts:
            if not isinstance(value, types.CodeType):
                consts.append(value)
                continue
            selected = False
            if (lazy_capsule_function_eligible(value, include, exclude) and
                    ratio > 0 and random.randint(1, 100) <= ratio and
                    (max_functions == 0 or len(entries) < max_functions)):
                capsule_id = allocate_id()
                resolved_mode = mode
                if resolved_mode == 'adaptive':
                    resolved_mode = 'count'
                wrapper = make_lazy_capsule_wrapper_code(
                    value, manager_name, capsule_id)
                entries.append({
                    'id': capsule_id,
                    'name': value.co_name,
                    'code': value,
                    'mode': resolved_mode,
                    'retain_calls': retain_calls,
                })
                consts.append(wrapper)
                selected = True
                changed = True
            if not selected:
                nested = visit(value)
                consts.append(nested)
                if nested is not value:
                    changed = True
        if changed:
            return rebuild_code(code, consts=tuple(consts))
        return code

    return visit(root_code), entries


def make_lnotab_noise(lnotab, count):
    count = max(0, min(64, int(count or 0)))
    if count <= 0:
        return lnotab
    noise = []
    for _ in range(count):
        noise.append(chr(random.randint(0, 2)))
        noise.append(chr(random.randint(0, 255)))
    return lnotab + ''.join(noise)


def make_structural_const_salts(count, depth, code_name, taunt_text=None):
    salts = []
    count = max(0, min(128, int(count or 0)))
    marker = taunt_text or 'mcp-shield'
    for idx in range(count):
        seed = random.randint(1, 2147483647)
        salts.append((
            random_ident('salt'),
            (seed ^ (idx + depth + 17)),
            random_bytes(random.randint(4, 18)),
            code_name if idx % 5 == 0 else marker,
        ))
    return salts


def make_name_chaff(base_names, count, taunt_text=None):
    count = max(0, min(256, int(count or 0)))
    names = []
    base = [name for name in base_names if isinstance(name, str) and name]
    api_words = ['GetEngineCompFactory', 'RegisterSystem', 'CreateComponent', 'ListenForEvent', 'BroadcastEvent']
    for idx in range(count):
        if base and idx % 3 == 0:
            src = random.choice(base)
            names.append('_ghost_%s_%08x' % (src.replace('.', '_')[:24], random.getrandbits(32)))
        elif idx % 3 == 1:
            names.append('_netease_%s_%08x' % (random.choice(api_words), random.getrandbits(32)))
        else:
            names.append(random_ident('nch'))
    return names


def slot_mirage_varnames(co, varnames, limit=8):
    """Rename non-argument fast-local slots without touching bytecode indexes.

    Python 2.7's fast-local instructions address ``co_varnames`` by numeric
    slot.  The spelling is only observable through reflection/tracebacks, so
    replacing cold locals with compiler-looking names (``.0``, ``.1`` ...)
    adds no dispatch or per-call work.  Argument and closure slots are kept
    intact because they are part of the public/function protocol.
    """
    if not varnames or not co:
        return varnames
    if len(varnames) <= max(0, int(co.co_argcount)):
        return varnames
    # Do not perturb code that explicitly exposes its local namespace.  This
    # keeps locals()/eval()/frame based compatibility paths deterministic.
    introspection_names = set(('locals', 'vars', 'eval', 'exec', 'dir',
                               'inspect', 'currentframe', 'getouterframes',
                               '_getframe', 'f_locals'))
    if introspection_names.intersection(set(co.co_names)):
        return varnames
    # Generator/comprehension slots already have compiler-owned .0 names.
    # Renaming those functions would make the result less stable rather than
    # more misleading.
    if co.co_flags & 0x20:
        return varnames
    arg_slots = int(co.co_argcount)
    if co.co_flags & CO_VARARGS:
        arg_slots += 1
    if co.co_flags & CO_VARKEYWORDS:
        arg_slots += 1
    arg_slots = min(len(varnames), arg_slots)
    protected = set(getattr(co, 'co_cellvars', ()))
    protected.update(getattr(co, 'co_freevars', ()))
    used = set(varnames)
    out = list(varnames)
    budget = max(0, min(64, int(limit or 0)))
    serial = 0
    changed = 0
    for index in range(arg_slots, len(out)):
        if changed >= budget:
            break
        if out[index] in protected or out[index].startswith('.'):
            continue
        candidate = '.%d' % serial
        serial += 1
        while candidate in used:
            candidate = '.%d' % serial
            serial += 1
        used.discard(out[index])
        used.add(candidate)
        out[index] = candidate
        changed += 1
    return tuple(out)


def obfuscate_code_object(co, const_noise, tail_noise, depth=0, filename_mode='keep', bad_bytecode=0, bad_units=3, nop_bloat=0, stop_bloat=0, arg_poison=0, exception_poison=0, call_poison=0, metadata_poison=False, adaptive_strength=False, adaptive_max_scale=4, taunt_text=None, taunt_inner_consts=0, split_gates=False, split_interval=18, split_bad_units=2, split_nop_bloat=2, fake_code_objects=0, ghost_names=0, split_adaptive=False, loop_shadow_gates=False, const_swamp=0, real_block_reorder=False, real_block_reorder_limit=2, safe_dead_blocks=False, safe_dead_interval=20, safe_dead_width=4, safe_dead_limit=6, oparg_poison=False, opaque_predicates=False, opaque_interval=28, opaque_width=3, opaque_limit=4, fake_code_nop_bloat=0, fake_code_stop_bloat=0, root_const_swamp=0, metadata_binary=False, metadata_name_poison=False, index_pool_shuffle=False, index_pool_mirrors=0, const_ref_chains=0, bytecode_stack_pad=0, bytecode_lnotab_noise=0, bytecode_const_salts=0, bytecode_name_chaff=0, bytecode_entry_noise=0, bytecode_exception_decoys=0, bytecode_stack_noise=False, bytecode_stack_noise_interval=18, bytecode_stack_noise_limit=6, bytecode_jump_inversion=False, bytecode_jump_inversion_limit=4, bytecode_jump_trampolines=False, bytecode_jump_trampoline_limit=4, bytecode_strategy_variation=False, bytecode_strategy_seed=0, bytecode_delayed_const_access=False, bytecode_delayed_const_limit=3, bytecode_extended_arg_prefix=False, bytecode_extended_arg_interval=11, bytecode_extended_arg_limit=6, slot_mirage=False, slot_mirage_limit=8, bytecode_cfg_flow=False, bytecode_cfg_flow_ratio=35, bytecode_cfg_flow_max_edges=6, bytecode_cfg_block_seeds=False, bytecode_cfg_block_seed_ratio=35, bytecode_cfg_block_seed_max_blocks=64, bytecode_cfg_block_shuffle=False, bytecode_cfg_block_shuffle_ratio=35, bytecode_cfg_block_shuffle_max_blocks=192, bytecode_decoy_islands=False, bytecode_decoy_island_ratio=20, bytecode_decoy_island_limit=2, bytecode_decoy_island_width=4, bytecode_decoy_island_growth=15):
    experimental_allowed = depth > 0 and is_function_code(co)
    consts = []
    for const in co.co_consts:
        if isinstance(const, types.CodeType):
            const = obfuscate_code_object(const, max(0, const_noise - 1 + (depth % 2)), tail_noise, depth + 1, filename_mode, bad_bytecode, bad_units, nop_bloat, stop_bloat, arg_poison, exception_poison, call_poison, metadata_poison, adaptive_strength, adaptive_max_scale, taunt_text, taunt_inner_consts, split_gates, split_interval, split_bad_units, split_nop_bloat, fake_code_objects, ghost_names, split_adaptive, loop_shadow_gates, const_swamp, real_block_reorder, real_block_reorder_limit, safe_dead_blocks, safe_dead_interval, safe_dead_width, safe_dead_limit, oparg_poison, opaque_predicates, opaque_interval, opaque_width, opaque_limit, fake_code_nop_bloat, fake_code_stop_bloat, root_const_swamp, metadata_binary, metadata_name_poison, index_pool_shuffle, index_pool_mirrors, const_ref_chains, bytecode_stack_pad, bytecode_lnotab_noise, bytecode_const_salts, bytecode_name_chaff, bytecode_entry_noise, bytecode_exception_decoys, bytecode_stack_noise, bytecode_stack_noise_interval, bytecode_stack_noise_limit, bytecode_jump_inversion, bytecode_jump_inversion_limit, bytecode_jump_trampolines, bytecode_jump_trampoline_limit, bytecode_strategy_variation, bytecode_strategy_seed, bytecode_delayed_const_access, bytecode_delayed_const_limit, bytecode_extended_arg_prefix, bytecode_extended_arg_interval, bytecode_extended_arg_limit, slot_mirage, slot_mirage_limit, bytecode_cfg_flow, bytecode_cfg_flow_ratio, bytecode_cfg_flow_max_edges, bytecode_cfg_block_seeds, bytecode_cfg_block_seed_ratio, bytecode_cfg_block_seed_max_blocks, bytecode_cfg_block_shuffle, bytecode_cfg_block_shuffle_ratio, bytecode_cfg_block_shuffle_max_blocks, bytecode_decoy_islands, bytecode_decoy_island_ratio, bytecode_decoy_island_limit, bytecode_decoy_island_width, bytecode_decoy_island_growth)
        consts.append(const)
    scale = 1
    if adaptive_strength:
        scale = 1 + min(max(0, adaptive_max_scale - 1), (len(co.co_code) // 4096) + min(depth, 2))
    density = max(0, (const_noise * scale) + (depth % 4) + min(depth, 3))
    for idx in range(density):
        consts.append(make_fake_const(depth, idx, taunt_text, taunt_inner_consts))
    fake_count = max(0, fake_code_objects)
    if adaptive_strength:
        fake_count *= scale
    for idx in range(fake_count):
        consts.append(make_fake_code_object(depth, idx, taunt_text, 0, fake_code_nop_bloat, fake_code_stop_bloat))
    swamp_count = const_swamp * (scale if adaptive_strength else 1)
    if depth == 0:
        swamp_count += max(0, root_const_swamp)
    consts.extend(make_const_swamp(swamp_count, taunt_text))
    ref_count = const_ref_chains * (scale if adaptive_strength else 1)
    if depth > 2:
        ref_count = max(0, ref_count // 2)
    consts.extend(make_const_reference_chain(ref_count, taunt_text))
    consts.extend(make_structural_const_salts(bytecode_const_salts * (scale if adaptive_strength else 1), depth, co.co_name, taunt_text))
    true_const_index = len(consts)
    consts.append(True)
    varnames = list(co.co_varnames)
    code_bytes = co.co_code
    dispatch_changed = 0
    if bytecode_cfg_flow and experimental_allowed:
        code_bytes, consts, varnames, dispatch_changed = apply_state_dispatcher(
            co, co.co_code, consts, varnames,
            bytecode_cfg_flow_ratio,
            max(8, min(128, bytecode_cfg_flow_max_edges * 8)))
    junk_local_index = None
    nlocals = len(varnames) if dispatch_changed else co.co_nlocals
    names = list(co.co_names)
    names.extend(make_ghost_names(ghost_names * (scale if adaptive_strength else 1), taunt_text))
    names.extend(make_name_chaff(names, bytecode_name_chaff * (scale if adaptive_strength else 1), taunt_text))
    filename = co.co_filename
    if filename_mode == 'mem':
        filename = '<mem>'
    elif filename_mode == 'module':
        filename = '<%s>' % os.path.basename(co.co_filename).replace(' ', '_')
    name = co.co_name
    firstlineno = co.co_firstlineno
    if metadata_poison:
        filename = random_binary_metadata_label('file') if metadata_binary else random_metadata_label('file')
        firstlineno = -1
        if metadata_name_poison and can_poison_real_code_name(co, name):
            name = random_binary_metadata_label('name') if metadata_binary else random_metadata_label('name')
    local_stack_noise = bool(bytecode_stack_noise)
    local_stack_interval = max(4, int(bytecode_stack_noise_interval or 18))
    local_stack_limit = max(0, int(bytecode_stack_noise_limit or 0))
    local_jump_inversion = bool(bytecode_jump_inversion)
    local_inversion_limit = max(0, int(bytecode_jump_inversion_limit or 0))
    local_jump_trampolines = bool(bytecode_jump_trampolines)
    local_trampoline_limit = max(0, int(bytecode_jump_trampoline_limit or 0))
    local_delayed_const_access = bool(bytecode_delayed_const_access)
    local_delayed_const_limit = max(0, int(bytecode_delayed_const_limit or 0))
    # Exception blocks have block-stack edges in addition to ordinary jump
    # targets. Expanding/inverting their jumps was the remaining source of
    # intermittent MCS "unknown opcode" failures in event callbacks.
    if bytecode_has_exception_control_flow(co.co_code):
        local_jump_inversion = False
        local_inversion_limit = 0
        local_jump_trampolines = False
        local_trampoline_limit = 0
    if bytecode_strategy_variation and experimental_allowed:
        variant = bytecode_strategy_variant(co, depth, bytecode_strategy_seed, 4)
        if variant == 0:
            local_stack_noise = False
            local_trampoline_limit = max(1, local_trampoline_limit // 2) if local_jump_trampolines else 0
            local_delayed_const_limit = max(1, local_delayed_const_limit // 2) if local_delayed_const_access else 0
        elif variant == 1:
            local_jump_inversion = False
            local_stack_limit += 1 if local_stack_noise else 0
            local_delayed_const_limit += 1 if local_delayed_const_access else 0
        elif variant == 2:
            local_stack_interval += 6
            local_inversion_limit = max(1, local_inversion_limit // 2) if local_jump_inversion else 0
        else:
            bonus = 1 + min(depth, 2)
            local_stack_limit += bonus if local_stack_noise else 0
            local_inversion_limit += bonus if local_jump_inversion else 0
            local_trampoline_limit += bonus if local_jump_trampolines else 0
            local_delayed_const_limit += bonus if local_delayed_const_access else 0
    delayed_const_changed = 0
    code_bytes = append_tail_noise(co, tail_noise * scale, bad_bytecode * scale, bad_units, nop_bloat * scale, stop_bloat * scale, arg_poison * scale, exception_poison * scale, call_poison * scale, code_bytes)
    if real_block_reorder and experimental_allowed:
        code_bytes = bytecode_reorder_linear_blocks(code_bytes, 3, 8, real_block_reorder_limit)
    if safe_dead_blocks and experimental_allowed:
        code_bytes = bytecode_safe_dead_blocks(code_bytes, safe_dead_interval, safe_dead_width, safe_dead_limit, true_const_index, junk_local_index, oparg_poison)
    if opaque_predicates and experimental_allowed and can_apply_bytecode_opaque_predicates(co, code_bytes):
        predicate_local_index = 0 if co.co_argcount > 0 else None
        code_bytes = bytecode_opaque_predicates(
            code_bytes, opaque_interval, opaque_width, opaque_limit,
            true_const_index, junk_local_index, predicate_local_index)
    if split_gates:
        code_bytes = bytecode_split_gates(code_bytes, split_interval, split_bad_units, split_nop_bloat, taunt_text, split_adaptive, loop_shadow_gates and experimental_allowed)
    if local_jump_trampolines and experimental_allowed:
        code_bytes = bytecode_jump_trampoline_chains(code_bytes, local_trampoline_limit * (scale if adaptive_strength else 1), len(co.co_code))
    if local_jump_inversion and experimental_allowed:
        code_bytes = bytecode_conditional_jump_inversion(code_bytes, local_inversion_limit * (scale if adaptive_strength else 1))
    if local_delayed_const_access and experimental_allowed:
        code_bytes, consts, delayed_const_changed = bytecode_delayed_constant_access(code_bytes, consts, local_delayed_const_limit * (scale if adaptive_strength else 1), len(co.co_code))
    if local_stack_noise and experimental_allowed:
        noise_interval = max(6, local_stack_interval // (scale if adaptive_strength else 1))
        code_bytes = bytecode_stack_equivalent_noise(code_bytes, noise_interval, local_stack_limit * (scale if adaptive_strength else 1), true_const_index)
    if bytecode_exception_decoys and experimental_allowed:
        code_bytes = prepend_exception_decoys(code_bytes, bytecode_exception_decoys * (scale if adaptive_strength else 1), true_const_index)
    if bytecode_entry_noise:
        code_bytes = prepend_legal_entry_noise(code_bytes, bytecode_entry_noise * (scale if adaptive_strength else 1), true_const_index, junk_local_index)
    if bytecode_decoy_islands and experimental_allowed:
        code_bytes, _decoy_island_count = apply_decoy_islands(
            co, code_bytes, true_const_index,
            bytecode_decoy_island_ratio, bytecode_decoy_island_limit,
            bytecode_decoy_island_width, bytecode_decoy_island_growth,
            bytecode_strategy_seed)
    if index_pool_mirrors:
        consts, names = make_index_pool_mirrors(consts, names, index_pool_mirrors * (scale if adaptive_strength else 1))
    if index_pool_shuffle:
        consts, names, varnames, code_bytes = apply_index_pool_shuffle(co, code_bytes, consts, names, varnames)
    if bytecode_extended_arg_prefix and experimental_allowed:
        code_bytes = bytecode_extended_arg_prefixes(
            code_bytes, bytecode_extended_arg_interval,
            bytecode_extended_arg_limit * (scale if adaptive_strength else 1))
    if slot_mirage:
        varnames = slot_mirage_varnames(co, varnames, slot_mirage_limit)
    if bytecode_cfg_block_seeds and experimental_allowed:
        code_bytes, consts, varnames, cfg_changed = apply_block_seed_flow(
            co, code_bytes, consts, varnames,
            bytecode_cfg_block_seed_ratio,
            bytecode_cfg_block_seed_max_blocks)
        if cfg_changed:
            nlocals = len(varnames)
    elif bytecode_cfg_flow and experimental_allowed:
        code_bytes, consts, varnames, cfg_changed = apply_conditional_edge_proxies(
            co, code_bytes, consts, varnames,
            bytecode_cfg_flow_ratio, bytecode_cfg_flow_max_edges)
        if cfg_changed:
            nlocals = len(varnames)
    if bytecode_cfg_block_shuffle and experimental_allowed:
        code_bytes, _cfg_moved = apply_basic_block_shuffle(
            co, code_bytes, bytecode_cfg_block_shuffle_ratio,
            bytecode_cfg_block_shuffle_max_blocks)
    stacksize = max(co.co_stacksize, 2) + (1 if delayed_const_changed else 0) + max(0, min(4096, int(bytecode_stack_pad or 0))) + (min(depth, 8) if bytecode_stack_pad else 0)
    lnotab = make_lnotab_noise(co.co_lnotab, bytecode_lnotab_noise * (scale if adaptive_strength else 1))
    return rebuild_code(co, consts, code_bytes, filename, name, firstlineno, names, varnames, nlocals, stacksize, lnotab)


def obfuscate_code_with_options(code, opts, depth=0):
    return obfuscate_code_object(
        code, opts.const_noise, opts.tail_noise, depth, opts.filename_mode,
        opts.dead_bad_bytecode, opts.dead_bad_units, opts.dead_nop_bloat,
        opts.dead_stop_bloat, opts.dead_arg_poison,
        opts.dead_exception_poison, opts.dead_call_poison,
        opts.metadata_poison, opts.adaptive_strength,
        opts.adaptive_max_scale, opts.taunt_text, opts.taunt_inner_consts,
        opts.bytecode_split_gates, opts.bytecode_split_interval,
        opts.bytecode_split_bad_units, opts.bytecode_split_nop_bloat,
        opts.fake_code_objects, opts.ghost_names, opts.split_adaptive,
        opts.loop_shadow_gates, opts.const_swamp, opts.real_block_reorder,
        opts.real_block_reorder_limit, opts.safe_dead_blocks,
        opts.safe_dead_interval, opts.safe_dead_width, opts.safe_dead_limit,
        opts.oparg_poison, opts.bytecode_opaque_predicates,
        opts.bytecode_opaque_interval, opts.bytecode_opaque_width,
        opts.bytecode_opaque_limit, opts.fake_code_nop_bloat,
        opts.fake_code_stop_bloat, opts.root_const_swamp,
        opts.metadata_binary, opts.metadata_name_poison,
        opts.index_pool_shuffle, opts.index_pool_mirrors,
        opts.const_ref_chains, opts.bytecode_stack_pad,
        opts.bytecode_lnotab_noise, opts.bytecode_const_salts,
        opts.bytecode_name_chaff, opts.bytecode_entry_noise,
        opts.bytecode_exception_decoys, opts.bytecode_stack_noise,
        opts.bytecode_stack_noise_interval, opts.bytecode_stack_noise_limit,
        opts.bytecode_jump_inversion, opts.bytecode_jump_inversion_limit,
        opts.bytecode_jump_trampolines,
        opts.bytecode_jump_trampoline_limit,
        opts.bytecode_strategy_variation, opts.bytecode_strategy_seed,
        opts.bytecode_delayed_const_access, opts.bytecode_delayed_const_limit,
        opts.bytecode_extended_arg_prefix,
        opts.bytecode_extended_arg_interval,
        opts.bytecode_extended_arg_limit, opts.slot_mirage,
        opts.slot_mirage_limit, opts.bytecode_cfg_flow,
        opts.bytecode_cfg_flow_ratio, opts.bytecode_cfg_flow_max_edges,
        opts.bytecode_cfg_block_seeds, opts.bytecode_cfg_block_seed_ratio,
        opts.bytecode_cfg_block_seed_max_blocks,
        opts.bytecode_cfg_block_shuffle,
        opts.bytecode_cfg_block_shuffle_ratio,
        opts.bytecode_cfg_block_shuffle_max_blocks,
        opts.bytecode_decoy_islands, opts.bytecode_decoy_island_ratio,
        opts.bytecode_decoy_island_limit, opts.bytecode_decoy_island_width,
        opts.bytecode_decoy_island_growth)
