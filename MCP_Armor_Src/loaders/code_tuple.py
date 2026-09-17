# -*- coding: utf-8 -*-
"""Code Tuple packing, arenas and reconstruction source."""


import pickle
import marshal
from MCP_Armor_Src.core import py27_opcode as opcode
import random
import sys
import types

from MCP_Armor_Src.bytecode_obf.decoys import (
    make_fake_const,
)

from MCP_Armor_Src.bytecode_obf.instructions import (
    read_oparg,
)

from MCP_Armor_Src.core.constants import (
    CODE_BLOCK_RELOC_MAGIC,
    CODE_BLOCK_RELOC_ROW_MAGIC,
    CODE_BYTES_SPLIT_MAGIC,
    CODE_CONST_ARENA_REF_MAGIC,
    CODE_CONST_ARENA_ROW_MAGIC,
    CODE_CONST_PROVIDER_MAGIC,
    CODE_FIELD_ARENA_CONTEXT_MAGIC,
    CODE_FIELD_DESCRIPTOR_MAGIC,
    CODE_FIELD_OBJECT_MAGIC,
    CODE_FIELD_PROVIDER_MAGIC,
    CODE_GLOBAL_ARENA_MAGIC,
    CODE_GLOBAL_ARENA_NODE_MAGIC,
    CODE_GLOBAL_ARENA_REF_MAGIC,
    CODE_GLOBAL_ARENA_ROW_MAGIC,
    CODE_REF_MASK_MAGIC,
    CODE_REF_TABLE_MAGIC,
    CODE_TUPLE_FRAG_MAGIC,
    CODE_TUPLE_MAGIC,
    CODE_TUPLE_PROVIDER_GRAPH_MAGIC,
    CODE_TUPLE_PROVIDER_MAGIC,
    CODE_TUPLE_SHUFFLE_MAGIC,
    CODE_UNIT_ARENA_MAGIC,
    CODE_UNIT_ARENA_ROW_MAGIC,
    HAVE_ARGUMENT,
    LOAD_CONST,
)

from MCP_Armor_Src.utils.encoding import (
    byte_value,
    debug_print_code,
    random_bytes,
    random_ident,
)


def make_fake_code_bytes_chunk(size_hint):
    size_hint = max(1, min(96, size_hint))
    size = random.randint(1, size_hint)
    return bytes(random.randint(0, 255) for _ in range(size))


def split_code_bytes_for_payload(code_bytes, enabled=False, min_size=48, max_chunks=6, fake_chunks=0):
    if not enabled or len(code_bytes) < max(1, min_size):
        return code_bytes
    max_chunks = max(2, min(32, max_chunks))
    fake_chunks = max(0, min(32, fake_chunks))
    chunk_count = min(max_chunks, max(2, len(code_bytes) // max(1, min_size)))
    if chunk_count < 2:
        return code_bytes
    cuts = sorted(random.sample(list(range(1, len(code_bytes))), chunk_count - 1))
    parts = []
    start = 0
    for cut in cuts + [len(code_bytes)]:
        parts.append(code_bytes[start:cut])
        start = cut
    real_count = len(parts)
    for _ in range(fake_chunks):
        parts.append(make_fake_code_bytes_chunk(max(4, len(code_bytes) // max(1, real_count))))
    shuffled = list(range(len(parts)))
    random.shuffle(shuffled)
    if shuffled == list(range(len(parts))) and len(shuffled) > 1:
        shuffled = shuffled[1:] + shuffled[:1]
    shuffled_parts = [parts[index] for index in shuffled]
    position_by_original = {}
    for new_pos, original_index in enumerate(shuffled):
        if original_index < real_count:
            position_by_original[original_index] = new_pos
    seed = random.randint(1, 255)
    encoded_order = tuple((position_by_original[index] ^ seed) for index in range(real_count))
    return (CODE_BYTES_SPLIT_MAGIC, seed, encoded_order, tuple(shuffled_parts))


def _xor_bytes(data, key):
    key = max(1, int(key) & 255)
    values = [byte_value(ch) ^ ((key + index) & 255)
              for index, ch in enumerate(data)]
    # ``bytes(generator)`` is a textual generator representation on Python 2
    # rather than a byte container.  Build the payload explicitly so reference
    # rows remain valid for both the Python 2 target and Python 3 controller.
    if sys.version_info[0] < 3:
        return ''.join(chr(value) for value in values)
    return bytes(values)


def widen_code_ref_row(row, enabled=False):
    if not enabled:
        return row
    junk = []
    for _ in range(random.randint(1, 4)):
        kind = random.randint(0, 2)
        if kind == 0:
            junk.append(random.randint(-999999, 999999))
        elif kind == 1:
            junk.append(random_bytes(random.randint(3, 18)))
        else:
            junk.append((random.randint(1, 255), random_ident('crw')))
    return tuple(list(row) + junk)


def make_code_ref_decoy_rows(count, start_id, code_tuple_field_shuffle=False, code_ref_wide_rows=False, code_tuple_fragments=False, code_tuple_fragment_providers=False, code_tuple_provider_graph=False, code_tuple_provider_decoys=0, code_field_descriptors=False, code_provider_context_bind=False):
    rows = []
    count = max(0, min(64, int(count or 0)))
    for index in range(count):
        func_name = random_ident('cdr')
        arg_name = random_ident('cda')
        key_name = random_ident('cdk')
        source = (
            'def %s(%s=None):\n'
            '    %s = %r\n'
            '    if %s == -1:\n'
            '        return %s\n'
            '    return %s\n'
        ) % (func_name, arg_name, key_name,
             random_bytes(random.randint(8, 24)), arg_name, key_name,
             arg_name)
        fake_code = compile(source, '<ref-decoy>', 'exec', 0, True)
        fake_tuple = pack_code_tuple(fake_code, False, 48, 6, 0, 0, None, code_tuple_field_shuffle, False, False, code_tuple_fragments, code_tuple_fragment_providers, code_tuple_provider_graph, code_tuple_provider_decoys, code_field_descriptors, code_provider_context_bind)
        ref_id = start_id + index
        ref_key = random.randint(1, 255)
        rows.append(widen_code_ref_row((ref_id, ref_key, _xor_bytes(pickle.dumps(fake_tuple, 2), ref_key)), code_ref_wide_rows))
    return rows


def make_provider_record(row, graph=False):
    seed = random.randint(1, 255)
    key = random.randint(1, 2147483647)
    if not graph:
        return (CODE_TUPLE_PROVIDER_MAGIC, key, seed, key ^ seed, row)
    left = random.randint(1, 255)
    right = seed ^ left
    left_mask = random.randint(1, 255)
    right_mask = random.randint(1, 255)
    left_node = (left_mask, left ^ left_mask, random_ident('cpg'))
    right_node = (right_mask, right ^ right_mask, random_ident('cpg'))
    return (CODE_TUPLE_PROVIDER_GRAPH_MAGIC, key, key ^ seed, left_node, right_node, row, random_bytes(random.randint(3, 10)))


def make_fake_provider_record(graph=False):
    seed = random.randint(1, 255)
    key = random.randint(1, 2147483647)
    fake_row = (seed, ((random.randint(64, 192) ^ seed, random_bytes(random.randint(3, 10))),), random_ident('cpf'))
    if not graph:
        return (CODE_TUPLE_PROVIDER_MAGIC, key, seed, key ^ seed, fake_row)
    left = random.randint(1, 255)
    right = random.randint(1, 255)
    left_mask = random.randint(1, 255)
    right_mask = random.randint(1, 255)
    left_node = (left_mask, left ^ left_mask, random_ident('cpg'))
    right_node = (right_mask, right ^ right_mask, random_ident('cpg'))
    return (CODE_TUPLE_PROVIDER_GRAPH_MAGIC, key, key ^ seed, left_node, right_node, fake_row, random_ident('fake'))


def providerize_fragment_rows(rows, enabled=False, graph=False, decoys=0):
    if not enabled:
        return tuple(rows)
    records = []
    for row in rows:
        records.append(make_provider_record(row, graph))
    for _ in range(random.randint(1, 3) + max(0, min(32, int(decoys or 0)))):
        records.append(make_fake_provider_record(graph))
    random.shuffle(records)
    return tuple(records)


def fragment_code_tuple_fields(fields, enabled=False, providers=False, provider_graph=False, provider_decoys=0):
    if not enabled:
        return fields
    indexes = list(range(len(fields)))
    random.shuffle(indexes)
    group_count = random.randint(3, min(7, len(fields)))
    groups = [[] for _ in range(group_count)]
    for pos, index in enumerate(indexes):
        groups[pos % group_count].append(index)
    rows = []
    for group in groups:
        group.sort()
        seed = random.randint(1, 255)
        row_values = []
        for index in group:
            row_values.append((index ^ seed, fields[index]))
        row = [seed, tuple(row_values)]
        for _ in range(random.randint(0, 2)):
            row.append(random_bytes(random.randint(3, 12)))
        rows.append(tuple(row))
    random.shuffle(rows)
    return (CODE_TUPLE_FRAG_MAGIC, len(fields), providerize_fragment_rows(rows, providers, provider_graph, provider_decoys))


def code_field_value_size(value):
    try:
        return len(value)
    except Exception:
        return 1


def code_field_context_tag(build_id, code_id, parent_id, field_id, salt,
                           value_size, mask):
    return (
        (int(build_id) * 0x01F123BB) ^
        (int(code_id) * 0x0059D2F1) ^
        ((int(parent_id) + 2) * 0x00045D9F) ^
        (int(field_id) * 0x001B8735) ^ int(salt) ^
        int(value_size) ^ int(mask)
    ) & 0x7fffffff


def make_code_field_descriptor(value, build_id, code_id, parent_id, field_id,
                               context_bind=False):
    salt = random.randint(1, 2147483647)
    value_size = code_field_value_size(value)
    tag_mask = salt ^ 0x035A71D9
    provider = (
        CODE_FIELD_PROVIDER_MAGIC,
        salt,
        value_size ^ salt,
        value,
        code_field_context_tag(build_id, code_id, parent_id, field_id, salt,
                               value_size, tag_mask),
    )
    descriptor_check = (
        field_id ^ salt ^ len(provider) ^ 0x02D35A71
    ) & 0x7fffffff
    return (
        CODE_FIELD_DESCRIPTOR_MAGIC,
        field_id ^ (salt & 255),
        provider,
        descriptor_check,
    )


def wrap_code_field_object(packed_fields, build_id, code_id, parent_id,
                           context_bind=False):
    mask = random.randint(1, 2147483647)
    packed_size = code_field_value_size(packed_fields)
    bind_flag = 1 if context_bind else 0
    check = (
        (build_id * 0x003D2A9D) ^ (code_id * 0x000F1433) ^
        ((parent_id + 2) * 0x0012AD61) ^ packed_size ^ mask ^
        (bind_flag * 0x00051ED7)
    ) & 0x7fffffff
    return (
        CODE_FIELD_OBJECT_MAGIC,
        mask,
        build_id ^ mask,
        code_id ^ mask,
        parent_id ^ mask,
        bind_flag ^ (mask & 1),
        packed_fields,
        check,
        random_bytes(random.randint(4, 14)),
    )


def pack_code_tuple(code, code_bytes_split=False, code_bytes_split_min=48, code_bytes_split_max_chunks=6, code_bytes_fake_chunks=0, depth=0, code_ref_table=None, code_tuple_field_shuffle=False, code_ref_wide_rows=False, code_ref_mask_markers=False, code_tuple_fragments=False, code_tuple_fragment_providers=False, code_tuple_provider_graph=False, code_tuple_provider_decoys=0, code_field_descriptors=False, code_provider_context_bind=False, field_context=None, parent_id=-1):
    if code_field_descriptors:
        if field_context is None:
            field_context = {
                'build_id': random.randint(1, 2147483647),
                'next_code_id': 0,
            }
        build_id = field_context['build_id']
        code_id = field_context['next_code_id']
        field_context['next_code_id'] += 1
    else:
        build_id = 0
        code_id = -1
    consts = []
    depth_max_chunks = max(2, code_bytes_split_max_chunks - min(depth, max(0, code_bytes_split_max_chunks - 2)))
    depth_fake_chunks = max(0, code_bytes_fake_chunks - min(depth, code_bytes_fake_chunks))
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            packed_const = pack_code_tuple(const, code_bytes_split, code_bytes_split_min, code_bytes_split_max_chunks, code_bytes_fake_chunks, depth + 1, code_ref_table, code_tuple_field_shuffle, code_ref_wide_rows, code_ref_mask_markers, code_tuple_fragments, code_tuple_fragment_providers, code_tuple_provider_graph, code_tuple_provider_decoys, code_field_descriptors, code_provider_context_bind, field_context, code_id)
            if code_ref_table is not None:
                ref_id = len(code_ref_table) + 1
                ref_key = random.randint(1, 255)
                ref_blob = pickle.dumps(packed_const, 2)
                code_ref_table.append(widen_code_ref_row((ref_id, ref_key, _xor_bytes(ref_blob, ref_key)), code_ref_wide_rows))
                if code_ref_mask_markers:
                    ref_mask = random.randint(1, 2147483647)
                    const = (CODE_REF_MASK_MAGIC, ref_mask, ref_id ^ ref_mask, ref_key ^ (ref_mask & 255))
                else:
                    const = (CODE_REF_TABLE_MAGIC, ref_id, ref_key)
            else:
                const = CODE_TUPLE_MAGIC + pickle.dumps(packed_const, 2)
        consts.append(const)
    code_bytes = split_code_bytes_for_payload(code.co_code, code_bytes_split, code_bytes_split_min, depth_max_chunks, depth_fake_chunks)
    fields = (
        code.co_argcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code_bytes,
        tuple(consts),
        code.co_names,
        code.co_varnames,
        code.co_filename,
        code.co_name,
        code.co_firstlineno,
        code.co_lnotab,
        code.co_freevars,
        code.co_cellvars,
    )
    if code_field_descriptors:
        fields = tuple(
            make_code_field_descriptor(
                value, build_id, code_id, parent_id, field_id,
                code_provider_context_bind)
            for field_id, value in enumerate(fields)
        )
    if code_tuple_field_shuffle:
        order = list(range(len(fields)))
        random.shuffle(order)
        if order == list(range(len(fields))) and len(order) > 1:
            order = order[1:] + order[:1]
        packed_fields = (CODE_TUPLE_SHUFFLE_MAGIC, tuple(order), fragment_code_tuple_fields(tuple(fields[index] for index in order), code_tuple_fragments, code_tuple_fragment_providers, code_tuple_provider_graph, code_tuple_provider_decoys))
    else:
        packed_fields = fragment_code_tuple_fields(fields, code_tuple_fragments, code_tuple_fragment_providers, code_tuple_provider_graph, code_tuple_provider_decoys)
    if code_field_descriptors:
        return wrap_code_field_object(
            packed_fields, build_id, code_id, parent_id,
            code_provider_context_bind)
    return packed_fields


def collect_code_object_graph(root):
    nodes = []
    node_ids = {}
    depths = {}
    parents = {}

    def walk(code, depth, parent_id):
        marker = id(code)
        if marker in node_ids:
            return node_ids[marker]
        code_id = len(nodes)
        node_ids[marker] = code_id
        depths[code_id] = depth
        parents[code_id] = parent_id
        nodes.append(code)
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                walk(const, depth + 1, code_id)
        return code_id

    root_id = walk(root, 0, -1)
    return nodes, node_ids, depths, parents, root_id


def make_global_arena_templates():
    return (
        (0, 0, 2, 64, '', (None,), (), (),
         random_ident('af'), random_ident('an'), 1, '', (), ()),
        (0, 0, 4, 67, '', (None,), (), (),
         random_ident('af'), random_ident('an'), random.randint(2, 80), '', (), ()),
        (1, 1, 3, 67, '', (None,), (), (random_ident('av'),),
         random_ident('af'), random_ident('an'), random.randint(2, 80), '', (), ()),
    )


def choose_global_arena_base(fields, templates, prior_fields, template_delta):
    if not template_delta:
        return -1, templates[0]
    candidates = [(-idx - 1, value) for idx, value in enumerate(templates)]
    start = max(0, len(prior_fields) - 8)
    candidates.extend((idx, prior_fields[idx]) for idx in range(start, len(prior_fields)))
    scored = []
    best = -1
    for base_id, base_fields in candidates:
        score = sum(1 for idx in range(14) if fields[idx] == base_fields[idx])
        if score > best:
            best = score
            scored = [(base_id, base_fields)]
        elif score == best:
            scored.append((base_id, base_fields))
    return random.choice(scored)


def resolve_stored_opcode_map(stored_to_std, code_id):
    if not stored_to_std:
        return {}
    for value in list(stored_to_std.values()):
        if isinstance(value, dict):
            return stored_to_std.get(code_id, {})
        break
    return stored_to_std


def split_stored_code_units(code_bytes, stored_to_std):
    units = []
    pos = 0
    size = len(code_bytes)
    while pos < size:
        raw_op = byte_value(code_bytes[pos])
        std_op = stored_to_std.get(raw_op, raw_op)
        # NetEase remaps opcode numbers across HAVE_ARGUMENT. Instruction
        # width belongs to the normalized/std opcode, not the stored byte.
        length = 3 if std_op >= HAVE_ARGUMENT else 1
        if pos + length > size:
            return None
        arg = read_oparg(code_bytes, pos) if length == 3 else None
        units.append((pos, length, raw_op, std_op, arg))
        pos += length
    return units


def pack_code_unit_arena(code_bytes, stored_to_std=None, decoys=0,
                         operand_graph=False):
    stored_to_std = stored_to_std or {}
    units = split_stored_code_units(code_bytes, stored_to_std)
    if not units or len(units) > 65535:
        return code_bytes
    seed = random.randint(1, 255)
    rows = []
    for index, (pos, length, raw_op, _std_op, arg) in enumerate(units):
        mask = random.randint(1, 2147483647)
        unit = code_bytes[pos:pos + length]
        if operand_graph:
            graph_seed = random.randint(1, 255)
            if length == 3:
                low = arg & 255
                high = (arg >> 8) & 255
                payload = (
                    1 ^ graph_seed, raw_op ^ graph_seed, graph_seed,
                    low ^ graph_seed,
                    high ^ ((graph_seed + index) & 255),
                    (raw_op + low + high + index) & 255,
                )
            else:
                payload = (
                    0 ^ graph_seed, raw_op ^ graph_seed, graph_seed,
                    (raw_op + index) & 255,
                )
        else:
            payload = unit
        rows.append((
            CODE_UNIT_ARENA_ROW_MAGIC, mask, index ^ mask, payload,
            length ^ (mask & 255), random_bytes(random.randint(2, 9)),
        ))
    decoys = max(0, min(256, int(decoys or 0)))
    for offset in range(decoys):
        fake_id = len(units) + offset + 1
        mask = random.randint(1, 2147483647)
        if operand_graph and offset % 2:
            graph_seed = random.randint(1, 255)
            payload = (random.randint(0, 3) ^ graph_seed,
                       random.randint(0, 255) ^ graph_seed, graph_seed,
                       random.randint(0, 255))
            fake_len = random.choice([1, 3])
        else:
            fake_len = random.choice([1, 3])
            payload = random_bytes(fake_len)
        rows.append((
            CODE_UNIT_ARENA_ROW_MAGIC, mask, fake_id ^ mask, payload,
            fake_len ^ (mask & 255), random_ident('unit'),
        ))
    random.shuffle(rows)
    order = tuple(index ^ seed for index in range(len(units)))
    return (
        CODE_UNIT_ARENA_MAGIC, seed, order, tuple(rows),
        len(code_bytes) ^ seed, len(units) ^ seed,
        (1 if operand_graph else 0) ^ seed,
        random_bytes(random.randint(4, 13)),
    )


def pack_code_block_relocation(code_bytes, stored_to_std=None, decoys=0,
                               code_unit_arena=False,
                               code_unit_arena_decoys=0,
                               code_operand_graph=False):
    if len(code_bytes) < 12 or len(code_bytes) > 65535:
        return code_bytes
    stored_to_std = stored_to_std or {}
    units = split_stored_code_units(code_bytes, stored_to_std)
    if not units:
        return code_bytes
    offsets = set(pos for pos, _length, _raw, _std, _arg in units)
    offsets.add(len(code_bytes))
    boundaries = set([0, len(code_bytes)])
    jumps = []
    terminal_names = set(['RETURN_VALUE', 'RAISE_VARARGS', 'BREAK_LOOP',
                          'CONTINUE_LOOP', 'YIELD_VALUE', 'END_FINALLY'])
    for pos, length, _raw_op, std_op, arg in units:
        next_pos = pos + length
        if std_op in opcode.hasjrel:
            target = next_pos + arg
            jumps.append((pos, length, 1, target))
            boundaries.add(next_pos)
            boundaries.add(target)
        elif std_op in opcode.hasjabs:
            target = arg
            jumps.append((pos, length, 0, target))
            boundaries.add(next_pos)
            boundaries.add(target)
        elif std_op < len(opcode.opname) and opcode.opname[std_op] in terminal_names:
            boundaries.add(next_pos)
    if any(boundary not in offsets for boundary in boundaries):
        return code_bytes
    sorted_bounds = sorted(boundaries)
    if len(sorted_bounds) <= 2:
        return code_bytes
    block_for_offset = {}
    blocks = []
    for block_id in range(len(sorted_bounds) - 1):
        start = sorted_bounds[block_id]
        end = sorted_bounds[block_id + 1]
        if start == end:
            continue
        block_for_offset[start] = block_id
        blocks.append([start, end, code_bytes[start:end], []])
    if not blocks or len(blocks) > 65535:
        return code_bytes
    starts = [block[0] for block in blocks]
    for pos, length, kind, target in jumps:
        if length != 3 or target not in block_for_offset:
            return code_bytes
        source_id = max(idx for idx, start in enumerate(starts) if start <= pos)
        local_pos = pos - blocks[source_id][0]
        target_id = block_for_offset[target]
        raw = list(blocks[source_id][2])
        raw[local_pos + 1] = '\x00'
        raw[local_pos + 2] = '\x00'
        blocks[source_id][2] = ''.join(raw)
        blocks[source_id][3].append((local_pos, kind, target_id, 0))

    seed = random.randint(1, 255)
    rows = []
    for block_id, (_start, _end, raw, relocs) in enumerate(blocks):
        mask = random.randint(1, 2147483647)
        encoded_relocs = tuple((local ^ seed, kind ^ seed,
                                target_id ^ seed, inner ^ seed)
                               for local, kind, target_id, inner in relocs)
        stored_raw = (pack_code_unit_arena(
            raw, stored_to_std, code_unit_arena_decoys,
            code_operand_graph) if code_unit_arena else raw)
        rows.append((CODE_BLOCK_RELOC_ROW_MAGIC, mask, block_id ^ mask,
                     stored_raw, encoded_relocs, len(raw) ^ (mask & 65535),
                     random_bytes(random.randint(2, 10))))
    decoys = max(0, min(64, int(decoys or 0)))
    for index in range(decoys):
        fake_id = len(blocks) + index + 1
        mask = random.randint(1, 2147483647)
        fake_raw = random_bytes(random.randint(3, 24))
        rows.append((CODE_BLOCK_RELOC_ROW_MAGIC, mask, fake_id ^ mask,
                     fake_raw, (), len(fake_raw) ^ (mask & 65535),
                     random_ident('block')))
    random.shuffle(rows)
    order = tuple(block_id ^ seed for block_id in range(len(blocks)))
    return (CODE_BLOCK_RELOC_MAGIC, seed, order, tuple(rows),
            len(code_bytes) ^ seed, len(blocks) ^ seed,
            random_bytes(random.randint(5, 15)))


def pack_const_provider(value, enabled=False):
    if not enabled:
        return value
    left = random.randint(1, 2147483647)
    right = random.randint(1, 2147483647)
    seed = left ^ right
    mask = random.randint(1, 2147483647)
    return (
        CODE_CONST_PROVIDER_MAGIC,
        seed ^ mask,
        mask,
        (left ^ mask, mask),
        (right ^ seed, seed),
        value,
        random_bytes(random.randint(3, 11)),
    )


def pack_code_global_arena(code, code_bytes_split=False, code_bytes_split_min=48,
                           code_bytes_split_max_chunks=6, code_bytes_fake_chunks=0,
                           template_delta=False, arena_decoys=0,
                           code_block_relocation=False, code_block_reloc_decoys=0,
                           stored_to_std=None, code_unit_arena=False,
                           code_unit_arena_decoys=0,
                           code_operand_graph=False, code_const_arena=False,
                           code_const_arena_decoys=0,
                           code_const_provider_graph=False,
                           code_const_arena_limit=1024,
                           code_field_descriptors=False,
                           code_provider_context_bind=False):
    nodes, node_ids, depths, parents, root_id = collect_code_object_graph(code)
    build_id = random.randint(1, 2147483647) if code_field_descriptors else 0
    templates = (make_global_arena_templates()
                 if template_delta and not code_field_descriptors
                 else ((None,) * 14,))
    packed_fields = []
    node_rows = []
    field_rows = []
    const_rows = []

    for code_id, item in enumerate(nodes):
        consts = []
        stored_opcode_map = resolve_stored_opcode_map(stored_to_std, code_id)
        stored_units = split_stored_code_units(item.co_code, stored_opcode_map) or []
        referenced_const_indexes = set(
            arg for _pos, length, _raw_op, std_op, arg in stored_units
            if length == 3 and std_op == LOAD_CONST and arg is not None)
        for const_index, const in enumerate(item.co_consts):
            if isinstance(const, types.CodeType):
                child_id = node_ids[id(const)]
                ref_mask = random.randint(1, 2147483647)
                const = (CODE_GLOBAL_ARENA_REF_MAGIC, ref_mask,
                         child_id ^ ref_mask, child_id ^ ref_mask ^ 0x05A17A55)
            elif (code_const_arena and const_index in referenced_const_indexes and
                  (code_const_arena_limit <= 0 or
                   len(const_rows) < code_const_arena_limit)):
                const_id = len(const_rows)
                ref_mask = random.randint(1, 2147483647)
                marker_id = const_id ^ ref_mask
                const_rows.append((
                    CODE_CONST_ARENA_ROW_MAGIC,
                    ref_mask,
                    marker_id,
                    pack_const_provider(const, code_const_provider_graph),
                    (const_id ^ ref_mask ^ 0x01C05A17) & 0x7fffffff,
                    random_bytes(random.randint(2, 10)),
                ))
                const = (CODE_CONST_ARENA_REF_MAGIC, ref_mask, marker_id,
                         marker_id ^ 0x06C057A1)
            consts.append(const)
        depth = depths.get(code_id, 0)
        depth_max_chunks = max(2, code_bytes_split_max_chunks -
                               min(depth, max(0, code_bytes_split_max_chunks - 2)))
        depth_fake_chunks = max(0, code_bytes_fake_chunks - min(depth, code_bytes_fake_chunks))
        if code_block_relocation:
            code_bytes = pack_code_block_relocation(
                item.co_code, resolve_stored_opcode_map(stored_to_std, code_id),
                code_block_reloc_decoys, code_unit_arena,
                code_unit_arena_decoys, code_operand_graph)
        elif code_unit_arena:
            code_bytes = pack_code_unit_arena(
                item.co_code, resolve_stored_opcode_map(stored_to_std, code_id),
                code_unit_arena_decoys, code_operand_graph)
        else:
            code_bytes = split_code_bytes_for_payload(
                item.co_code, code_bytes_split, code_bytes_split_min,
                depth_max_chunks, depth_fake_chunks)
        fields = (
            item.co_argcount, item.co_nlocals, item.co_stacksize, item.co_flags,
            code_bytes, tuple(consts), item.co_names, item.co_varnames,
            item.co_filename, item.co_name, item.co_firstlineno, item.co_lnotab,
            item.co_freevars, item.co_cellvars,
        )
        base_id, base_fields = choose_global_arena_base(
            fields, templates, packed_fields,
            template_delta and not code_field_descriptors)
        patch_indexes = [idx for idx in range(14) if fields[idx] != base_fields[idx]]
        packed_fields.append(fields)

        node_mask = random.randint(1, 2147483647)
        node_row = (
            CODE_GLOBAL_ARENA_NODE_MAGIC,
            node_mask,
            code_id ^ node_mask,
            (base_id + 4) ^ node_mask,
            len(patch_indexes) ^ (node_mask & 255),
            14 ^ ((node_mask >> 8) & 255),
            random_bytes(random.randint(3, 11)),
        )
        if code_field_descriptors:
            parent_id = parents.get(code_id, -1)
            bind_flag = 1 if code_provider_context_bind else 0
            node_check = (
                (build_id * 0x0019F3A7) ^ (code_id * 0x0007A2D5) ^
                ((parent_id + 2) * 0x00031D4B) ^ node_mask ^
                (bind_flag * 0x00045E91)
            ) & 0x7fffffff
            node_row = node_row[:6] + (
                parent_id ^ node_mask,
                build_id ^ node_mask,
                bind_flag ^ (node_mask & 1),
                node_check,
                node_row[6],
            )
        node_rows.append(node_row)

        random.shuffle(patch_indexes)
        group_count = max(1, min(len(patch_indexes), random.randint(2, 5)))
        groups = [[] for _ in range(group_count)]
        for pos, field_index in enumerate(patch_indexes):
            groups[pos % group_count].append(field_index)
        for group in groups:
            row_mask = random.randint(1, 2147483647)
            seed = random.randint(1, 255)
            pairs = tuple((
                field_index ^ seed,
                make_code_field_descriptor(
                    fields[field_index], build_id, code_id,
                    parents.get(code_id, -1), field_index,
                    code_provider_context_bind)
                if code_field_descriptors else fields[field_index]
            ) for field_index in group)
            check = (code_id ^ seed ^ len(pairs) ^ row_mask) & 0x7fffffff
            field_rows.append((
                CODE_GLOBAL_ARENA_ROW_MAGIC,
                row_mask,
                code_id ^ row_mask,
                seed,
                pairs,
                check,
                random_bytes(random.randint(2, 10)),
            ))

    decoy_count = max(0, min(128, int(arena_decoys or 0)))
    for offset in range(decoy_count):
        fake_id = len(nodes) + offset + 1
        node_mask = random.randint(1, 2147483647)
        node_rows.append((
            CODE_GLOBAL_ARENA_NODE_MAGIC, node_mask, fake_id ^ node_mask,
            3 ^ node_mask, random.randint(1, 14) ^ (node_mask & 255),
            14 ^ ((node_mask >> 8) & 255), random_bytes(random.randint(4, 14))))
        row_mask = random.randint(1, 2147483647)
        seed = random.randint(1, 255)
        fake_pairs = tuple((random.randint(0, 13) ^ seed,
                            random_bytes(random.randint(3, 18)))
                           for _ in range(random.randint(1, 3)))
        check = (fake_id ^ seed ^ len(fake_pairs) ^ row_mask) & 0x7fffffff
        field_rows.append((CODE_GLOBAL_ARENA_ROW_MAGIC, row_mask,
                           fake_id ^ row_mask, seed, fake_pairs, check,
                           random_ident('arena')))

    random.shuffle(node_rows)
    random.shuffle(field_rows)
    real_const_count = len(const_rows)
    if code_const_arena:
        decoy_count = max(0, min(512, int(code_const_arena_decoys or 0)))
        for offset in range(decoy_count):
            fake_id = real_const_count + offset + 1
            mask = random.randint(1, 2147483647)
            const_rows.append((
                CODE_CONST_ARENA_ROW_MAGIC, mask, fake_id ^ mask,
                pack_const_provider(make_fake_const(7, offset),
                                    code_const_provider_graph),
                (fake_id ^ mask ^ 0x01C05A17) & 0x7fffffff,
                random_ident('const'),
            ))
        random.shuffle(const_rows)
    root_mask = random.randint(1, 2147483647)
    flags = (1 if template_delta and not code_field_descriptors else 0) ^ root_mask
    result = (
        CODE_GLOBAL_ARENA_MAGIC,
        root_mask,
        root_id ^ root_mask,
        templates,
        tuple(node_rows),
        tuple(field_rows),
        len(nodes) ^ root_mask,
        flags,
        random_bytes(random.randint(8, 24)),
    )
    if code_const_arena:
        result += (tuple(const_rows), real_const_count ^ root_mask)
    elif code_field_descriptors:
        result += ((), root_mask)
    if code_field_descriptors:
        result += (
            CODE_FIELD_ARENA_CONTEXT_MAGIC,
            build_id ^ root_mask,
            (1 if code_provider_context_bind else 0) ^ (root_mask & 1),
        )
    return result


def dumps_code_payload(code, use_code_tuple=True, code_bytes_split=False, code_bytes_split_min=48, code_bytes_split_max_chunks=6, code_bytes_fake_chunks=0, code_ref_table=False, code_tuple_field_shuffle=False, code_ref_decoys=0, code_ref_wide_rows=False, code_ref_mask_markers=False, code_tuple_fragments=False, code_tuple_fragment_providers=False, code_tuple_provider_graph=False, code_tuple_provider_decoys=0, code_global_arena=False, code_template_delta=False, code_global_arena_decoys=0, code_block_relocation=False, code_block_reloc_decoys=0, stored_to_std=None, code_unit_arena=False, code_unit_arena_decoys=0, code_operand_graph=False, code_const_arena=False, code_const_arena_decoys=0, code_const_provider_graph=False, code_const_arena_limit=1024, code_field_descriptors=False, code_provider_context_bind=False):
    if use_code_tuple:
        if code_global_arena:
            root_tuple = pack_code_global_arena(
                code, code_bytes_split, code_bytes_split_min,
                code_bytes_split_max_chunks, code_bytes_fake_chunks,
                code_template_delta, code_global_arena_decoys,
                code_block_relocation, code_block_reloc_decoys, stored_to_std,
                code_unit_arena, code_unit_arena_decoys, code_operand_graph,
                code_const_arena, code_const_arena_decoys,
                code_const_provider_graph, code_const_arena_limit,
                code_field_descriptors, code_provider_context_bind)
            return CODE_TUPLE_MAGIC + pickle.dumps(root_tuple, 2)
        refs = [] if code_ref_table else None
        root_tuple = pack_code_tuple(code, code_bytes_split, code_bytes_split_min, code_bytes_split_max_chunks, code_bytes_fake_chunks, 0, refs, code_tuple_field_shuffle, code_ref_wide_rows, code_ref_mask_markers, code_tuple_fragments, code_tuple_fragment_providers, code_tuple_provider_graph, code_tuple_provider_decoys, code_field_descriptors, code_provider_context_bind)
        if refs is not None and refs:
            refs.extend(make_code_ref_decoy_rows(code_ref_decoys, len(refs) + 1, code_tuple_field_shuffle, code_ref_wide_rows, code_tuple_fragments, code_tuple_fragment_providers, code_tuple_provider_graph, code_tuple_provider_decoys, code_field_descriptors, code_provider_context_bind))
            random.shuffle(refs)
            root_tuple = (CODE_REF_TABLE_MAGIC, root_tuple, tuple(refs))
        return CODE_TUPLE_MAGIC + pickle.dumps(root_tuple, 2)
    return marshal.dumps(code)


def build_code_tuple_loader_code(names, dialect=None):
    values = dict(names)
    for key_name in [
            'field_shape_name', 'field_resolve_name', 'field_descriptor_factory_name',
            'field_get_name', 'field_set_name', 'field_delete_name',
            'field_repr_name', 'field_materialize_name', 'field_object_open_name',
            'field_build_name', 'field_code_name', 'field_parent_name',
            'field_id_name', 'field_value_name', 'field_provider_name',
            'field_expected_build_name', 'field_expected_parent_name',
            'field_bind_name', 'field_attr_name', 'field_attrs_name',
            'field_holder_name', 'field_class_name', 'field_self_name',
            'field_descriptor_type_name', 'field_holder_type_name',
            'field_descriptor_init_name', 'field_holder_init_name',
            'field_guard_getattribute_name', 'field_attr_order_name',
            'lambda_code_type_name',
            'fused_bytes_name', 'fused_map_name', 'fused_counter_name',
            'fused_per_code_name', 'fused_active_name']:
        if key_name not in values:
            values[key_name] = random_ident(key_name[:4])
    if 'salt_name' not in values:
        values['salt_name'] = random_ident('fslt')
    if 'have_argument' not in values:
        values['have_argument'] = HAVE_ARGUMENT
    debug_enabled = bool(values.get('debug_enabled'))
    if debug_enabled:
        root_name = values['debug_root_name']
        debug_tuple_begin = (
            '    if %s:\n'
            '        print(%r)'
        ) % (root_name, '[DEBUG] MCP CodeTuple Begin Loaded')
        debug_tuple_pickle = (
            '        if %s:\n'
            '            print(%r)'
        ) % (root_name, '[DEBUG] MCP CodeTuple cPickle Loaded')
        debug_tuple_complete = (
            '    if %s:\n'
            '        print(%r)'
        ) % (root_name, '[DEBUG] MCP CodeTuple Complete Loaded')
    else:
        debug_tuple_begin = ''
        debug_tuple_pickle = ''
        debug_tuple_complete = ''
    if dialect is None:
        dialect = random.randrange(3)
    # Keep the loader ABI identical while varying the source shape of small,
    # frequently fingerprinted helpers per generated module.
    if int(dialect) % 3 == 0:
        code_ref_xor_body = (
            "    return ''.join([chr(ord(%(raw_name)s) ^ ((%(seed_name)s + "
            "%(order_item_name)s) & 255)) for %(order_item_name)s, "
            "%(raw_name)s in enumerate(%(raw_name)s)])")
        field_shape_body = (
            "    try:\n"
            "        return len(%(field_value_name)s)\n"
            "    except Exception:\n"
            "        return 1")
    elif int(dialect) % 3 == 1:
        code_ref_xor_body = (
            "    %(raw_name)s = list(%(raw_name)s)\n"
            "    return ''.join(chr(ord(%(raw_name)s[%(order_item_name)s]) ^ "
            "((%(seed_name)s + %(order_item_name)s) & 255)) for "
            "%(order_item_name)s in range(len(%(raw_name)s)))")
        field_shape_body = (
            "    value = %(field_value_name)s\n"
            "    try:\n"
            "        return len(value)\n"
            "    except (TypeError, AttributeError):\n"
            "        return 1")
    else:
        code_ref_xor_body = (
            "    return ''.join(map(lambda %(order_item_name)s: chr(ord(%(raw_name)s[%(order_item_name)s]) ^ "
            "((%(seed_name)s + %(order_item_name)s) & 255)), range(len(%(raw_name)s))))")
        field_shape_body = (
            "    value = %(field_value_name)s\n"
            "    try:\n"
            "        return len(value)\n"
            "    except (TypeError, AttributeError):\n"
            "        return 1")
    values.update({
        'code_ref_xor_body': code_ref_xor_body % values,
        'field_shape_body': field_shape_body % values,
        'code_tuple_magic_repr': repr(CODE_TUPLE_MAGIC),
        'code_bytes_split_magic_repr': repr(CODE_BYTES_SPLIT_MAGIC),
        'code_ref_table_magic_repr': repr(CODE_REF_TABLE_MAGIC),
        'code_tuple_shuffle_magic_repr': repr(CODE_TUPLE_SHUFFLE_MAGIC),
        'code_ref_mask_magic_repr': repr(CODE_REF_MASK_MAGIC),
        'code_tuple_frag_magic_repr': repr(CODE_TUPLE_FRAG_MAGIC),
        'code_tuple_provider_magic_repr': repr(CODE_TUPLE_PROVIDER_MAGIC),
        'code_tuple_provider_graph_magic_repr': repr(CODE_TUPLE_PROVIDER_GRAPH_MAGIC),
        'code_field_object_magic_repr': repr(CODE_FIELD_OBJECT_MAGIC),
        'code_field_descriptor_magic_repr': repr(CODE_FIELD_DESCRIPTOR_MAGIC),
        'code_field_provider_magic_repr': repr(CODE_FIELD_PROVIDER_MAGIC),
        'code_field_arena_context_magic_repr': repr(CODE_FIELD_ARENA_CONTEXT_MAGIC),
        'field_descriptor_class_repr': repr(random_ident('CodeFieldDescriptor')),
        'field_holder_class_repr': repr(random_ident('CodeFieldHolder')),
        'field_repr_value': repr('<%s sealed>' % random_ident('field')),
        'field_attr_order_repr': repr(tuple(random_ident('f') for _ in range(14))),
        'field_descriptor_slot_repr': repr(random_ident('field_id')),
        'field_records_slot_repr': repr(random_ident('records')),
        'field_build_slot_repr': repr(random_ident('build')),
        'field_code_slot_repr': repr(random_ident('code')),
        'field_parent_slot_repr': repr(random_ident('parent')),
        'field_decoy_key_repr': repr(random_ident('sealed')),
        'field_decoy_value': random.randint(0x10000, 0x7fffffff),
        'code_global_arena_magic_repr': repr(CODE_GLOBAL_ARENA_MAGIC),
        'code_global_arena_ref_magic_repr': repr(CODE_GLOBAL_ARENA_REF_MAGIC),
        'code_global_arena_node_magic_repr': repr(CODE_GLOBAL_ARENA_NODE_MAGIC),
        'code_global_arena_row_magic_repr': repr(CODE_GLOBAL_ARENA_ROW_MAGIC),
        'code_block_reloc_magic_repr': repr(CODE_BLOCK_RELOC_MAGIC),
        'code_block_reloc_row_magic_repr': repr(CODE_BLOCK_RELOC_ROW_MAGIC),
        'code_unit_arena_magic_repr': repr(CODE_UNIT_ARENA_MAGIC),
        'code_unit_arena_row_magic_repr': repr(CODE_UNIT_ARENA_ROW_MAGIC),
        'code_const_arena_ref_magic_repr': repr(CODE_CONST_ARENA_REF_MAGIC),
        'code_const_arena_row_magic_repr': repr(CODE_CONST_ARENA_ROW_MAGIC),
        'code_const_provider_magic_repr': repr(CODE_CONST_PROVIDER_MAGIC),
        'debug_tuple_begin': debug_tuple_begin,
        'debug_tuple_pickle': debug_tuple_pickle,
        'debug_tuple_complete': debug_tuple_complete,
        'debug_unit_arena': debug_print_code(debug_enabled, 'MCP Bytecode UnitArenaJoin', 8),
        'debug_block_reloc': debug_print_code(debug_enabled, 'MCP Bytecode BlockRelocation', 8),
        'debug_bytes_split': debug_print_code(debug_enabled, 'MCP Bytecode BytesSplitJoin', 8),
        'debug_arena_begin': debug_print_code(debug_enabled, 'MCP CodeArena Begin', 4),
        'debug_const_arena': debug_print_code(debug_enabled, 'MCP CodeArena ConstArena', 8),
        'debug_arena_done': debug_print_code(debug_enabled, 'MCP CodeArena Complete', 4),
        'debug_ref_table': debug_print_code(debug_enabled, 'MCP CodeTuple RefTable', 8),
        'debug_tuple_shuffle': debug_print_code(debug_enabled, 'MCP CodeTuple FieldShuffle', 8),
        'debug_field_object': debug_print_code(debug_enabled, 'MCP CodeField ContextBind', 4),
        'debug_field_materialize': debug_print_code(debug_enabled, 'MCP CodeField DescriptorMaterialize', 4),
    })
    return '''def %(code_ref_xor_name)s(%(raw_name)s, %(seed_name)s):
    %(seed_name)s = max(1, int(%(seed_name)s) & 255)
%(code_ref_xor_body)s

def %(field_shape_name)s(%(field_value_name)s):
%(field_shape_body)s

def %(field_resolve_name)s(%(field_provider_name)s, %(field_build_name)s, %(field_code_name)s, %(field_parent_name)s, %(field_id_name)s):
    if not (isinstance(%(field_provider_name)s, tuple) and len(%(field_provider_name)s) == 4 and %(field_provider_name)s[0] == %(code_field_descriptor_magic_repr)s):
        raise ValueError('missing code field descriptor')
    %(mask_name)s = %(field_provider_name)s[2][1]
    if (%(field_provider_name)s[1] ^ (%(mask_name)s & 255)) != %(field_id_name)s:
        raise ValueError('bad descriptor field id')
    if %(field_provider_name)s[3] != ((%(field_id_name)s ^ %(mask_name)s ^ len(%(field_provider_name)s[2]) ^ 0x02D35A71) & 0x7fffffff):
        raise ValueError('bad descriptor guard')
    %(field_provider_name)s = %(field_provider_name)s[2]
    if not (isinstance(%(field_provider_name)s, tuple) and len(%(field_provider_name)s) == 5 and %(field_provider_name)s[0] == %(code_field_provider_magic_repr)s):
        raise ValueError('missing code field provider')
    %(salt_name)s = %(field_provider_name)s[1]
    %(key_len_name)s = %(field_provider_name)s[2] ^ %(salt_name)s
    %(field_value_name)s = %(field_provider_name)s[3]
    if %(field_shape_name)s(%(field_value_name)s) != %(key_len_name)s:
        raise ValueError('bad field provider size')
    %(left_name)s = (((%(field_build_name)s * 0x01F123BB) ^ (%(field_code_name)s * 0x0059D2F1) ^ ((%(field_parent_name)s + 2) * 0x00045D9F) ^ (%(field_id_name)s * 0x001B8735) ^ %(salt_name)s ^ %(key_len_name)s ^ (%(salt_name)s ^ 0x035A71D9)) & 0x7fffffff)
    if %(field_provider_name)s[4] != %(left_name)s:
        raise ValueError('bad field provider tag')
    return %(field_value_name)s

%(field_descriptor_type_name)s = None
%(field_holder_type_name)s = None
%(field_attr_order_name)s = %(field_attr_order_repr)s

def %(field_descriptor_init_name)s(%(field_self_name)s, %(field_id_name)s):
    object.__setattr__(%(field_self_name)s, %(field_descriptor_slot_repr)s, %(field_id_name)s)

def %(field_get_name)s(%(field_self_name)s, %(field_holder_name)s, %(field_class_name)s=None):
    if %(field_holder_name)s is None:
        return %(field_self_name)s
    %(field_id_name)s = object.__getattribute__(%(field_self_name)s, %(field_descriptor_slot_repr)s)
    %(tuple_name)s = object.__getattribute__(%(field_holder_name)s, %(field_records_slot_repr)s)
    %(field_build_name)s = object.__getattribute__(%(field_holder_name)s, %(field_build_slot_repr)s)
    %(field_code_name)s = object.__getattribute__(%(field_holder_name)s, %(field_code_slot_repr)s)
    %(field_parent_name)s = object.__getattribute__(%(field_holder_name)s, %(field_parent_slot_repr)s)
    return %(field_resolve_name)s(%(tuple_name)s[%(field_id_name)s], %(field_build_name)s, %(field_code_name)s, %(field_parent_name)s, %(field_id_name)s)

def %(field_set_name)s(%(field_self_name)s, %(field_holder_name)s, %(field_value_name)s):
    raise AttributeError('sealed code field')

def %(field_delete_name)s(%(field_self_name)s, %(field_holder_name)s):
    raise AttributeError('sealed code field')

def %(field_repr_name)s(%(field_self_name)s):
    return %(field_repr_value)s

def %(field_holder_init_name)s(%(field_self_name)s, %(tuple_name)s, %(field_build_name)s, %(field_code_name)s, %(field_parent_name)s):
    object.__setattr__(%(field_self_name)s, %(field_records_slot_repr)s, %(tuple_name)s)
    object.__setattr__(%(field_self_name)s, %(field_build_slot_repr)s, %(field_build_name)s)
    object.__setattr__(%(field_self_name)s, %(field_code_slot_repr)s, %(field_code_name)s)
    object.__setattr__(%(field_self_name)s, %(field_parent_slot_repr)s, %(field_parent_name)s)

def %(field_guard_getattribute_name)s(%(field_self_name)s, %(field_attr_name)s):
    if %(field_attr_name)s == '__dict__':
        return {%(field_decoy_key_repr)s: %(field_decoy_value)d}
    return object.__getattribute__(%(field_self_name)s, %(field_attr_name)s)

def %(field_materialize_name)s(%(tuple_name)s, %(field_build_name)s, %(field_code_name)s, %(field_parent_name)s):
    global %(field_descriptor_type_name)s, %(field_holder_type_name)s
%(debug_field_materialize)s
    if len(%(tuple_name)s) != 14:
        raise ValueError('bad code field count')
    if %(field_holder_type_name)s is None:
        %(field_descriptor_type_name)s = type(%(field_descriptor_class_repr)s, (object,), {
            '__slots__': (%(field_descriptor_slot_repr)s,),
            '__init__': %(field_descriptor_init_name)s,
            '__get__': %(field_get_name)s,
            '__set__': %(field_set_name)s,
            '__delete__': %(field_delete_name)s,
            '__repr__': %(field_repr_name)s,
        })
        %(field_attrs_name)s = {
            '__slots__': (%(field_records_slot_repr)s, %(field_build_slot_repr)s, %(field_code_slot_repr)s, %(field_parent_slot_repr)s),
            '__init__': %(field_holder_init_name)s,
            '__getattribute__': %(field_guard_getattribute_name)s,
            '__repr__': %(field_repr_name)s,
        }
        for %(field_id_name)s, %(field_attr_name)s in enumerate(%(field_attr_order_name)s):
            %(field_attrs_name)s[%(field_attr_name)s] = %(field_descriptor_type_name)s(%(field_id_name)s)
        %(field_holder_type_name)s = type(%(field_holder_class_repr)s, (object,), %(field_attrs_name)s)
    %(field_holder_name)s = %(field_holder_type_name)s(%(tuple_name)s, %(field_build_name)s, %(field_code_name)s, %(field_parent_name)s)
    return tuple([getattr(%(field_holder_name)s, %(field_attr_name)s) for %(field_attr_name)s in %(field_attr_order_name)s])

def %(field_object_open_name)s(%(raw_name)s, %(field_expected_build_name)s=None, %(field_expected_parent_name)s=None):
    if not (isinstance(%(raw_name)s, tuple) and len(%(raw_name)s) >= 8 and %(raw_name)s[0] == %(code_field_object_magic_repr)s):
        return (%(raw_name)s, None, None, None, 0)
%(debug_field_object)s
    %(mask_name)s = %(raw_name)s[1]
    %(field_build_name)s = %(raw_name)s[2] ^ %(mask_name)s
    %(field_code_name)s = %(raw_name)s[3] ^ %(mask_name)s
    %(field_parent_name)s = %(raw_name)s[4] ^ %(mask_name)s
    %(field_bind_name)s = %(raw_name)s[5] ^ (%(mask_name)s & 1)
    %(key_len_name)s = %(field_shape_name)s(%(raw_name)s[6])
    %(left_name)s = (((%(field_build_name)s * 0x003D2A9D) ^ (%(field_code_name)s * 0x000F1433) ^ ((%(field_parent_name)s + 2) * 0x0012AD61) ^ %(key_len_name)s ^ %(mask_name)s ^ (%(field_bind_name)s * 0x00051ED7)) & 0x7fffffff)
    if %(raw_name)s[7] != %(left_name)s:
        raise ValueError('bad code field object tag')
    if %(field_bind_name)s:
        if %(field_expected_build_name)s is not None and %(field_expected_build_name)s != %(field_build_name)s:
            raise ValueError('detached code field build')
        if %(field_expected_parent_name)s is None:
            if %(field_parent_name)s != -1:
                raise ValueError('detached nested code field')
        elif %(field_expected_parent_name)s != %(field_parent_name)s:
            raise ValueError('detached code field parent')
    return (%(raw_name)s[6], %(field_build_name)s, %(field_code_name)s, %(field_parent_name)s, %(field_bind_name)s)

def %(code_units_join_name)s(%(raw_name)s):
    if not (isinstance(%(raw_name)s, tuple) and len(%(raw_name)s) >= 7 and %(raw_name)s[0] == %(code_unit_arena_magic_repr)s):
        return %(raw_name)s
%(debug_unit_arena)s
    %(seed_name)s = %(raw_name)s[1]
    %(key_len_name)s = %(raw_name)s[5] ^ %(seed_name)s
    %(left_name)s = %(raw_name)s[6] ^ %(seed_name)s
    %(items_name)s = {}
    for %(ref_row_name)s in %(raw_name)s[3]:
        if not (isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 5 and %(ref_row_name)s[0] == %(code_unit_arena_row_magic_repr)s):
            continue
        %(idx_name)s = %(ref_row_name)s[1] ^ %(ref_row_name)s[2]
        if %(idx_name)s < 0 or %(idx_name)s >= %(key_len_name)s:
            continue
        %(right_name)s = %(ref_row_name)s[4] ^ (%(ref_row_name)s[1] & 255)
        %(item_name)s = %(ref_row_name)s[3]
        if %(left_name)s:
            if not isinstance(%(item_name)s, tuple) or len(%(item_name)s) < 4:
                continue
            %(mask_name)s = %(item_name)s[2]
            %(opv_name)s = %(item_name)s[1] ^ %(mask_name)s
            %(ch_name)s = %(item_name)s[0] ^ %(mask_name)s
            if %(ch_name)s == 0 and len(%(item_name)s) == 4:
                if %(item_name)s[3] != ((%(opv_name)s + %(idx_name)s) & 255):
                    continue
                %(item_name)s = chr(%(opv_name)s)
            elif %(ch_name)s == 1 and len(%(item_name)s) == 6:
                %(pos_name)s = %(item_name)s[3] ^ %(mask_name)s
                %(data_arg)s = %(item_name)s[4] ^ ((%(mask_name)s + %(idx_name)s) & 255)
                if %(item_name)s[5] != ((%(opv_name)s + %(pos_name)s + %(data_arg)s + %(idx_name)s) & 255):
                    continue
                %(item_name)s = chr(%(opv_name)s) + chr(%(pos_name)s) + chr(%(data_arg)s)
            else:
                continue
        if not isinstance(%(item_name)s, str) or len(%(item_name)s) != %(right_name)s:
            continue
        %(items_name)s[%(idx_name)s] = %(item_name)s
    %(consts_name)s = []
    for %(order_item_name)s in %(raw_name)s[2]:
        %(idx_name)s = %(order_item_name)s ^ %(seed_name)s
        if %(idx_name)s not in %(items_name)s:
            raise ValueError('missing instruction unit')
        %(consts_name)s.append(%(items_name)s[%(idx_name)s])
    %(out_name)s = ''.join(%(consts_name)s)
    if len(%(out_name)s) != (%(raw_name)s[4] ^ %(seed_name)s):
        raise ValueError('bad instruction arena size')
    return %(out_name)s

def %(code_bytes_join_name)s(%(raw_name)s):
    if isinstance(%(raw_name)s, tuple) and len(%(raw_name)s) >= 7 and %(raw_name)s[0] == %(code_unit_arena_magic_repr)s:
        return %(code_units_join_name)s(%(raw_name)s)
    if isinstance(%(raw_name)s, tuple) and len(%(raw_name)s) >= 6 and %(raw_name)s[0] == %(code_block_reloc_magic_repr)s:
%(debug_block_reloc)s
        %(seed_name)s = %(raw_name)s[1]
        %(items_name)s = {}
        %(ref_table_name)s = {}
        for %(ref_row_name)s in %(raw_name)s[3]:
            if not (isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 6 and %(ref_row_name)s[0] == %(code_block_reloc_row_magic_repr)s):
                continue
            %(idx_name)s = %(ref_row_name)s[1] ^ %(ref_row_name)s[2]
            %(item_name)s = %(code_units_join_name)s(%(ref_row_name)s[3])
            if len(%(item_name)s) != (%(ref_row_name)s[5] ^ (%(ref_row_name)s[1] & 65535)):
                continue
            %(items_name)s[%(idx_name)s] = %(item_name)s
            %(ref_table_name)s[%(idx_name)s] = %(ref_row_name)s[4]
        %(key_len_name)s = %(raw_name)s[5] ^ %(seed_name)s
        %(consts_name)s = []
        %(out_name)s = {}
        for %(order_item_name)s in %(raw_name)s[2]:
            %(idx_name)s = %(order_item_name)s ^ %(seed_name)s
            if %(idx_name)s not in %(items_name)s or %(idx_name)s >= %(key_len_name)s:
                raise ValueError('missing relocated block')
            %(out_name)s[%(idx_name)s] = sum(len(%(item_name)s) for %(item_name)s in %(consts_name)s)
            %(consts_name)s.append(%(items_name)s[%(idx_name)s])
        %(src_name)s = list(''.join(%(consts_name)s))
        if len(%(src_name)s) != (%(raw_name)s[4] ^ %(seed_name)s):
            raise ValueError('bad relocated code size')
        for %(idx_name)s in range(%(key_len_name)s):
            if %(idx_name)s not in %(ref_table_name)s or %(idx_name)s not in %(out_name)s:
                continue
            for %(order_item_name)s in %(ref_table_name)s[%(idx_name)s]:
                %(pos_name)s = %(order_item_name)s[0] ^ %(seed_name)s
                %(left_name)s = %(order_item_name)s[1] ^ %(seed_name)s
                %(right_name)s = %(order_item_name)s[2] ^ %(seed_name)s
                %(opv_name)s = %(order_item_name)s[3] ^ %(seed_name)s
                if %(right_name)s not in %(out_name)s:
                    raise ValueError('bad relocation target')
                %(ch_name)s = %(out_name)s[%(idx_name)s] + %(pos_name)s
                %(data_arg)s = %(out_name)s[%(right_name)s] + %(opv_name)s
                if %(left_name)s == 1:
                    %(data_arg)s -= %(ch_name)s + 3
                elif %(left_name)s != 0:
                    raise ValueError('bad relocation kind')
                if %(data_arg)s < 0 or %(data_arg)s > 65535 or %(ch_name)s + 2 >= len(%(src_name)s):
                    raise ValueError('relocation overflow')
                %(src_name)s[%(ch_name)s + 1] = chr(%(data_arg)s & 255)
                %(src_name)s[%(ch_name)s + 2] = chr((%(data_arg)s >> 8) & 255)
        return ''.join(%(src_name)s)
    if isinstance(%(raw_name)s, tuple) and len(%(raw_name)s) == 4 and %(raw_name)s[0] == %(code_bytes_split_magic_repr)s:
%(debug_bytes_split)s
        %(seed_name)s = %(raw_name)s[1]
        return ''.join([%(raw_name)s[3][(%(order_item_name)s ^ %(seed_name)s)] for %(order_item_name)s in %(raw_name)s[2]])
    return %(raw_name)s

def %(fused_bytes_name)s(%(raw_name)s, %(fused_map_name)s, %(fused_counter_name)s, %(fused_per_code_name)s):
    if %(fused_map_name)s is None:
        return %(raw_name)s
    if %(fused_counter_name)s is None:
        %(fused_counter_name)s = [0]
    if %(fused_per_code_name)s:
        %(idx_name)s = %(fused_counter_name)s[0]
        %(fused_counter_name)s[0] += 1
        %(fused_active_name)s = %(fused_map_name)s.get(%(idx_name)s, {})
    else:
        %(fused_active_name)s = %(fused_map_name)s
    %(out_name)s = list(%(raw_name)s)
    %(pos_name)s = 0
    while %(pos_name)s < len(%(out_name)s):
        %(opv_name)s = ord(%(out_name)s[%(pos_name)s])
        %(out_name)s[%(pos_name)s] = chr(%(fused_active_name)s.get(%(opv_name)s, %(opv_name)s))
        %(pos_name)s += 3 if %(opv_name)s >= %(have_argument)d else 1
    return ''.join(%(out_name)s)

def %(frag_provider_name)s(%(ref_row_name)s):
    if isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 5 and %(ref_row_name)s[0] == %(code_tuple_provider_magic_repr)s:
        if (%(ref_row_name)s[1] ^ %(ref_row_name)s[3]) == %(ref_row_name)s[2]:
            return %(ref_row_name)s[4]
    if isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 6 and %(ref_row_name)s[0] == %(code_tuple_provider_graph_magic_repr)s:
        try:
            %(left_name)s = %(ref_row_name)s[3][0] ^ %(ref_row_name)s[3][1]
            %(right_name)s = %(ref_row_name)s[4][0] ^ %(ref_row_name)s[4][1]
            %(seed_name)s = %(left_name)s ^ %(right_name)s
            if (%(ref_row_name)s[1] ^ %(ref_row_name)s[2]) == %(seed_name)s:
                return %(ref_row_name)s[5]
        except Exception:
            pass
    return %(ref_row_name)s

def %(arena_load_name)s(%(raw_name)s, %(pickle_name)s, %(types_name)s, %(fused_map_name)s=None, %(fused_counter_name)s=None, %(fused_per_code_name)s=False):
%(debug_arena_begin)s
    %(lambda_code_type_name)s = (lambda: None).func_code.__class__
    %(magic_name)s = %(raw_name)s[1]
    %(code_arg)s = %(raw_name)s[2] ^ %(magic_name)s
    %(field_build_name)s = None
    %(field_bind_name)s = 0
    %(field_attrs_name)s = {}
    if len(%(raw_name)s) >= 14 and %(raw_name)s[11] == %(code_field_arena_context_magic_repr)s:
        %(field_build_name)s = %(raw_name)s[12] ^ %(magic_name)s
        %(field_bind_name)s = %(raw_name)s[13] ^ (%(magic_name)s & 1)
    %(items_name)s = {}
    for %(ref_row_name)s in %(raw_name)s[4]:
        if not (isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 6 and %(ref_row_name)s[0] == %(code_global_arena_node_magic_repr)s):
            continue
        %(idx_name)s = %(ref_row_name)s[1] ^ %(ref_row_name)s[2]
        %(left_name)s = (%(ref_row_name)s[3] ^ %(ref_row_name)s[1]) - 4
        %(right_name)s = %(ref_row_name)s[4] ^ (%(ref_row_name)s[1] & 255)
        %(key_len_name)s = %(ref_row_name)s[5] ^ ((%(ref_row_name)s[1] >> 8) & 255)
        if %(key_len_name)s == 14:
            if %(field_build_name)s is not None:
                if len(%(ref_row_name)s) < 10:
                    continue
                %(field_parent_name)s = %(ref_row_name)s[6] ^ %(ref_row_name)s[1]
                if (%(ref_row_name)s[7] ^ %(ref_row_name)s[1]) != %(field_build_name)s:
                    continue
                if (%(ref_row_name)s[8] ^ (%(ref_row_name)s[1] & 1)) != %(field_bind_name)s:
                    continue
                %(field_provider_name)s = (((%(field_build_name)s * 0x0019F3A7) ^ (%(idx_name)s * 0x0007A2D5) ^ ((%(field_parent_name)s + 2) * 0x00031D4B) ^ %(ref_row_name)s[1] ^ (%(field_bind_name)s * 0x00045E91)) & 0x7fffffff)
                if %(ref_row_name)s[9] != %(field_provider_name)s:
                    continue
                %(field_attrs_name)s[%(idx_name)s] = %(field_parent_name)s
            %(items_name)s[%(idx_name)s] = (%(left_name)s, %(right_name)s)
    %(ref_table_name)s = {}
    for %(ref_row_name)s in %(raw_name)s[5]:
        if not (isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 6 and %(ref_row_name)s[0] == %(code_global_arena_row_magic_repr)s):
            continue
        %(idx_name)s = %(ref_row_name)s[1] ^ %(ref_row_name)s[2]
        %(seed_name)s = %(ref_row_name)s[3]
        if %(ref_row_name)s[5] != ((%(idx_name)s ^ %(seed_name)s ^ len(%(ref_row_name)s[4]) ^ %(ref_row_name)s[1]) & 0x7fffffff):
            continue
        %(ref_table_name)s.setdefault(%(idx_name)s, [])
        for %(order_item_name)s in %(ref_row_name)s[4]:
            %(ref_table_name)s[%(idx_name)s].append((%(order_item_name)s[0] ^ %(seed_name)s, %(order_item_name)s[1]))
    %(out_name)s = {}
    %(key_len_name)s = %(raw_name)s[6] ^ %(magic_name)s
    for %(idx_name)s in range(%(key_len_name)s):
        if %(idx_name)s not in %(items_name)s:
            raise ValueError('missing arena node')
        %(left_name)s, %(right_name)s = %(items_name)s[%(idx_name)s]
        if %(left_name)s < 0:
            %(tuple_name)s = list(%(raw_name)s[3][-%(left_name)s - 1])
        else:
            if %(left_name)s >= %(idx_name)s or %(left_name)s not in %(out_name)s:
                raise ValueError('bad arena base')
            %(tuple_name)s = list(%(out_name)s[%(left_name)s])
        %(src_name)s = %(ref_table_name)s.get(%(idx_name)s, [])
        if len(%(src_name)s) != %(right_name)s:
            raise ValueError('bad arena patch count')
        %(key_arg)s = set()
        for %(order_item_name)s in %(src_name)s:
            %(pos_name)s = %(order_item_name)s[0]
            if %(pos_name)s < 0 or %(pos_name)s >= 14 or %(pos_name)s in %(key_arg)s:
                raise ValueError('bad arena field')
            %(key_arg)s.add(%(pos_name)s)
            %(tuple_name)s[%(pos_name)s] = %(order_item_name)s[1]
        %(out_name)s[%(idx_name)s] = tuple(%(tuple_name)s)
    %(const_arena_name)s = {}
    if len(%(raw_name)s) >= 11:
%(debug_const_arena)s
        %(key_len_name)s = %(raw_name)s[10] ^ %(magic_name)s
        for %(ref_row_name)s in %(raw_name)s[9]:
            if not (isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 5 and %(ref_row_name)s[0] == %(code_const_arena_row_magic_repr)s):
                continue
            %(idx_name)s = %(ref_row_name)s[1] ^ %(ref_row_name)s[2]
            if %(idx_name)s < 0 or %(idx_name)s >= %(key_len_name)s:
                continue
            if %(ref_row_name)s[4] != ((%(idx_name)s ^ %(ref_row_name)s[1] ^ 0x01C05A17) & 0x7fffffff):
                continue
            %(const_provider_name)s = %(ref_row_name)s[3]
            if isinstance(%(const_provider_name)s, tuple) and len(%(const_provider_name)s) >= 6 and %(const_provider_name)s[0] == %(code_const_provider_magic_repr)s:
                try:
                    %(seed_name)s = %(const_provider_name)s[1] ^ %(const_provider_name)s[2]
                    %(left_name)s = %(const_provider_name)s[3][0] ^ %(const_provider_name)s[3][1]
                    %(right_name)s = %(const_provider_name)s[4][0] ^ %(const_provider_name)s[4][1]
                    if %(seed_name)s != (%(left_name)s ^ %(right_name)s):
                        continue
                    %(const_provider_name)s = %(const_provider_name)s[5]
                except Exception:
                    continue
            %(const_arena_name)s[%(idx_name)s] = %(const_provider_name)s
        if len(%(const_arena_name)s) != %(key_len_name)s:
            raise ValueError('missing constant arena row')
    %(data_arg)s = {}
    def %(arena_build_name)s(%(idx_name)s):
        if %(idx_name)s in %(data_arg)s:
            return %(data_arg)s[%(idx_name)s]
        %(tuple_name)s = list(%(out_name)s[%(idx_name)s])
        if %(field_build_name)s is not None:
            if %(idx_name)s not in %(field_attrs_name)s:
                raise ValueError('missing code field owner')
            %(tuple_name)s = list(%(field_materialize_name)s(%(tuple_name)s, %(field_build_name)s, %(idx_name)s, %(field_attrs_name)s[%(idx_name)s]))
        %(tuple_name)s[4] = %(fused_bytes_name)s(%(code_bytes_join_name)s(%(tuple_name)s[4]), %(fused_map_name)s, %(fused_counter_name)s, %(fused_per_code_name)s)
        %(consts_name)s = []
        for %(const_name)s in %(tuple_name)s[5]:
            if isinstance(%(const_name)s, tuple) and len(%(const_name)s) == 4 and %(const_name)s[0] == %(code_global_arena_ref_magic_repr)s:
                %(left_name)s = %(const_name)s[1] ^ %(const_name)s[2]
                if %(const_name)s[3] == (%(const_name)s[2] ^ 0x05A17A55):
                    %(const_name)s = %(arena_build_name)s(%(left_name)s)
            elif isinstance(%(const_name)s, tuple) and len(%(const_name)s) == 4 and %(const_name)s[0] == %(code_const_arena_ref_magic_repr)s:
                %(left_name)s = %(const_name)s[1] ^ %(const_name)s[2]
                if %(const_name)s[3] != (%(const_name)s[2] ^ 0x06C057A1) or %(left_name)s not in %(const_arena_name)s:
                    raise ValueError('bad constant arena reference')
                %(const_name)s = %(const_arena_name)s[%(left_name)s]
            %(consts_name)s.append(%(const_name)s)
        %(tuple_name)s[5] = tuple(%(consts_name)s)
        %(ch_name)s = %(lambda_code_type_name)s(*%(tuple_name)s)
        %(data_arg)s[%(idx_name)s] = %(ch_name)s
        return %(ch_name)s
    %(code_arg)s = %(arena_build_name)s(%(code_arg)s)
%(debug_arena_done)s
    return %(code_arg)s

def %(code_tuple_load_name)s(%(raw_name)s, %(pickle_name)s, %(types_name)s, %(ref_table_name)s=None, %(field_expected_build_name)s=None, %(field_expected_parent_name)s=None, %(fused_map_name)s=None, %(fused_counter_name)s=None, %(fused_per_code_name)s=False):
    %(lambda_code_type_name)s = (lambda: None).func_code.__class__
    %(debug_root_name)s = %(ref_table_name)s is None
%(debug_tuple_begin)s
    %(magic_name)s = %(code_tuple_magic_repr)s
    if isinstance(%(raw_name)s, str) and getattr(%(raw_name)s, %(str_name)s(%(startswith_code)s))(%(magic_name)s):
        %(tuple_name)s = getattr(%(pickle_name)s, %(str_name)s(%(loads_code)s))(%(raw_name)s[len(%(magic_name)s):])
%(debug_tuple_pickle)s
    else:
        %(tuple_name)s = %(raw_name)s
    if isinstance(%(tuple_name)s, tuple) and len(%(tuple_name)s) >= 8 and %(tuple_name)s[0] == %(code_global_arena_magic_repr)s:
        return %(arena_load_name)s(%(tuple_name)s, %(pickle_name)s, %(types_name)s, %(fused_map_name)s, %(fused_counter_name)s, %(fused_per_code_name)s)
    if %(ref_table_name)s is None and isinstance(%(tuple_name)s, tuple) and len(%(tuple_name)s) == 3 and %(tuple_name)s[0] == %(code_ref_table_magic_repr)s:
%(debug_ref_table)s
        %(ref_table_name)s = {}
        for %(ref_row_name)s in %(tuple_name)s[2]:
            try:
                %(ref_table_name)s[%(ref_row_name)s[0]] = (%(ref_row_name)s[1], %(ref_row_name)s[2])
            except Exception:
                pass
        %(tuple_name)s = %(tuple_name)s[1]
    %(tuple_name)s, %(field_build_name)s, %(field_code_name)s, %(field_parent_name)s, %(field_bind_name)s = %(field_object_open_name)s(%(tuple_name)s, %(field_expected_build_name)s, %(field_expected_parent_name)s)
    if isinstance(%(tuple_name)s, tuple) and len(%(tuple_name)s) == 3 and %(tuple_name)s[0] == %(code_tuple_frag_magic_repr)s:
        %(consts_name)s = [None] * %(tuple_name)s[1]
        for %(ref_row_name)s in %(tuple_name)s[2]:
            %(ref_row_name)s = %(frag_provider_name)s(%(ref_row_name)s)
            if not (isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 2 and isinstance(%(ref_row_name)s[1], tuple)):
                continue
            %(seed_name)s = %(ref_row_name)s[0]
            for %(order_item_name)s in %(ref_row_name)s[1]:
                if (%(order_item_name)s[0] ^ %(seed_name)s) < len(%(consts_name)s):
                    %(consts_name)s[%(order_item_name)s[0] ^ %(seed_name)s] = %(order_item_name)s[1]
        %(tuple_name)s = tuple(%(consts_name)s)
    if isinstance(%(tuple_name)s, tuple) and len(%(tuple_name)s) == 3 and %(tuple_name)s[0] == %(code_tuple_shuffle_magic_repr)s:
%(debug_tuple_shuffle)s
        %(src_name)s = %(tuple_name)s[2]
        if isinstance(%(src_name)s, tuple) and len(%(src_name)s) == 3 and %(src_name)s[0] == %(code_tuple_frag_magic_repr)s:
            %(consts_name)s = [None] * %(src_name)s[1]
            for %(ref_row_name)s in %(src_name)s[2]:
                %(ref_row_name)s = %(frag_provider_name)s(%(ref_row_name)s)
                if not (isinstance(%(ref_row_name)s, tuple) and len(%(ref_row_name)s) >= 2 and isinstance(%(ref_row_name)s[1], tuple)):
                    continue
                %(seed_name)s = %(ref_row_name)s[0]
                for %(order_item_name)s in %(ref_row_name)s[1]:
                    if (%(order_item_name)s[0] ^ %(seed_name)s) < len(%(consts_name)s):
                        %(consts_name)s[%(order_item_name)s[0] ^ %(seed_name)s] = %(order_item_name)s[1]
            %(src_name)s = tuple(%(consts_name)s)
        %(src_name)s = list(%(src_name)s)
        %(consts_name)s = [None] * len(%(src_name)s)
        for %(pos_name)s, %(order_item_name)s in enumerate(%(tuple_name)s[1]):
            %(consts_name)s[%(order_item_name)s] = %(src_name)s[%(pos_name)s]
        %(tuple_name)s = tuple(%(consts_name)s)
    if %(field_build_name)s is not None:
        %(tuple_name)s = %(field_materialize_name)s(%(tuple_name)s, %(field_build_name)s, %(field_code_name)s, %(field_parent_name)s)
    %(tuple_name)s = list(%(tuple_name)s)
    %(tuple_name)s[4] = %(fused_bytes_name)s(%(code_bytes_join_name)s(%(tuple_name)s[4]), %(fused_map_name)s, %(fused_counter_name)s, %(fused_per_code_name)s)
    %(consts_name)s = []
    for %(const_name)s in %(tuple_name)s[5]:
        if isinstance(%(const_name)s, tuple) and len(%(const_name)s) == 3 and %(const_name)s[0] == %(code_ref_table_magic_repr)s and %(ref_table_name)s is not None:
            try:
                %(ref_row_name)s = %(ref_table_name)s[%(const_name)s[1]]
                %(const_name)s = getattr(%(pickle_name)s, %(str_name)s(%(loads_code)s))(%(code_ref_xor_name)s(%(ref_row_name)s[1], %(ref_row_name)s[0]))
                %(const_name)s = %(code_tuple_load_name)s(%(const_name)s, %(pickle_name)s, %(types_name)s, %(ref_table_name)s, %(field_build_name)s, %(field_code_name)s, %(fused_map_name)s, %(fused_counter_name)s, %(fused_per_code_name)s)
            except Exception:
                pass
        elif isinstance(%(const_name)s, tuple) and len(%(const_name)s) == 4 and %(const_name)s[0] == %(code_ref_mask_magic_repr)s and %(ref_table_name)s is not None:
            try:
                %(ref_row_name)s = %(ref_table_name)s[%(const_name)s[2] ^ %(const_name)s[1]]
                %(const_name)s = getattr(%(pickle_name)s, %(str_name)s(%(loads_code)s))(%(code_ref_xor_name)s(%(ref_row_name)s[1], %(ref_row_name)s[0]))
                %(const_name)s = %(code_tuple_load_name)s(%(const_name)s, %(pickle_name)s, %(types_name)s, %(ref_table_name)s, %(field_build_name)s, %(field_code_name)s, %(fused_map_name)s, %(fused_counter_name)s, %(fused_per_code_name)s)
            except Exception:
                pass
        elif isinstance(%(const_name)s, str) and getattr(%(const_name)s, %(str_name)s(%(startswith_code)s))(%(magic_name)s):
            try:
                %(const_name)s = %(code_tuple_load_name)s(%(const_name)s, %(pickle_name)s, %(types_name)s, %(ref_table_name)s, %(field_build_name)s, %(field_code_name)s, %(fused_map_name)s, %(fused_counter_name)s, %(fused_per_code_name)s)
            except Exception:
                pass
        %(consts_name)s.append(%(const_name)s)
    %(tuple_name)s[5] = tuple(%(consts_name)s)
    %(code_arg)s = %(lambda_code_type_name)s(*%(tuple_name)s)
%(debug_tuple_complete)s
    return %(code_arg)s
''' % values
