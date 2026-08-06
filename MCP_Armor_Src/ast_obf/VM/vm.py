# -*- coding: utf-8 -*-
"""Source VM installation transform."""
from __future__ import absolute_import, print_function

import ast
import base64
import random
import struct
import zlib

from MCP_Armor_Src.ast_obf.dead_flow import (
    SOURCE_VM_OPS,
)

from MCP_Armor_Src.ast_obf.literals import (
    insert_source_string_xor_helpers,
    source_docstring_node,
)

from MCP_Armor_Src.ast_obf.VM.vm_analysis import (
    SourceVMCompiler,
    SourceVMEligibility,
)

from MCP_Armor_Src.ast_obf.VM.vm_runtime import (
    make_source_vm_runtime,
    source_vm_name_matches,
)

from MCP_Armor_Src.utils.encoding import (
    random_ident,
)


class SourceVMTransformer(ast.NodeTransformer):
    def __init__(self, ratio=15, min_ops=8, max_ops=160, max_functions=8,
                 includes=None, excludes=None, allow_loops=False, debug=False,
                 dotzero_relay=False, binary_payload=False,
                 encrypt_names=False, dialect_index=0, dialect_count=1,
                 flow_constants=False, exception_trap_ratio=0):
        self.ratio = max(0, min(100, int(ratio or 0)))
        self.min_ops = max(1, int(min_ops or 1))
        self.max_ops = max(self.min_ops, int(max_ops or self.min_ops))
        self.max_functions = max(0, int(max_functions or 0))
        self.includes = includes or []
        self.excludes = excludes or []
        self.allow_loops = bool(allow_loops)
        self.debug = debug
        self.dotzero_relay = bool(dotzero_relay)
        self.binary_payload = bool(binary_payload)
        self.encrypt_names = bool(encrypt_names)
        self.dialect_index = int(dialect_index or 0)
        self.dialect_count = max(1, int(dialect_count or 1))
        self.flow_constants = bool(flow_constants)
        self.exception_trap_ratio = max(
            0, min(25, int(exception_trap_ratio or 0)))
        self.runner_name = random_ident()
        self.decode_name = random_ident()
        self.namespace_name = random_ident()
        self.sentinel_name = random_ident()
        self.envelope_name = random_ident()
        self.envelope_open_name = random_ident()
        self.capability_name = random_ident()
        self.capability_token = random.randint(1, 0x7fffffff)
        values = []
        used_values = set()
        while len(values) < len(SOURCE_VM_OPS):
            value = random.randint(0x10000000, 0x6fffffff)
            if value not in used_values:
                used_values.add(value)
                values.append(value)
        self.tokens = dict(zip(SOURCE_VM_OPS, values))
        payload_names = ('seed', 'stride', 'mapkey', 'mapping', 'raw',
                         'consts', 'names', 'regcount', 'plans', 'cache',
                         'entry', 'seal', 'blocks', 'exceptions',
                         'single', 'fast', 'compact', 'flow')
        payload_order = list(payload_names)
        random.shuffle(payload_order)
        self.payload_slots = dict((name, index) for index, name in enumerate(payload_order))
        row_order = ['op', 'a', 'b', 'c', 'd', 'e', 'next']
        random.shuffle(row_order)
        self.row_slots = dict((name, index) for index, name in enumerate(row_order))
        self.used_ops = set()
        self.used_virtual_tokens = set([0])
        self.block_specs = []
        self.compact_ops = set()
        self.fused_instruction_count = 0
        self.full_mode = (
            self.ratio >= 100 and self.min_ops <= 1 and
            self.max_ops >= 2000 and self.max_functions == 0)
        self.fused_instruction_budget = 96 if self.full_mode else 768
        self.fused_function_limit = 32 if self.full_mode else 96
        self.total_instruction_count = 0
        self.compact_function_count = 0
        self.fused_function_count = 0
        self.max_register_count = 0
        self.function_depth = 0
        self.payload_statements = []
        self.count = 0

    def eligible_name(self, name, qualname=None, budget=100):
        if self.max_functions and self.count >= self.max_functions:
            return False
        if name.startswith('_mcp_') or source_vm_name_matches(name, self.excludes):
            return False
        if self.includes and not source_vm_name_matches(name, self.includes):
            return False
        identity = qualname or name
        if (sum(ord(ch) for ch in identity) % self.dialect_count !=
                self.dialect_index):
            return False
        effective = max(0, min(100, int(self.ratio * budget / 100)))
        return effective >= 100 or random.randint(1, 100) <= effective

    def encode_payload(self, compiler, flow_token=0, budget=100):
        compact = (len(compiler.instructions) > self.fused_function_limit or
                   self.fused_instruction_count + len(compiler.instructions) >
                   self.fused_instruction_budget)
        if compact:
            self.compact_ops.update(compiler.used_ops)
            self.compact_function_count += 1
        else:
            self.fused_instruction_count += len(compiler.instructions)
            self.fused_function_count += 1
        self.total_instruction_count += len(compiler.instructions)
        self.max_register_count = max(
            self.max_register_count, compiler.next_reg)
        used = list(compiler.used_ops)
        entries = [('real', name, self.tokens[name]) for name in used]
        for index in range(random.randint(2, 6)):
            entries.append(('decoy', index, random.randint(0x10000000, 0x6fffffff)))
        random.shuffle(entries)
        slot_by_op = dict((name, index) for index, (kind, name, token) in enumerate(entries) if kind == 'real')
        seed = random.randint(1, 0x7fffffff)
        stride = random.randint(257, 65535) | 1
        map_key = random.randint(1, 0x7fffffff)
        seal = random.randint(1, 0x7fffffff)
        encoded_map = tuple(token ^ map_key for kind, name, token in entries)
        virtual_tokens = []
        while len(virtual_tokens) < len(compiler.instructions):
            token = random.randint(0x10000, 0x7fffffff)
            if token not in self.used_virtual_tokens:
                self.used_virtual_tokens.add(token)
                virtual_tokens.append(token)

        leaders = set([0])
        controls = set(['JUMP', 'JFALSE', 'JTRUE', 'NEXT', 'RETURN'])
        for index, instruction in enumerate(compiler.instructions):
            op = instruction[0]
            if op not in controls:
                continue
            if index + 1 < len(compiler.instructions):
                leaders.add(index + 1)
            target = None
            if op == 'JUMP':
                target = instruction[1]
            elif op in ('JFALSE', 'JTRUE'):
                target = instruction[2]
            elif op == 'NEXT':
                target = instruction[3]
            if target is not None and 0 <= target < len(compiler.instructions):
                leaders.add(target)
        for index in range(1, len(compiler.instructions)):
            if (compiler.instruction_handlers[index] !=
                    compiler.instruction_handlers[index - 1]):
                leaders.add(index)
        leaders = sorted(leaders)
        flow_seeds = {}
        used_flow_seeds = set()
        for leader in leaders:
            flow_seed = random.randint(1, 0x7fffffff)
            while flow_seed in used_flow_seeds:
                flow_seed = random.randint(1, 0x7fffffff)
            used_flow_seeds.add(flow_seed)
            flow_seeds[leader] = flow_seed
        block_for_pc = {}
        for position, leader in enumerate(leaders):
            end = leaders[position + 1] if position + 1 < len(leaders) else len(compiler.instructions)
            for pc in range(leader, end):
                block_for_pc[pc] = leader

        def virtual_target(index):
            if index < 0 or index >= len(virtual_tokens):
                return 0
            return virtual_tokens[index]

        rows = []
        decoded_instructions = []
        for pc, instruction in enumerate(compiler.instructions):
            operands = list(instruction[1:])
            if instruction[0] == 'JUMP':
                operands[0] = virtual_target(operands[0])
            elif instruction[0] in ('JFALSE', 'JTRUE'):
                operands[1] = virtual_target(operands[1])
            elif instruction[0] == 'NEXT':
                operands[2] = virtual_target(operands[2])
            salt = random.randint(1, 0x7fffffff)
            base = (seed + salt * stride) & 0x7fffffff
            next_token = virtual_target(pc + 1)
            values = [virtual_tokens[pc], slot_by_op[instruction[0]]] + operands + [next_token]
            decoded_instructions.append(tuple([instruction[0]] + operands + [next_token]))
            guard = seal
            for value in values:
                guard = ((guard * 1000003) ^ int(value)) & 0x7fffffff
            values.append(guard)
            row = [salt]
            for field, value in enumerate(values, 1):
                row.append(int(value) ^ ((base + field * 131) & 0x7fffffff))
            if not compact:
                for _ in range(random.randint(0, 3)):
                    row.append(random.randint(-0x7fffffff, 0x7fffffff))
            rows.append(tuple(row))
        random.shuffle(rows)
        payload_blocks = []
        exception_rows = []
        for position, start in enumerate(leaders):
            end = leaders[position + 1] if position + 1 < len(leaders) else len(compiler.instructions)
            instructions = tuple(decoded_instructions[start:end])
            if instructions:
                if not compact:
                    self.block_specs.append((virtual_tokens[start], instructions))
                payload_blocks.append((virtual_tokens[start], tuple(virtual_tokens[start:end])))
                contexts = []
                for context_id in reversed(compiler.instruction_handlers[start]):
                    context = compiler.exception_contexts[context_id]
                    clauses = tuple(
                        (type_reg, virtual_target(handler_start),
                         context['exception_reg'])
                        for type_reg, handler_start in context['clauses'])
                    contexts.append(clauses)
                if contexts:
                    handler_tokens = (virtual_tokens[start:end]
                                      if compact else (virtual_tokens[start],))
                    for handler_token in handler_tokens:
                        exception_rows.append(
                            (handler_token, tuple(contexts)))
        raw_payload = tuple(rows)
        if compact:
            records = []
            for pc, instruction in enumerate(decoded_instructions):
                logical_row = dict(zip(
                    ('a', 'b', 'c', 'd', 'e', 'next'), instruction[1:]))
                logical_row['op'] = self.tokens[instruction[0]]
                physical_row = [0] * len(self.row_slots)
                for field, slot in self.row_slots.items():
                    physical_row[slot] = logical_row[field]
                records.append(struct.pack(
                    '>8i', *([virtual_tokens[pc]] + physical_row)))
            binary = ''.join(records)
            if self.binary_payload:
                # Bytecode loaders already compress and encrypt the enclosing
                # code object, so a second textual encoding only wastes space.
                raw_payload = ('R', binary)
            else:
                binary = zlib.compress(binary, 9)
                binary_key = random.randint(1, 255)
                encrypted = ''.join(chr(ord(value) ^ (
                    (binary_key + index * 131) & 255))
                    for index, value in enumerate(binary))
                raw_payload = ('C', binary_key, base64.b64encode(encrypted))
        stored_constants = tuple(compiler.constants)
        if self.flow_constants and stored_constants:
            const_key = random.randint(1, 0x7fffffff)
            const_sites = {}
            for pc, instruction in enumerate(compiler.instructions):
                if instruction[0] == 'CONST':
                    const_sites[instruction[2]] = flow_seeds[block_for_pc[pc]]
            constant_rows = []
            for index, value in enumerate(stored_constants):
                flow_seed = const_sites.get(index, flow_seeds[leaders[0]])
                key = ((const_key ^ flow_seed ^ (index * 1000003)) &
                       0x7fffffff)
                type_name = type(value).__name__
                if type_name in ('int', 'long') and type_name != 'bool':
                    constant_rows.append(('I', int(value) ^ key))
                elif type_name in ('str', 'unicode'):
                    is_unicode = int(type_name == 'unicode')
                    raw = value.encode('utf-8') if is_unicode else value
                    encoded = tuple(
                        (ord(ch) if not isinstance(ch, int) else ch) ^
                        ((key + offset * 131) & 255)
                        for offset, ch in enumerate(raw))
                    constant_rows.append(('S', is_unicode, encoded))
                else:
                    constant_rows.append(('V', value))
            stored_constants = ('K', const_key, tuple(constant_rows))
        stored_names = tuple(compiler.names)
        if self.encrypt_names and stored_names:
            name_seed = random.randint(1, 0x7fffffff)
            name_step = random.randint(3, 253) | 1
            name_bias = random.randint(1, 255)
            name_drift = random.randint(1, 127) | 1
            name_rows = []
            for name in stored_names:
                mode = random.randint(0, 2)
                site = random.randint(1, 0x7fffffff)
                reverse = random.randint(0, 1)
                raw_name = str(name)
                if reverse:
                    raw_name = raw_name[::-1]
                encoded_name = []
                for index, value in enumerate(raw_name):
                    if mode == 0:
                        key = ((name_seed ^ flow_seeds[leaders[0]]) + site + index * name_step) & 255
                        encoded_name.append(ord(value) ^ key)
                    elif mode == 1:
                        key = ((name_seed ^ flow_seeds[leaders[0]] ^ site) + index * name_step) & 255
                        encoded_name.append((ord(value) + key + name_bias) & 255)
                    else:
                        key = ((name_seed ^ flow_seeds[leaders[0]] ^ site) + index * name_step) & 255
                        encoded_name.append(((ord(value) ^ key) + name_bias +
                                             index * name_drift) & 255)
                name_rows.append(
                    (mode, site, reverse, tuple(encoded_name)))
            stored_names = (
                'N', name_seed, name_step, name_bias, name_drift,
                tuple(name_rows))
        logical = {
            'seed': seed, 'stride': stride, 'mapkey': map_key,
            'mapping': encoded_map, 'raw': raw_payload,
            'consts': stored_constants, 'names': stored_names,
            'regcount': compiler.next_reg, 'plans': tuple(compiler.plans),
            'cache': None, 'entry': virtual_tokens[0], 'seal': seal,
            'blocks': tuple(payload_blocks),
            'exceptions': tuple(exception_rows),
            'single': (len(payload_blocks) == 1 and not exception_rows and
                       not compact),
            'fast': None,
            'compact': compact,
            'flow': (
                int(flow_token or 0) ^ flow_seeds[leaders[0]],
                tuple((virtual_tokens[leader], flow_seeds[leader])
                      for leader in leaders),
                tuple(virtual_tokens[leader] for leader in leaders
                      if budget >= 80 and self.exception_trap_ratio and
                      random.randint(1, 100) <= self.exception_trap_ratio)),
        }
        payload = [None] * len(self.payload_slots)
        for name, index in self.payload_slots.items():
            payload[index] = logical[name]
        return payload

    def visit_FunctionDef(self, node):
        if (getattr(node, '_mcp_source_synthetic', False) or
                getattr(node, '_mcp_source_vm_wrapped', False)):
            return node
        nested = self.function_depth > 0
        self.function_depth += 1
        try:
            self.generic_visit(node)
        finally:
            self.function_depth -= 1
        # A nested function may capture cells from its parent. The standalone
        # VM wrapper has no closure tuple, so preserve it until closure cells
        # are represented explicitly by the VM.
        if nested:
            return node
        selection_name = getattr(node, '_mcp_source_original_name', node.name)
        budget = getattr(node, '_mcp_source_cost_budget', 100)
        if getattr(node, '_mcp_source_hot', False):
            return node
        if not self.eligible_name(
                selection_name,
                getattr(node, '_mcp_source_qualname', selection_name),
                budget):
            return node
        doc = source_docstring_node(node.body)
        doc_statement = node.body[0] if doc is not None else None
        body = node.body[1:] if doc is not None else node.body
        checker = SourceVMEligibility()
        for statement in body:
            checker.visit(statement)
        if (not checker.ok or (checker.has_loop and not self.allow_loops) or
                checker.node_count < self.min_ops or checker.node_count > self.max_ops):
            return node
        try:
            compiler = SourceVMCompiler(node).compile(body)
        except (ValueError, KeyError, TypeError):
            return node
        if len(compiler.instructions) > self.max_ops:
            return node
        self.used_ops.update(compiler.used_ops)
        payload_name = random_ident()
        payload = self.encode_payload(
            compiler, getattr(node, '_mcp_source_flow_token', 0), budget)
        mirror = []
        for index in range(len(payload)):
            if index == self.payload_slots['entry']:
                mirror.append(random.randint(0x10000, 0x7fffffff))
            elif index in (self.payload_slots['cache'], self.payload_slots['fast']):
                mirror.append(None)
            else:
                mirror.append(random.randint(-0x7fffffff, 0x7fffffff))
        statement = ast.parse('%s = %s(%r, %r, %s)\n' % (
            payload_name, self.envelope_name, payload, mirror,
            self.capability_name)).body[0]
        self.payload_statements.append(statement)
        args = [ast.Name(id=item.id, ctx=ast.Load()) for item in node.args.args]
        if node.args.vararg:
            args.append(ast.Name(id=node.args.vararg, ctx=ast.Load()))
        if node.args.kwarg:
            args.append(ast.Name(id=node.args.kwarg, ctx=ast.Load()))
        flow_arg = getattr(node, '_mcp_source_flow_arg', None)
        flow_value = (ast.Name(id=flow_arg, ctx=ast.Load())
                      if flow_arg else ast.Num(n=0))
        call = ast.Call(
            func=ast.Name(id=self.runner_name, ctx=ast.Load()),
            args=[ast.Name(id=payload_name, ctx=ast.Load()),
                  ast.Tuple(elts=args, ctx=ast.Load()), flow_value],
            keywords=[], starargs=None, kwargs=None)
        unwrap = ast.If(
            test=ast.Compare(
                left=ast.Attribute(
                    value=ast.Name(id=payload_name, ctx=ast.Load()),
                    attr='__class__', ctx=ast.Load()),
                ops=[ast.Is()],
                comparators=[ast.Name(id=self.envelope_name, ctx=ast.Load())]),
            body=[ast.Assign(
                targets=[ast.Name(id=payload_name, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id=payload_name, ctx=ast.Load()),
                        attr=self.envelope_open_name, ctx=ast.Load()),
                    args=[ast.Name(id=self.capability_name, ctx=ast.Load())],
                    keywords=[], starargs=None, kwargs=None))],
            orelse=[])
        replacement = ast.Return(value=call)
        node.body = ([doc_statement] if doc_statement is not None else []) + [
            ast.Global(names=[payload_name]), unwrap, replacement]
        node._mcp_source_vm_wrapped = True
        self.count += 1
        return node

    def finish(self, tree):
        if not self.count:
            return tree
        helpers = make_source_vm_runtime(
            self.tokens, self.block_specs, self.runner_name, self.decode_name,
            self.namespace_name, self.sentinel_name, self.payload_slots,
            self.row_slots, self.envelope_name, self.envelope_open_name,
            self.capability_name, self.capability_token, self.debug,
            self.dotzero_relay, self.compact_ops)
        insert_source_string_xor_helpers(tree, helpers + self.payload_statements)
        if self.debug:
            print('[DEBUG] AST VM functions=%d instructions=%d fused=%d compact=%d max_regs=%d' % (
                self.count, self.total_instruction_count,
                self.fused_function_count, self.compact_function_count,
                self.max_register_count))
        ast.fix_missing_locations(tree)
        return tree


def virtualize_source_functions(tree, ratio=15, min_ops=8, max_ops=160,
                                max_functions=8, includes=None, excludes=None,
                                allow_loops=False, debug=False,
                                dotzero_relay=False, binary_payload=False,
                                encrypt_names=False, dialects=1,
                                flow_constants=False,
                                exception_trap_ratio=0):
    dialects = max(1, min(8, int(dialects or 1)))
    total = 0
    remaining = max_functions
    for index in range(dialects):
        if max_functions:
            slots = max(0, remaining)
            if not slots:
                break
        else:
            slots = 0
        transformer = SourceVMTransformer(
            ratio, min_ops, max_ops, slots, includes, excludes,
            allow_loops, debug, dotzero_relay, binary_payload, encrypt_names,
            index, dialects, flow_constants, exception_trap_ratio)
        tree = transformer.visit(tree)
        tree = transformer.finish(tree)
        total += transformer.count
        if max_functions:
            remaining -= transformer.count
    return tree, total
