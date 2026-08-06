# -*- coding: utf-8 -*-
"""Generated register-VM runtime source."""
from __future__ import absolute_import, print_function

import ast
import fnmatch
import random

from MCP_Armor_Src.utils.encoding import (
    random_ident,
)


def source_vm_name_matches(name, patterns):
    for pattern in patterns or []:
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


def _source_vm_indent(text, width=4):
    prefix = ' ' * width
    return '\n'.join(prefix + line if line else line for line in text.splitlines())


def _source_vm_handler_source(op, name, row_slots, namespace_name,
                              sentinel_name, shift_name, arg_names=None):
    r, x, k, n, p, f = (arg_names or
                         [random_ident() for _ in range(6)])
    a, b, c = row_slots['a'], row_slots['b'], row_slots['c']
    d, e = row_slots['d'], row_slots['e']
    values = {
        'r': r, 'x': x, 'k': k, 'n': n, 'p': p, 'f': f,
        'A': a, 'B': b, 'C': c, 'D': d, 'E': e,
        'namespace': namespace_name, 'sentinel': sentinel_name,
        'shift': shift_name,
    }
    bodies = {
        'CONST': '''%(const_index)s = %(x)s[%(B)d]
%(const_value)s = %(k)s[1][%(const_index)s] if isinstance(%(k)s, list) else %(k)s[%(const_index)s]
if isinstance(%(k)s, list) and isinstance(%(const_value)s, tuple) and %(const_value)s:
    %(const_key)s = (%(k)s[0] ^ %(f)s ^ (%(const_index)s * 1000003)) & 2147483647
    if %(const_value)s[0] == 'I':
        %(const_value)s = %(const_value)s[1] ^ %(const_key)s
    elif %(const_value)s[0] == 'S':
        %(const_value)s = ''.join(chr(%(byte)s ^ ((%(const_key)s + %(offset)s * 131) & 255)) for %(offset)s, %(byte)s in enumerate(%(const_value)s[2]))
        if %(k)s[1][%(const_index)s][1]:
            %(const_value)s = %(const_value)s.decode('utf-8')
    elif %(const_value)s[0] == 'V':
        %(const_value)s = %(const_value)s[1]
    %(k)s[1][%(const_index)s] = %(const_value)s
%(r)s[%(x)s[%(A)d]] = %(const_value)s''',
        'MOVE': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]',
        'LOCAL': '''if %(r)s[%(x)s[%(B)d]] is %(sentinel)s:
    raise UnboundLocalError("local variable '%%s' referenced before assignment" %% %(n)s[%(x)s[%(C)d]])
%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]''',
        'GLOBAL': '''%(name)s = %(n)s[%(x)s[%(B)d]]
try:
    %(r)s[%(x)s[%(A)d]] = %(namespace)s[%(name)s]
except KeyError:
    %(builtins)s = %(namespace)s.get('__builtins__', __builtins__)
    try:
        if isinstance(%(builtins)s, dict):
            %(r)s[%(x)s[%(A)d]] = %(builtins)s[%(name)s]
        else:
            %(r)s[%(x)s[%(A)d]] = getattr(%(builtins)s, %(name)s)
    except (KeyError, AttributeError):
        raise NameError("global name '%%s' is not defined" %% %(name)s)''',
        'ADD': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] + %(r)s[%(x)s[%(C)d]]',
        'SUB': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] - %(r)s[%(x)s[%(C)d]]',
        'MUL': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] * %(r)s[%(x)s[%(C)d]]',
        'DIV': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] / %(r)s[%(x)s[%(C)d]]',
        'FLOORDIV': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] // %(r)s[%(x)s[%(C)d]]',
        'MOD': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] %% %(r)s[%(x)s[%(C)d]]',
        'POW': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] ** %(r)s[%(x)s[%(C)d]]',
        'LSHIFT': '%(r)s[%(x)s[%(A)d]] = %(shift)s(%(r)s[%(x)s[%(B)d]], %(r)s[%(x)s[%(C)d]], 1)',
        'RSHIFT': '%(r)s[%(x)s[%(A)d]] = %(shift)s(%(r)s[%(x)s[%(B)d]], %(r)s[%(x)s[%(C)d]], 0)',
        'BITOR': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] | %(r)s[%(x)s[%(C)d]]',
        'BITXOR': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] ^ %(r)s[%(x)s[%(C)d]]',
        'BITAND': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] & %(r)s[%(x)s[%(C)d]]',
        'IADD': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] += %(r)s[%(x)s[%(C)d]]',
        'ISUB': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] -= %(r)s[%(x)s[%(C)d]]',
        'IMUL': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] *= %(r)s[%(x)s[%(C)d]]',
        'IDIV': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] /= %(r)s[%(x)s[%(C)d]]',
        'IFLOORDIV': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] //= %(r)s[%(x)s[%(C)d]]',
        'IMOD': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] %%= %(r)s[%(x)s[%(C)d]]',
        'IPOW': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] **= %(r)s[%(x)s[%(C)d]]',
        'ILSHIFT': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] <<= %(r)s[%(x)s[%(C)d]]',
        'IRSHIFT': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] >>= %(r)s[%(x)s[%(C)d]]',
        'IBITOR': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] |= %(r)s[%(x)s[%(C)d]]',
        'IBITXOR': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] ^= %(r)s[%(x)s[%(C)d]]',
        'IBITAND': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]]\n%(r)s[%(x)s[%(A)d]] &= %(r)s[%(x)s[%(C)d]]',
        'UADD': '%(r)s[%(x)s[%(A)d]] = +%(r)s[%(x)s[%(B)d]]',
        'USUB': '%(r)s[%(x)s[%(A)d]] = -%(r)s[%(x)s[%(B)d]]',
        'NOT': '%(r)s[%(x)s[%(A)d]] = not %(r)s[%(x)s[%(B)d]]',
        'INVERT': '%(r)s[%(x)s[%(A)d]] = ~%(r)s[%(x)s[%(B)d]]',
        'ATTR': '%(r)s[%(x)s[%(A)d]] = getattr(%(r)s[%(x)s[%(B)d]], %(n)s[%(x)s[%(C)d]])',
        'SUBSCR': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]][%(r)s[%(x)s[%(C)d]]]',
        'CALL': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]](*[%(r)s[%(value)s] for %(value)s in %(p)s[%(x)s[%(C)d]]])',
        'CALL_EX': '''%(plan)s = %(p)s[%(x)s[%(C)d]]
%(args)s = [%(r)s[%(value)s] for %(value)s in %(plan)s[0]]
%(kwargs)s = dict((%(n)s[%(plan)s[1][%(value)s]], %(r)s[%(plan)s[1][%(value)s + 1]]) for %(value)s in range(0, len(%(plan)s[1]), 2))
if %(plan)s[2] >= 0:
    %(args)s.extend(%(r)s[%(plan)s[2]])
if %(plan)s[3] >= 0:
    %(kwargs)s.update(%(r)s[%(plan)s[3]])
%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]](*%(args)s, **%(kwargs)s)''',
        'LIST': '%(r)s[%(x)s[%(A)d]] = [%(r)s[%(value)s] for %(value)s in %(p)s[%(x)s[%(B)d]]]',
        'TUPLE': '%(r)s[%(x)s[%(A)d]] = tuple([%(r)s[%(value)s] for %(value)s in %(p)s[%(x)s[%(B)d]]])',
        'SET': '%(r)s[%(x)s[%(A)d]] = set([%(r)s[%(value)s] for %(value)s in %(p)s[%(x)s[%(B)d]]])',
        'APPEND': '%(r)s[%(x)s[%(A)d]].append(%(r)s[%(x)s[%(B)d]])',
        'SLICE': '''%(lower)s = None if %(x)s[%(B)d] < 0 else %(r)s[%(x)s[%(B)d]]
%(upper)s = None if %(x)s[%(C)d] < 0 else %(r)s[%(x)s[%(C)d]]
%(step)s = None if %(x)s[%(D)d] < 0 else %(r)s[%(x)s[%(D)d]]
%(r)s[%(x)s[%(A)d]] = slice(%(lower)s, %(upper)s, %(step)s)''',
        'DICT': '''%(plan)s = %(p)s[%(x)s[%(B)d]]
%(r)s[%(x)s[%(A)d]] = dict((%(r)s[%(plan)s[%(value)s]], %(r)s[%(plan)s[%(value)s + 1]]) for %(value)s in range(0, len(%(plan)s), 2))''',
        'STORE_ATTR': 'setattr(%(r)s[%(x)s[%(A)d]], %(n)s[%(x)s[%(B)d]], %(r)s[%(x)s[%(C)d]])',
        'STORE_SUBSCR': '%(r)s[%(x)s[%(A)d]][%(r)s[%(x)s[%(B)d]]] = %(r)s[%(x)s[%(C)d]]',
        'STORE_GLOBAL': '%(namespace)s[%(n)s[%(x)s[%(A)d]]] = %(r)s[%(x)s[%(B)d]]',
        'DELETE_LOCAL': '''if %(r)s[%(x)s[%(A)d]] is %(sentinel)s:
    raise UnboundLocalError("local variable '%%s' referenced before assignment" %% %(n)s[%(x)s[%(B)d]])
%(r)s[%(x)s[%(A)d]] = %(sentinel)s''',
        'DELETE_GLOBAL': '''%(name)s = %(n)s[%(x)s[%(A)d]]
try:
    del %(namespace)s[%(name)s]
except KeyError:
    raise NameError("global name '%%s' is not defined" %% %(name)s)''',
        'DELETE_ATTR': 'delattr(%(r)s[%(x)s[%(A)d]], %(n)s[%(x)s[%(B)d]])',
        'DELETE_SUBSCR': 'del %(r)s[%(x)s[%(A)d]][%(r)s[%(x)s[%(B)d]]]',
        'ASSERT': '''if not %(r)s[%(x)s[%(A)d]]:
    if %(x)s[%(B)d] < 0:
        raise AssertionError()
    raise AssertionError(%(r)s[%(x)s[%(B)d]])''',
        'RAISE': 'raise %(r)s[%(x)s[%(A)d]]',
        'UNPACK': '''%(plan)s = %(p)s[%(x)s[%(B)d]]
%(items)s = list(%(r)s[%(x)s[%(A)d]])
if len(%(items)s) != len(%(plan)s):
    raise ValueError()
for %(index)s, %(value)s in enumerate(%(plan)s):
    %(r)s[%(value)s] = %(items)s[%(index)s]''',
        'ITER': '%(r)s[%(x)s[%(A)d]] = iter(%(r)s[%(x)s[%(B)d]])',
        'NEXT': '''try:
    %(r)s[%(x)s[%(A)d]] = next(%(r)s[%(x)s[%(B)d]])
except StopIteration:
    return (0, %(x)s[%(C)d])''',
        'LT': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] < %(r)s[%(x)s[%(C)d]]',
        'LE': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] <= %(r)s[%(x)s[%(C)d]]',
        'EQ': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] == %(r)s[%(x)s[%(C)d]]',
        'NE': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] != %(r)s[%(x)s[%(C)d]]',
        'GT': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] > %(r)s[%(x)s[%(C)d]]',
        'GE': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] >= %(r)s[%(x)s[%(C)d]]',
        'IS': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] is %(r)s[%(x)s[%(C)d]]',
        'ISNOT': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] is not %(r)s[%(x)s[%(C)d]]',
        'IN': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] in %(r)s[%(x)s[%(C)d]]',
        'NOTIN': '%(r)s[%(x)s[%(A)d]] = %(r)s[%(x)s[%(B)d]] not in %(r)s[%(x)s[%(C)d]]',
        'JUMP': 'return (0, %(x)s[%(A)d])',
        'JFALSE': '''if not %(r)s[%(x)s[%(A)d]]:
    return (0, %(x)s[%(B)d])''',
        'JTRUE': '''if %(r)s[%(x)s[%(A)d]]:
    return (0, %(x)s[%(B)d])''',
        'RETURN': 'return (1, %(r)s[%(x)s[%(A)d]])',
    }
    extra = {}
    for key in ('name', 'builtins', 'plan', 'args', 'kwargs', 'value',
                'items', 'index', 'lower', 'upper', 'step', 'const_index',
                'const_value', 'const_key', 'byte', 'offset'):
        extra[key] = random_ident()
    values.update(extra)
    body = bodies[op] % values
    return 'def %s(%s, %s, %s, %s, %s, %s):\n%s\n' % (
        name, r, x, k, n, p, f, _source_vm_indent(body))


class _SourceVMRowBinder(ast.NodeTransformer):
    def __init__(self, row_name, physical_values):
        self.row_name = row_name
        self.physical_values = physical_values

    def visit_Subscript(self, node):
        node = self.generic_visit(node)
        if (isinstance(node.value, ast.Name) and node.value.id == self.row_name and
                isinstance(node.slice, ast.Index) and
                isinstance(node.slice.value, ast.Num)):
            index = int(node.slice.value.n)
            return ast.copy_location(ast.Num(n=self.physical_values[index]), node)
        return node


def _source_vm_block_handler(name, instructions, row_slots, namespace_name,
                             sentinel_name, shift_name):
    regs, consts, names, plans, flow, row = [random_ident() for _ in range(6)]
    shell = ast.parse('def %s(%s, %s, %s, %s, %s):\n    pass\n' % (
        name, regs, consts, names, plans, flow)).body[0]
    body = []
    last_next = 0
    for instruction in instructions:
        op = instruction[0]
        logical = dict(zip(('a', 'b', 'c', 'd', 'e', 'next'), instruction[1:]))
        logical['op'] = 0
        physical = [None] * len(row_slots)
        for key, index in row_slots.items():
            physical[index] = logical[key]
        operation = ast.parse(_source_vm_handler_source(
            op, random_ident(), row_slots, namespace_name, sentinel_name,
            shift_name, (regs, row, consts, names, plans, flow))).body[0]
        binder = _SourceVMRowBinder(row, physical)
        body.extend([binder.visit(statement) for statement in operation.body])
        last_next = instruction[6]
    body.append(ast.Return(value=ast.Tuple(
        elts=[ast.Num(n=0), ast.Num(n=last_next)], ctx=ast.Load())))
    shell.body = body
    shell._mcp_source_synthetic = True
    return shell


def _source_vm_compact_handler(name, operations, tokens, row_slots,
                               namespace_name, sentinel_name, shift_name):
    statements = []
    pairs = []
    for operation_name in sorted(operations):
        handler_name = random_ident()
        operation = ast.parse(_source_vm_handler_source(
            operation_name, handler_name, row_slots, namespace_name,
            sentinel_name, shift_name)).body[0]
        operation._mcp_source_synthetic = True
        statements.append(operation)
        pairs.append((tokens[operation_name], handler_name))
    random.shuffle(statements)
    mapping = ast.Dict(
        keys=[ast.Num(n=token) for token, handler in pairs],
        values=[ast.Name(id=handler, ctx=ast.Load())
                for token, handler in pairs])
    assignment = ast.Assign(
        targets=[ast.Name(id=name, ctx=ast.Store())], value=mapping)
    statements.append(assignment)
    return statements


def make_source_vm_runtime(tokens, block_specs, runner_name, decode_name,
                           namespace_name, sentinel_name, payload_slots,
                           row_slots, envelope_name, envelope_open_name,
                           capability_name, capability_token, debug=False,
                           dotzero_relay=False, compact_ops=None):
    shift_name = random_ident()
    table_name = random_ident()
    table_key_name = random_ident()
    table_key = random.randint(1, 0x7fffffff)
    route_name = random_ident()
    route_cache_name = random_ident()
    route_mask = random.randint(1, 0x7fffffff)
    descriptor_name = random_ident()
    provider_base_name = random_ident()
    provider_field_name = random_ident()
    provider_gate_name = random_ident()
    semantic_name = random_ident()
    semantic_left = random.randint(1, 0x7fffffff)
    semantic_right = random.randint(1, 0x7fffffff)
    semantic_mask = capability_token ^ semantic_left ^ semantic_right
    compact_handler_name = random_ident()

    logical_rows = {
        'op': '(%(mapping)s[%(slot)s] ^ %(mapkey)s)',
        'a': '%(values)s[2]', 'b': '%(values)s[3]',
        'c': '%(values)s[4]', 'd': '%(values)s[5]',
        'e': '%(values)s[6]', 'next': '%(values)s[7]',
    }
    physical_rows = [None] * len(row_slots)
    for logical, physical in row_slots.items():
        physical_rows[physical] = logical_rows[logical]
    row_tuple = ', '.join(physical_rows)

    names = {}
    for key in ('left', 'right', 'mode', 'method', 'reflected', 'result',
                'payload', 'rows', 'seed', 'stride', 'mapkey', 'mapping',
                'raw', 'row', 'base', 'values', 'field', 'slot', 'guard',
                'part', 'argv', 'code', 'regs', 'index', 'value', 'consts',
                'names', 'plans', 'pc', 'reply', 'blocks', 'plan', 'token',
                'block', 'fast', 'candidate', 'expected', 'opened',
                'mirror', 'owner', 'instance', 'real', 'decoy', 'gate',
                'key', 'sequence', 'handlers', 'error', 'contexts',
                'context', 'clause', 'matched', 'binary', 'rawkey',
                 'offset', 'packed', 'name_rows', 'name_row', 'name_mode',
                 'name_out', 'name_chars', 'name_site', 'name_seed',
                 'name_step', 'name_bias', 'name_drift', 'flow',
                 'flow_info', 'flow_map', 'flow_source', 'flow_target',
                 'traps', 'const_rows'):
        names[key] = random_ident()
    values = dict(names)
    values.update({
        'namespace': namespace_name, 'sentinel': sentinel_name,
        'decode': decode_name, 'runner': runner_name, 'shift': shift_name,
        'table': table_name, 'table_key_name': table_key_name,
        'route': route_name, 'route_cache': route_cache_name,
        'step': compact_handler_name,
        'route_mask': route_mask,
        'envelope': envelope_name, 'envelope_open': envelope_open_name,
        'capability': capability_name, 'descriptor': descriptor_name,
        'provider_base': provider_base_name,
        'provider_field': provider_field_name,
        'provider_gate': provider_gate_name,
        'semantic': semantic_name, 'semantic_left': semantic_left,
        'semantic_right': semantic_right, 'semantic_mask': semantic_mask,
        'P_SEED': payload_slots['seed'], 'P_STRIDE': payload_slots['stride'],
        'P_MAPKEY': payload_slots['mapkey'], 'P_MAPPING': payload_slots['mapping'],
        'P_RAW': payload_slots['raw'], 'P_CONSTS': payload_slots['consts'],
        'P_NAMES': payload_slots['names'], 'P_REGCOUNT': payload_slots['regcount'],
        'P_PLANS': payload_slots['plans'], 'P_CACHE': payload_slots['cache'],
        'P_ENTRY': payload_slots['entry'], 'P_SEAL': payload_slots['seal'],
        'P_BLOCKS': payload_slots['blocks'],
        'P_EXCEPTIONS': payload_slots['exceptions'],
        'P_COMPACT': payload_slots['compact'],
        'P_SINGLE': payload_slots['single'], 'P_FAST': payload_slots['fast'],
        'P_FLOW': payload_slots['flow'],
        'R_OP': row_slots['op'], 'R_NEXT': row_slots['next'],
    })
    values['row_tuple'] = row_tuple % values
    source = r'''
%(namespace)s = globals()
%(sentinel)s = object()

class %(envelope)s(object):
    __slots__ = ('%(real)s', '%(mirror)s', '%(key)s', '%(opened)s')
    def __init__(self, %(real)s, %(mirror)s, %(key)s):
        self.%(real)s = %(real)s
        self.%(mirror)s = %(mirror)s
        self.%(key)s = %(key)s
        self.%(opened)s = False
    def %(envelope_open)s(self, %(key)s):
        if %(key)s != self.%(key)s:
            raise KeyError()
        if not self.%(opened)s:
            self.%(opened)s = True
            self.%(mirror)s = ()
        return self.%(real)s
    def __len__(self):
        return len(self.%(mirror)s)
    def __iter__(self):
        return iter(self.%(mirror)s)
    def __getitem__(self, %(key)s):
        return self.%(mirror)s[%(key)s]
    def __setitem__(self, %(key)s, %(value)s):
        raise TypeError()
    def __repr__(self):
        return repr(self.%(mirror)s)

class %(descriptor)s(object):
    def __get__(self, %(instance)s, %(owner)s):
        if %(instance)s is None:
            return self
        if %(instance)s.%(provider_gate)s == %(instance)s.%(key)s:
            return %(instance)s.%(real)s
        return %(instance)s.%(decoy)s
    def __repr__(self):
        return "<member 'f_code' of 'frame' objects>"

class %(provider_base)s(object):
    __slots__ = ('%(real)s', '%(decoy)s', '%(provider_gate)s', '%(key)s')
    %(provider_field)s = %(descriptor)s()
    def __init__(self, %(real)s, %(decoy)s, %(gate)s, %(key)s):
        self.%(real)s = %(real)s
        self.%(decoy)s = %(decoy)s
        self.%(provider_gate)s = %(gate)s
        self.%(key)s = %(key)s

def %(semantic)s(%(left)s, %(right)s, %(key)s):
    try:
        if %(left)s == %(right)s:
            return %(key)s ^ 1431655765
        raise LookupError()
    except LookupError:
        return %(key)s ^ 858993459
    finally:
        return %(left)s ^ %(right)s ^ %(key)s

%(capability)s = %(semantic)s(%(semantic_left)d, %(semantic_right)d, %(semantic_mask)d)

def %(shift)s(%(left)s, %(right)s, %(mode)s):
    if %(mode)s:
        %(method)s, %(reflected)s = ''.join([chr(%(value)s) for %(value)s in (95, 95, 108, 115, 104, 105, 102, 116, 95, 95)]), ''.join([chr(%(value)s) for %(value)s in (95, 95, 114, 108, 115, 104, 105, 102, 116, 95, 95)])
    else:
        %(method)s, %(reflected)s = ''.join([chr(%(value)s) for %(value)s in (95, 95, 114, 115, 104, 105, 102, 116, 95, 95)]), ''.join([chr(%(value)s) for %(value)s in (95, 95, 114, 114, 115, 104, 105, 102, 116, 95, 95)])
    try:
        %(result)s = getattr(%(left)s, %(method)s)(%(right)s)
    except AttributeError:
        %(result)s = NotImplemented
    if %(result)s is not NotImplemented:
        return %(result)s
    try:
        %(result)s = getattr(%(right)s, %(reflected)s)(%(left)s)
    except AttributeError:
        raise TypeError()
    if %(result)s is NotImplemented:
        raise TypeError()
    return %(result)s

def %(route)s(%(token)s):
    %(key)s = %(token)s ^ %(table_key_name)s
    try:
        return %(route_cache)s[%(key)s]
    except KeyError:
        pass
    %(expected)s = ((%(key)s * 1103515245) + %(route_mask)d) & 2147483647
    for %(candidate)s in %(table)s[%(key)s]:
        if len(%(candidate)s) == 3 and ((%(candidate)s[0] ^ %(candidate)s[2]) & 2147483647) == %(expected)s:
            %(real)s = getattr(%(candidate)s[1], '%(provider_field)s')
            %(route_cache)s[%(key)s] = %(real)s
            return %(real)s
    raise KeyError()

def %(decode)s(%(payload)s, %(flow)s):
    %(rows)s = {}
    %(seed)s, %(stride)s = %(payload)s[%(P_SEED)d], %(payload)s[%(P_STRIDE)d]
    %(mapkey)s, %(mapping)s = %(payload)s[%(P_MAPKEY)d], %(payload)s[%(P_MAPPING)d]
    %(raw)s, %(guard)s = %(payload)s[%(P_RAW)d], %(payload)s[%(P_SEAL)d]
    %(packed)s = False
    if isinstance(%(raw)s, tuple) and len(%(raw)s) == 2 and %(raw)s[0] == 'R':
        %(binary)s = %(raw)s[1]
        if len(%(binary)s) %% 32:
            raise ValueError()
        %(raw)s = tuple(__import__('struct').unpack('>8i', %(binary)s[%(offset)s:%(offset)s + 32]) for %(offset)s in range(0, len(%(binary)s), 32))
        %(packed)s = True
    elif isinstance(%(raw)s, tuple) and len(%(raw)s) == 2 and %(raw)s[0] == 'Z':
        %(binary)s = __import__('zlib').decompress(%(raw)s[1])
        if len(%(binary)s) %% 32:
            raise ValueError()
        %(raw)s = tuple(__import__('struct').unpack('>8i', %(binary)s[%(offset)s:%(offset)s + 32]) for %(offset)s in range(0, len(%(binary)s), 32))
        %(packed)s = True
    elif isinstance(%(raw)s, tuple) and len(%(raw)s) == 3 and %(raw)s[0] == 'C':
        %(rawkey)s = %(raw)s[1]
        %(binary)s = __import__('base64').b64decode(%(raw)s[2])
        %(binary)s = ''.join(chr(ord(%(value)s) ^ ((%(rawkey)s + %(index)s * 131) & 255)) for %(index)s, %(value)s in enumerate(%(binary)s))
        %(binary)s = __import__('zlib').decompress(%(binary)s)
        if len(%(binary)s) %% 32:
            raise ValueError()
        %(raw)s = tuple(__import__('struct').unpack('>8i', %(binary)s[%(offset)s:%(offset)s + 32]) for %(offset)s in range(0, len(%(binary)s), 32))
        %(packed)s = True
    elif isinstance(%(raw)s, tuple) and len(%(raw)s) == 2 and isinstance(%(raw)s[1], str):
        %(rawkey)s = %(raw)s[0]
        %(binary)s = __import__('base64').b64decode(%(raw)s[1])
        %(binary)s = ''.join(chr(ord(%(value)s) ^ ((%(rawkey)s + %(index)s * 131) & 255)) for %(index)s, %(value)s in enumerate(%(binary)s))
        if len(%(binary)s) %% 40:
            raise ValueError()
        %(raw)s = tuple(__import__('struct').unpack('>10i', %(binary)s[%(offset)s:%(offset)s + 40]) for %(offset)s in range(0, len(%(binary)s), 40))
    if %(packed)s:
        for %(row)s in %(raw)s:
            %(rows)s[%(row)s[0]] = tuple(%(row)s[1:])
    else:
        for %(row)s in %(raw)s:
            %(base)s = (%(seed)s + %(row)s[0] * %(stride)s) & 2147483647
            %(values)s = []
            for %(field)s in range(1, 10):
                %(values)s.append(%(row)s[%(field)s] ^ ((%(base)s + %(field)s * 131) & 2147483647))
            %(part)s = %(guard)s
            for %(value)s in %(values)s[:8]:
                %(part)s = ((%(part)s * 1000003) ^ %(value)s) & 2147483647
            if %(part)s != %(values)s[8]:
                raise ValueError()
            %(slot)s = %(values)s[1]
            %(rows)s[%(values)s[0]] = (%(row_tuple)s)
    %(name_rows)s = %(payload)s[%(P_NAMES)d]
    if (isinstance(%(name_rows)s, tuple) and len(%(name_rows)s) == 6 and
            %(name_rows)s[0] == 'N'):
        %(name_seed)s, %(name_step)s = %(name_rows)s[1], %(name_rows)s[2]
        %(name_bias)s, %(name_drift)s = %(name_rows)s[3], %(name_rows)s[4]
        %(name_out)s = []
        for %(name_row)s in %(name_rows)s[5]:
            %(name_mode)s, %(name_site)s = %(name_row)s[0], %(name_row)s[1]
            %(name_chars)s = []
            for %(index)s, %(value)s in enumerate(%(name_row)s[3]):
                if %(name_mode)s == 0:
                    %(value)s = %(value)s ^ (((%(name_seed)s ^ %(flow)s) + %(name_site)s + %(index)s * %(name_step)s) & 255)
                elif %(name_mode)s == 1:
                    %(value)s = (%(value)s - (((%(name_seed)s ^ %(flow)s ^ %(name_site)s) + %(index)s * %(name_step)s) & 255) - %(name_bias)s) & 255
                else:
                    %(value)s = ((%(value)s - %(name_bias)s - %(index)s * %(name_drift)s) & 255) ^ (((%(name_seed)s ^ %(flow)s ^ %(name_site)s) + %(index)s * %(name_step)s) & 255)
                %(name_chars)s.append(chr(%(value)s))
            %(value)s = ''.join(%(name_chars)s)
            if %(name_row)s[2]:
                %(value)s = %(value)s[::-1]
            %(name_out)s.append(%(value)s)
        %(payload)s[%(P_NAMES)d] = tuple(%(name_out)s)
    %(const_rows)s = %(payload)s[%(P_CONSTS)d]
    if (isinstance(%(const_rows)s, tuple) and len(%(const_rows)s) == 3 and
            %(const_rows)s[0] == 'K'):
        %(payload)s[%(P_CONSTS)d] = [%(const_rows)s[1], list(%(const_rows)s[2])]
    for %(plan)s in %(payload)s[%(P_BLOCKS)d]:
        for %(token)s in %(plan)s[1]:
            if %(token)s not in %(rows)s:
                raise ValueError()
    if %(payload)s[%(P_COMPACT)d]:
        for %(token)s, %(row)s in %(rows)s.items():
            %(values)s = list(%(row)s)
            %(values)s[%(R_OP)d] = %(step)s[%(values)s[%(R_OP)d]]
            %(rows)s[%(token)s] = tuple(%(values)s)
    %(payload)s[%(P_CACHE)d] = %(rows)s
    if %(payload)s[%(P_SINGLE)d]:
        %(payload)s[%(P_FAST)d] = %(route)s(%(payload)s[%(P_ENTRY)d])
    %(payload)s[%(P_SEED)d] = None
    %(payload)s[%(P_STRIDE)d] = None
    %(payload)s[%(P_MAPKEY)d] = None
    %(payload)s[%(P_MAPPING)d] = None
    %(payload)s[%(P_RAW)d] = None
    %(payload)s[%(P_SEAL)d] = None
    %(payload)s[%(P_BLOCKS)d] = None
    return True
''' % values
    if dotzero_relay:
        direct = '%s(%d, %d, %d)' % (
            semantic_name, semantic_left, semantic_right, semantic_mask)
        relay = ('%s = tuple((%s for %s in (%s,)))[0]' % (
            capability_name, names['value'], names['value'], direct))
        source = source.replace(
            '%s = %s' % (capability_name, direct), relay, 1)

    handler_statements = []
    compact_assignment = None
    if compact_ops:
        compact_statements = _source_vm_compact_handler(
            compact_handler_name, compact_ops, tokens, row_slots,
            namespace_name, sentinel_name, shift_name)
        handler_statements.extend(compact_statements[:-1])
        compact_assignment = compact_statements[-1]
    pairs = []
    for entry_token, instructions in block_specs:
        handler_name = random_ident()
        handler_statements.append(_source_vm_block_handler(
            handler_name, instructions, row_slots, namespace_name, sentinel_name,
            shift_name))
        pairs.append((entry_token ^ table_key, handler_name))
    random.shuffle(handler_statements)
    if compact_assignment is not None:
        handler_statements.append(compact_assignment)
    random.shuffle(pairs)
    source += '\n%s = %d\n%s = {}\n%s = {}\n' % (
        table_key_name, table_key, table_name, route_cache_name)
    handler_names = [handler for key, handler in pairs]
    # Each real handler is hidden behind a per-entry descriptor and a shuffled
    # provider row.  Row selection is structural (shape/seal), never positional.
    for key, handler in pairs:
        expected = ((key * 1103515245) + route_mask) & 0x7fffffff
        provider_name = random_ident()
        gate = random.randint(1, 0x7fffffff)
        decoy_handler = random.choice(handler_names)
        source += "%s = %s(%s, %s, %d, %d)\n" % (
            provider_name, provider_base_name, handler, decoy_handler,
            gate, gate)
        real_left = random.randint(1, 0x7fffffff)
        real_right = real_left ^ expected
        candidates = ['(%d, %s, %d)' % (real_left, provider_name, real_right)]
        for _ in range(random.randint(2, 4)):
            fake_provider = random_ident()
            fake_gate = random.randint(1, 0x7fffffff)
            fake_handler = random.choice(handler_names)
            source += "%s = %s(%s, %s, %d, %d)\n" % (
                fake_provider, provider_base_name, fake_handler, handler,
                fake_gate, fake_gate ^ 1)
            fake_left = random.randint(1, 0x7fffffff)
            fake_right = random.randint(1, 0x7fffffff)
            while ((fake_left ^ fake_right) & 0x7fffffff) == expected:
                fake_right = random.randint(1, 0x7fffffff)
            candidates.append('(%d, %s, %d)' % (
                fake_left, fake_provider, fake_right))
        random.shuffle(candidates)
        source += '%s[%d] = [%s]\n' % (
            table_name, key, ', '.join(candidates))

    # Dead generator/comprehension code objects deliberately carry the hidden
    # iterator local named .0 in Python 2.7.  They are never called at runtime.
    for _ in range(random.randint(2, 4)):
        poison_name = random_ident()
        poison_arg = random_ident()
        poison_item = random_ident()
        poison_mask = random.randint(1, 0x7fffffff)
        source += ('def %s(%s):\n'
                   '    try:\n'
                   '        return tuple(((%s ^ %d) for %s in %s if (%s != %s)))\n'
                   '    finally:\n'
                   '        pass\n') % (
            poison_name, poison_arg, poison_item, poison_mask, poison_item,
            poison_arg, poison_item, poison_item)

    runner_values = dict(values)
    source += r'''
def %(runner)s(%(payload)s, %(argv)s, %(gate)s):
    %(flow_info)s = %(payload)s[%(P_FLOW)d]
    %(flow_map)s = dict(%(flow_info)s[1])
    %(traps)s = set(%(flow_info)s[2])
    %(flow)s = %(gate)s ^ %(flow_info)s[0]
    %(flow_source)s = %(flow_map)s[%(payload)s[%(P_ENTRY)d]]
    if %(flow)s != %(flow_source)s:
        raise ValueError()
    %(code)s = %(payload)s[%(P_CACHE)d]
    if %(code)s is None:
        %(decode)s(%(payload)s, %(flow)s)
        %(code)s = %(payload)s[%(P_CACHE)d]
    %(regs)s = [%(sentinel)s] * %(payload)s[%(P_REGCOUNT)d]
    for %(index)s, %(value)s in enumerate(%(argv)s):
        %(regs)s[%(index)s] = %(value)s
    %(consts)s = %(payload)s[%(P_CONSTS)d]
    %(names)s = %(payload)s[%(P_NAMES)d]
    %(plans)s = %(payload)s[%(P_PLANS)d]
    %(fast)s = %(payload)s[%(P_FAST)d]
    if %(fast)s is not None:
        return %(fast)s(%(regs)s, %(consts)s, %(names)s, %(plans)s, %(flow)s)[1]
    %(pc)s = %(payload)s[%(P_ENTRY)d]
    %(handlers)s = %(payload)s[%(P_EXCEPTIONS)d]
    if %(payload)s[%(P_COMPACT)d]:
        if not %(handlers)s:
            while %(pc)s:
                if %(pc)s in %(flow_map)s:
                    %(expected)s = %(flow_map)s[%(pc)s]
                    if %(flow)s != %(expected)s:
                        if %(pc)s in %(traps)s:
                            try:
                                raise LookupError()
                            except LookupError:
                                raise ValueError()
                        raise ValueError()
                    %(flow_source)s = %(expected)s
                %(row)s = %(code)s[%(pc)s]
                %(reply)s = %(row)s[%(R_OP)d](%(regs)s, %(row)s, %(consts)s, %(names)s, %(plans)s, %(flow)s)
                if %(reply)s is not None:
                    if %(reply)s[0]:
                        return %(reply)s[1]
                    %(pc)s = %(reply)s[1]
                else:
                    %(pc)s = %(row)s[%(R_NEXT)d]
                if %(pc)s in %(flow_map)s:
                    %(flow_target)s = %(flow_map)s[%(pc)s]
                    %(flow)s = %(flow)s ^ %(flow_source)s ^ %(flow_target)s
                    %(flow_source)s = %(flow_target)s
            return None
        %(handlers)s = dict(%(handlers)s)
        while %(pc)s:
            if %(pc)s in %(flow_map)s:
                %(expected)s = %(flow_map)s[%(pc)s]
                if %(flow)s != %(expected)s:
                    if %(pc)s in %(traps)s:
                        try:
                            raise LookupError()
                        except LookupError:
                            raise ValueError()
                    raise ValueError()
                %(flow_source)s = %(expected)s
            %(row)s = %(code)s[%(pc)s]
            try:
                %(reply)s = %(row)s[%(R_OP)d](%(regs)s, %(row)s, %(consts)s, %(names)s, %(plans)s, %(flow)s)
            except BaseException as %(error)s:
                %(matched)s = False
                for %(context)s in %(handlers)s.get(%(pc)s, ()):
                    for %(clause)s in %(context)s:
                        if %(clause)s[0] < 0 or isinstance(%(error)s, %(regs)s[%(clause)s[0]]):
                            %(regs)s[%(clause)s[2]] = %(error)s
                            %(pc)s = %(clause)s[1]
                            %(matched)s = True
                            break
                    if %(matched)s:
                        break
                if not %(matched)s:
                    raise
                if %(pc)s in %(flow_map)s:
                    %(flow_target)s = %(flow_map)s[%(pc)s]
                    %(flow)s = %(flow)s ^ %(flow_source)s ^ %(flow_target)s
                    %(flow_source)s = %(flow_target)s
                continue
            if %(reply)s is not None:
                if %(reply)s[0]:
                    return %(reply)s[1]
                %(pc)s = %(reply)s[1]
            else:
                %(pc)s = %(row)s[%(R_NEXT)d]
            if %(pc)s in %(flow_map)s:
                %(flow_target)s = %(flow_map)s[%(pc)s]
                %(flow)s = %(flow)s ^ %(flow_source)s ^ %(flow_target)s
                %(flow_source)s = %(flow_target)s
        return None
    if %(handlers)s:
        %(handlers)s = dict(%(handlers)s)
        while %(pc)s:
            if %(pc)s in %(flow_map)s:
                %(expected)s = %(flow_map)s[%(pc)s]
                if %(flow)s != %(expected)s:
                    if %(pc)s in %(traps)s:
                        try:
                            raise LookupError()
                        except LookupError:
                            raise ValueError()
                    raise ValueError()
                %(flow_source)s = %(expected)s
            try:
                %(reply)s = %(route)s(%(pc)s)(%(regs)s, %(consts)s, %(names)s, %(plans)s, %(flow)s)
            except BaseException as %(error)s:
                %(matched)s = False
                for %(context)s in %(handlers)s.get(%(pc)s, ()):
                    for %(clause)s in %(context)s:
                        if %(clause)s[0] < 0 or isinstance(%(error)s, %(regs)s[%(clause)s[0]]):
                            %(regs)s[%(clause)s[2]] = %(error)s
                            %(pc)s = %(clause)s[1]
                            %(matched)s = True
                            break
                    if %(matched)s:
                        break
                if not %(matched)s:
                    raise
                if %(pc)s in %(flow_map)s:
                    %(flow_target)s = %(flow_map)s[%(pc)s]
                    %(flow)s = %(flow)s ^ %(flow_source)s ^ %(flow_target)s
                    %(flow_source)s = %(flow_target)s
                continue
            if %(reply)s[0]:
                return %(reply)s[1]
            %(pc)s = %(reply)s[1]
            if %(pc)s in %(flow_map)s:
                %(flow_target)s = %(flow_map)s[%(pc)s]
                %(flow)s = %(flow)s ^ %(flow_source)s ^ %(flow_target)s
                %(flow_source)s = %(flow_target)s
        return None
    while %(pc)s:
        if %(pc)s in %(flow_map)s:
            %(expected)s = %(flow_map)s[%(pc)s]
            if %(flow)s != %(expected)s:
                if %(pc)s in %(traps)s:
                    try:
                        raise LookupError()
                    except LookupError:
                        raise ValueError()
                raise ValueError()
            %(flow_source)s = %(expected)s
        %(reply)s = %(route)s(%(pc)s)(%(regs)s, %(consts)s, %(names)s, %(plans)s, %(flow)s)
        if %(reply)s[0]:
            return %(reply)s[1]
        %(pc)s = %(reply)s[1]
        if %(pc)s in %(flow_map)s:
            %(flow_target)s = %(flow_map)s[%(pc)s]
            %(flow)s = %(flow)s ^ %(flow_source)s ^ %(flow_target)s
            %(flow_source)s = %(flow_target)s
    return None
''' % runner_values
    statements = ast.parse(source).body
    insert_at = len(statements)
    for index, statement in enumerate(statements):
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id == table_key_name:
                    insert_at = index
                    break
    statements[insert_at:insert_at] = handler_statements
    if debug:
        statements.append(ast.parse("print('[DEBUG] AST Virtual Runtime Loaded')\n").body[0])
    for statement in statements:
        for child in ast.walk(statement):
            if isinstance(child, (ast.FunctionDef, ast.ClassDef)):
                child._mcp_source_synthetic = True
    return statements
