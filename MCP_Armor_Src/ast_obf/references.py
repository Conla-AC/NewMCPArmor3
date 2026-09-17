# -*- coding: utf-8 -*-
"""Polymorphic encrypted attribute and method reference rewriting."""
from __future__ import absolute_import

import ast
import fnmatch
import random

from MCP_Armor_Src.utils.encoding import random_ident
from MCP_Armor_Src.ast_obf.literals import insert_source_string_xor_helpers


LOGICAL_ARGS = ('owner', 'row', 'site', 'seal', 'noise', 'flow')


class ReferenceVariant(object):
    def __init__(self, mode):
        self.mode = int(mode)
        self.helper_name = random_ident('ref')
        self.seed = random.randint(1, 0x7fffffff)
        self.step = random.randint(3, 253) | 1
        self.bias = random.randint(1, 255)
        self.drift = random.randint(1, 127) | 1
        self.seal_mul = random.randint(0x10001, 0x7fffffff) | 1
        self.seal_bias = random.randint(1, 0x7fffffff)
        self.reverse = bool(random.getrandbits(1))
        self.arg_order = list(LOGICAL_ARGS)
        random.shuffle(self.arg_order)

    def key_byte(self, site, index, flow=0):
        seed = self.seed ^ int(flow or 0)
        if self.mode == 0:
            return (seed + site + index * self.step) & 255
        return ((seed ^ site) + index * self.step) & 255

    def encode(self, name, site, noise, flow=0):
        raw = name.encode('utf-8')
        if self.reverse:
            raw = raw[::-1]
        values = []
        for index, value in enumerate(raw):
            byte = ord(value)
            key = self.key_byte(site, index, flow)
            if self.mode == 0:
                encoded = byte ^ key
            elif self.mode == 1:
                encoded = (byte + key + self.bias) & 255
            else:
                encoded = ((byte ^ key) + self.bias +
                           index * self.drift) & 255
            values.append(encoded)
        seal = ((site * self.seal_mul) ^ self.seed ^ int(flow or 0) ^
                (len(values) * self.seal_bias) ^ noise) & 0x7fffffff
        return tuple(values), seal

    def call(self, owner, name, flow_node=None, flow_token=0):
        site = random.randint(1, 0x7fffffff)
        noise = random.randint(1, 0x7fffffff)
        encoded, seal = self.encode(name, site, noise, flow_token)
        logical = {
            'owner': owner,
            'row': ast.Tuple(
                elts=[ast.Num(n=value) for value in encoded], ctx=ast.Load()),
            'site': ast.Num(n=site),
            'seal': ast.Num(n=seal),
            'noise': ast.Num(n=noise),
            'flow': flow_node or ast.Num(n=0),
        }
        return ast.Call(
            func=ast.Name(id=self.helper_name, ctx=ast.Load()),
            args=[logical[name] for name in self.arg_order],
            keywords=[], starargs=None, kwargs=None)


class SourceReferenceObfuscator(ast.NodeTransformer):
    def __init__(self, variants, ratio=35, excludes=None, bind_flow=False):
        self.variants = list(variants)
        self.ratio = max(0, min(100, int(ratio or 0)))
        self.excludes = list(excludes or ())
        self.count = 0
        self.bind_flow = bool(bind_flow)
        self.flow_stack = []
        self.budget_stack = []

    def visit_FunctionDef(self, node):
        if (getattr(node, '_mcp_source_synthetic', False) or
                getattr(node, '_mcp_source_vm_wrapped', False)):
            return node
        flow_arg = (getattr(node, '_mcp_source_flow_arg', None)
                    if self.bind_flow else None)
        flow_token = (getattr(node, '_mcp_source_flow_token', 0)
                      if flow_arg else 0)
        self.flow_stack.append((flow_arg, flow_token))
        self.budget_stack.append(
            getattr(node, '_mcp_source_cost_budget', 100))
        try:
            return self.generic_visit(node)
        finally:
            self.flow_stack.pop()
            self.budget_stack.pop()

    def excluded(self, name):
        # ``obj.__private`` is compiled as ``obj._ClassName__private`` inside
        # a class body. Replacing it with getattr(obj, '__private') bypasses
        # name mangling and changes runtime behavior. Keep both private and
        # magic double-underscore attributes direct.
        if name.startswith('__'):
            return True
        return any(fnmatch.fnmatch(name, pattern)
                   for pattern in self.excludes)

    def visit_Attribute(self, node):
        node.value = self.visit(node.value)
        budget = self.budget_stack[-1] if self.budget_stack else 100
        effective_ratio = int(self.ratio * budget / 100)
        if (not isinstance(node.ctx, ast.Load) or self.excluded(node.attr) or
                random.randint(1, 100) > effective_ratio):
            return node
        flow_arg, flow_token = self.flow_stack[-1] if self.flow_stack else (None, 0)
        flow_node = (ast.Name(id=flow_arg, ctx=ast.Load())
                     if flow_arg else ast.Num(n=0))
        replacement = random.choice(self.variants).call(
            node.value, node.attr, flow_node, flow_token)
        self.count += 1
        return ast.copy_location(replacement, node)


def _variant_names(variant):
    return dict((logical, random_ident(logical[:2]))
                for logical in LOGICAL_ARGS)


def _decode_expression(variant, names):
    row = names['row']
    site = names['site']
    flow = names['flow']
    index = random_ident('index')
    value = random_ident('value')
    if variant.mode == 0:
        expression = (
            'chr(%(value)s ^ (((%(seed)d ^ %(flow)s) + %(site)s + '
            '%(index)s * %(step)d) & 255))')
    elif variant.mode == 1:
        expression = (
            'chr((%(value)s - (((%(seed)d ^ %(flow)s ^ %(site)s) + '
            '%(index)s * %(step)d) & 255) - %(bias)d) & 255)')
    else:
        expression = (
            'chr(((%(value)s - %(bias)d - %(index)s * %(drift)d) & 255) '
            '^ (((%(seed)d ^ %(flow)s ^ %(site)s) + %(index)s * %(step)d) & 255))')
    values = {
        'value': value, 'index': index, 'site': site,
        'seed': variant.seed, 'step': variant.step, 'flow': flow,
        'bias': variant.bias, 'drift': variant.drift,
    }
    return expression % values, index, value, row


def _reference_helper(variant):
    names = _variant_names(variant)
    params = [names[name] for name in variant.arg_order]
    cache = random_ident('cache')
    token = random_ident('token')
    decoded = random_ident('decoded')
    expression, index, value, row = _decode_expression(variant, names)
    chars = random_ident('chars')
    seal_expr = (
        '((%(site)s * %(mul)d) ^ %(seed)d ^ %(flow)s ^ '
        '(len(%(row)s) * %(bias)d) ^ %(noise)s) & 0x7fffffff') % {
            'site': names['site'], 'mul': variant.seal_mul,
            'seed': variant.seed, 'row': row,
            'bias': variant.seal_bias, 'noise': names['noise'],
            'flow': names['flow'],
        }
    reverse = '[::-1]' if variant.reverse else ''
    if variant.mode == 0:
        body = (
            '    %(token)s = (%(row)s, %(site)s, %(noise)s, %(flow)s)\n'
            '    try:\n'
            '        %(decoded)s = %(cache)s[%(token)s]\n'
            '    except KeyError:\n'
            '        %(chars)s = []\n'
            '        for %(index)s, %(value)s in enumerate(%(row)s):\n'
            '            %(chars)s.append(%(expr)s)\n'
            "        %(decoded)s = ''.join(%(chars)s)%(reverse)s\n"
            '        %(cache)s[%(token)s] = %(decoded)s\n')
    elif variant.mode == 1:
        body = (
            '    %(token)s = (%(site)s, %(noise)s, %(row)s, %(flow)s)\n'
            '    %(decoded)s = %(cache)s.get(%(token)s)\n'
            '    if %(decoded)s is None:\n'
            '        %(chars)s = []\n'
            '        %(index)s = 0\n'
            '        while %(index)s < len(%(row)s):\n'
            '            %(value)s = %(row)s[%(index)s]\n'
            '            %(chars)s.append(%(expr)s)\n'
            '            %(index)s += 1\n'
            "        %(decoded)s = ''.join(%(chars)s)%(reverse)s\n"
            '        %(cache)s[%(token)s] = %(decoded)s\n')
    else:
        body = (
            '    %(token)s = (%(noise)s, %(row)s, %(site)s, %(flow)s)\n'
            '    if %(token)s not in %(cache)s:\n'
            '        %(chars)s = []\n'
            '        for %(index)s, %(value)s in enumerate(%(row)s):\n'
            '            %(chars)s.append(%(expr)s)\n'
            "        %(decoded)s = ''.join(%(chars)s)%(reverse)s\n"
            '        %(cache)s[%(token)s] = %(decoded)s\n'
            '    %(decoded)s = %(cache)s[%(token)s]\n')
    values = dict(names)
    values.update({
        'helper': variant.helper_name, 'params': ', '.join(params),
        'cache': cache, 'token': token, 'decoded': decoded,
        'expr': expression, 'index': index, 'value': value, 'row': row,
        'reverse': reverse, 'chars': chars,
    })
    source = (
        'def %(helper)s(%(params)s, %(cache)s={}):\n'
        '    if %(seal)s != %(seal_expr)s:\n'
        '        raise ValueError()\n'
        '%(body)s'
        '    return getattr(%(owner)s, %(decoded)s)\n'
    ) % dict(values, seal_expr=seal_expr, body=(body % values))
    statement = ast.parse(source).body[0]
    statement._mcp_source_synthetic = True
    return statement


def obfuscate_source_references(tree, ratio=35, excludes=None, variants=3,
                                bind_flow=False):
    variant_count = max(2, min(6, int(variants or 3)))
    modes = [index % 3 for index in range(variant_count)]
    random.shuffle(modes)
    pool = [ReferenceVariant(mode) for mode in modes]
    transformer = SourceReferenceObfuscator(
        pool, ratio, excludes, bind_flow)
    tree = transformer.visit(tree)
    if transformer.count:
        helpers = [_reference_helper(variant) for variant in pool]
        random.shuffle(helpers)
        tree = insert_source_string_xor_helpers(tree, helpers)
    ast.fix_missing_locations(tree)
    # Helpers are parsed independently and inserted into an existing tree;
    # Python 2.7 requires coordinates on every nested expression.
    def repair(node, line=1, col=0):
        if not isinstance(node, ast.AST):
            return
        current_line = getattr(node, 'lineno', None) or line
        current_col = getattr(node, 'col_offset', None)
        if current_col is None:
            current_col = col
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.stmt, ast.expr)):
                if getattr(child, 'lineno', None) is None:
                    child.lineno = current_line
                if getattr(child, 'col_offset', None) is None:
                    child.col_offset = current_col
            repair(child, current_line, current_col)
    repair(tree)
    ast.fix_missing_locations(tree)
    return tree, transformer.count
