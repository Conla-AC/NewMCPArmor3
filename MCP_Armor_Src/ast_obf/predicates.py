# -*- coding: utf-8 -*-
"""Safe interprocedural predicates for closed same-module call groups."""
from __future__ import absolute_import

import ast
import random

from MCP_Armor_Src.ast_obf.literals import source_docstring_node
from MCP_Armor_Src.utils.encoding import random_ident


def _token_expr(value):
    left = random.randint(1, 0x7fffffff)
    return ast.BinOp(
        left=ast.Num(n=left), op=ast.BitXor(),
        right=ast.Num(n=left ^ int(value)))


class _PredicateDefinitionCollector(ast.NodeVisitor):
    def __init__(self):
        self.classes = []
        self.functions = []
        self.module = {}
        self.methods = {}
        self.count = 0

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        self.generic_visit(node)
        self.classes.pop()

    def visit_FunctionDef(self, node):
        if (getattr(node, '_mcp_source_internal_predicate', False) and
                not self.functions):
            token = random.randint(1, 0x7fffffff)
            hidden = random_ident('flow')
            private = random.randint(1, 0x7fffffff)
            mul = random.randint(0x10001, 0x7fffffff) | 1
            seal = (((token ^ private) * mul) & 0x7fffffff)
            spec = {
                'token': token, 'hidden': hidden, 'private': private,
                'mul': mul, 'seal': seal,
            }
            node._mcp_source_flow_spec = spec
            if self.classes:
                self.methods[(self.classes[-1], node.name)] = spec
            else:
                self.module[node.name] = spec
            self.count += 1
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()


class InternalPredicateTransformer(ast.NodeTransformer):
    def __init__(self, collector):
        self.collector = collector
        self.classes = []
        self.functions = []

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        node = self.generic_visit(node)
        self.classes.pop()
        return node

    def visit_FunctionDef(self, node):
        spec = getattr(node, '_mcp_source_flow_spec', None)
        self.functions.append(node.name)
        node = self.generic_visit(node)
        self.functions.pop()
        if spec is None:
            return node
        node.args.args.append(ast.Name(id=spec['hidden'], ctx=ast.Param()))
        calculated = ast.BinOp(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Name(id=spec['hidden'], ctx=ast.Load()),
                    op=ast.BitXor(), right=ast.Num(n=spec['private'])),
                op=ast.Mult(), right=ast.Num(n=spec['mul'])),
            op=ast.BitAnd(), right=ast.Num(n=0x7fffffff))
        guard = ast.If(
            test=ast.Compare(
                left=calculated, ops=[ast.NotEq()],
                comparators=[ast.Num(n=spec['seal'])]),
            body=[ast.Raise(type=ast.Call(
                func=ast.Name(id='ValueError', ctx=ast.Load()), args=[],
                keywords=[], starargs=None, kwargs=None), inst=None,
                tback=None)], orelse=[])
        doc = source_docstring_node(node.body)
        node.body.insert(1 if doc is not None else 0, guard)
        node._mcp_source_hidden_args = 1
        node._mcp_source_flow_arg = spec['hidden']
        node._mcp_source_flow_token = spec['token']
        return node

    def visit_Call(self, node):
        node = self.generic_visit(node)
        spec = None
        if isinstance(node.func, ast.Name):
            spec = self.collector.module.get(node.func.id)
        elif (isinstance(node.func, ast.Attribute) and self.classes and
              isinstance(node.func.value, ast.Name) and
              node.func.value.id in ('self', 'cls')):
            spec = self.collector.methods.get(
                (self.classes[-1], node.func.attr))
        if spec is None:
            return node
        value = _token_expr(spec['token'])
        if getattr(node, 'starargs', None) is not None or node.keywords:
            node.keywords.append(ast.keyword(arg=spec['hidden'], value=value))
        else:
            node.args.append(value)
        return node


def inject_internal_predicates(tree):
    collector = _PredicateDefinitionCollector()
    collector.visit(tree)
    if not collector.count:
        return tree, 0
    tree = InternalPredicateTransformer(collector).visit(tree)
    ast.fix_missing_locations(tree)
    return tree, collector.count
