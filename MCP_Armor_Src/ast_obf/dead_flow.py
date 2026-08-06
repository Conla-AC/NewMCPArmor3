# -*- coding: utf-8 -*-
"""Source comment noise and unreachable-flow injection."""
from __future__ import absolute_import, print_function

import ast
import random

from MCP_Armor_Src.utils.encoding import (
    random_ident,
)


def add_source_comment_noise(source, count=2):
    lines = source.splitlines()
    if not lines or count <= 0:
        return source
    inserts = min(max(0, int(count)), 16)
    positions = [idx for idx, line in enumerate(lines) if line and not line.startswith(' ')]
    random.shuffle(positions)
    for pos in sorted(positions[:inserts], reverse=True):
        lines.insert(pos, '# %s' % random_ident('note'))
    return '\n'.join(lines) + ('\n' if source.endswith('\n') else '')


def make_source_dead_test():
    seed = random.randint(0x1000, 0x7fffffff)
    return ast.Compare(left=ast.Num(n=seed), ops=[ast.NotEq()], comparators=[ast.Num(n=seed)])


def make_source_dead_value(label):
    # These records are never consumed; keeping semantic labels such as
    # ``dead-flow``/``loop`` only gives static scanners a free signature.
    # Use the same identifier alphabet as the rest of the generated source.
    marker = random_ident('flow')
    return ast.Dict(
        keys=[ast.Str(s=random_ident('key')), ast.Str(s=random_ident('key')), ast.Str(s=random_ident('key'))],
        values=[
            ast.Str(s=marker),
            ast.Num(n=random.randint(0x10000, 0x7fffffff)),
            ast.Tuple(elts=[
                ast.Num(n=random.randint(1, 999)),
                ast.Str(s=random_ident('df'))], ctx=ast.Load()),
        ],
    )


def make_source_dead_flow_stmt():
    slot = random_ident('df')
    shadow = random_ident('df')
    marker = random_ident('df')
    inner_true = [
        ast.Assign(targets=[ast.Name(id=shadow, ctx=ast.Store())], value=make_source_dead_value('branch')),
        ast.For(
            target=ast.Name(id=marker, ctx=ast.Store()),
            iter=ast.Tuple(elts=[
                ast.Num(n=random.randint(3, 31)),
                ast.Num(n=random.randint(32, 127))],
                ctx=ast.Load()),
            body=[
                ast.Assign(
                    targets=[ast.Name(id=shadow, ctx=ast.Store())],
                    value=make_source_dead_value('loop'),
                )
            ],
            orelse=[],
        ),
    ]
    inner_false = [
        ast.Assign(
            targets=[ast.Name(id=shadow, ctx=ast.Store())],
            value=make_source_dead_value('else'),
        )
    ]
    node = ast.If(
        test=make_source_dead_test(),
        body=[
            ast.Assign(targets=[ast.Name(id=slot, ctx=ast.Store())], value=make_source_dead_value('dead-flow')),
            ast.If(
                test=ast.Compare(
                    left=ast.Num(n=1), ops=[ast.Eq()],
                    comparators=[ast.Num(n=1)]),
                body=inner_true,
                orelse=inner_false,
            ),
        ],
        orelse=[],
    )
    node._mcp_source_dead_flow = True
    return node


class SourceDeadFlowInjector(ast.NodeTransformer):
    def __init__(self, blocks=1):
        self.blocks = max(0, min(4, int(blocks or 0)))

    def _docstring_offset(self, body):
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Str):
            return 1
        return 0

    def _inject_body(self, body, local_blocks=None):
        if self.blocks <= 0 or not body:
            return body
        count = self.blocks if local_blocks is None else max(0, min(self.blocks, int(local_blocks or 0)))
        if count <= 0:
            return body
        output = list(body)
        start = self._docstring_offset(output)
        for _ in range(count):
            stmt = make_source_dead_flow_stmt()
            if output:
                ast.copy_location(stmt, output[min(start, len(output) - 1)])
            insert_at = start
            if len(output) > start:
                insert_at = random.randint(start, len(output))
            output.insert(insert_at, stmt)
        return output

    def visit_Module(self, node):
        self.generic_visit(node)
        offset = self._docstring_offset(node.body)
        while (offset < len(node.body) and
               isinstance(node.body[offset], ast.ImportFrom) and
               node.body[offset].module == '__future__'):
            offset += 1
        node.body = (node.body[:offset] +
                     self._inject_body(node.body[offset:], 1))
        return node

    def visit_ClassDef(self, node):
        self.generic_visit(node)
        node.body = self._inject_body(node.body, 1)
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if getattr(node, 'decorator_list', None):
            return node
        node.body = self._inject_body(node.body, self.blocks)
        return node


def inject_source_dead_flow(tree, blocks=1):
    tree = SourceDeadFlowInjector(blocks).visit(tree)
    ast.fix_missing_locations(tree)
    return tree


SOURCE_VM_OPS = (
    'CONST', 'GLOBAL', 'LOCAL', 'MOVE', 'ATTR', 'SUBSCR', 'CALL',
    'LIST', 'TUPLE', 'DICT', 'APPEND', 'STORE_ATTR', 'STORE_SUBSCR', 'UNPACK',
    'ITER', 'NEXT', 'CALL_EX', 'SET', 'SLICE',
    'STORE_GLOBAL', 'DELETE_LOCAL', 'DELETE_GLOBAL',
    'DELETE_ATTR', 'DELETE_SUBSCR', 'ASSERT', 'RAISE',
    'ADD', 'SUB', 'MUL', 'DIV', 'FLOORDIV', 'MOD', 'POW',
    'LSHIFT', 'RSHIFT', 'BITOR', 'BITXOR', 'BITAND',
    'UADD', 'USUB', 'NOT', 'INVERT',
    'IADD', 'ISUB', 'IMUL', 'IDIV', 'IFLOORDIV', 'IMOD', 'IPOW',
    'ILSHIFT', 'IRSHIFT', 'IBITOR', 'IBITXOR', 'IBITAND',
    'LT', 'LE', 'EQ', 'NE', 'GT', 'GE', 'IS', 'ISNOT', 'IN', 'NOTIN',
    'JUMP', 'JFALSE', 'JTRUE', 'RETURN',
)


SOURCE_VM_BINOPS = {
    ast.Add: 'ADD', ast.Sub: 'SUB', ast.Mult: 'MUL', ast.Div: 'DIV',
    ast.FloorDiv: 'FLOORDIV', ast.Mod: 'MOD', ast.Pow: 'POW',
    ast.LShift: 'LSHIFT', ast.RShift: 'RSHIFT', ast.BitOr: 'BITOR',
    ast.BitXor: 'BITXOR', ast.BitAnd: 'BITAND',
}


SOURCE_VM_UNARYOPS = {
    ast.UAdd: 'UADD', ast.USub: 'USUB', ast.Not: 'NOT', ast.Invert: 'INVERT',
}


SOURCE_VM_INPLACEOPS = {
    ast.Add: 'IADD', ast.Sub: 'ISUB', ast.Mult: 'IMUL', ast.Div: 'IDIV',
    ast.FloorDiv: 'IFLOORDIV', ast.Mod: 'IMOD', ast.Pow: 'IPOW',
    ast.LShift: 'ILSHIFT', ast.RShift: 'IRSHIFT', ast.BitOr: 'IBITOR',
    ast.BitXor: 'IBITXOR', ast.BitAnd: 'IBITAND',
}


SOURCE_VM_CMPOPS = {
    ast.Lt: 'LT', ast.LtE: 'LE', ast.Eq: 'EQ', ast.NotEq: 'NE',
    ast.Gt: 'GT', ast.GtE: 'GE', ast.Is: 'IS', ast.IsNot: 'ISNOT',
    ast.In: 'IN', ast.NotIn: 'NOTIN',
}
