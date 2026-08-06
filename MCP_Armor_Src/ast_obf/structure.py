# -*- coding: utf-8 -*-
"""Call linearization, source rendering and scheduling transforms."""
from __future__ import absolute_import, print_function

import ast
import random

from MCP_Armor_Src.utils.encoding import (
    random_ident,
)


class SourceLinearizeExpression(object):
    def __init__(self, temp_func):
        self.prefix = []
        self.temp_func = temp_func

    def _temp_name(self):
        return self.temp_func()

    def _store_temp(self, value, template):
        name = self._temp_name()
        assign = ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=value)
        self.prefix.append(ast.copy_location(assign, template))
        return ast.copy_location(ast.Name(id=name, ctx=ast.Load()), template)

    def _linearize_list(self, values):
        return [self.linearize(value) for value in values]

    def linearize(self, node):
        if node is None:
            return None
        if isinstance(node, ast.Call):
            func = self.linearize(node.func)
            args = self._linearize_list(node.args)
            keywords = []
            for keyword in node.keywords:
                keywords.append(ast.keyword(arg=keyword.arg, value=self.linearize(keyword.value)))
            starargs = self.linearize(node.starargs) if getattr(node, 'starargs', None) is not None else None
            kwargs = self.linearize(node.kwargs) if getattr(node, 'kwargs', None) is not None else None
            call = ast.Call(func=func, args=args, keywords=keywords, starargs=starargs, kwargs=kwargs)
            return self._store_temp(ast.copy_location(call, node), node)
        if isinstance(node, ast.Attribute):
            value = self.linearize(node.value)
            attr = ast.Attribute(value=value, attr=node.attr, ctx=ast.Load())
            return self._store_temp(ast.copy_location(attr, node), node)
        if isinstance(node, ast.BoolOp):
            return node
        if isinstance(node, ast.BinOp):
            node.left = self.linearize(node.left)
            node.right = self.linearize(node.right)
            return node
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1:
                return node
            node.left = self.linearize(node.left)
            node.comparators = self._linearize_list(node.comparators)
            return node
        if isinstance(node, ast.UnaryOp):
            node.operand = self.linearize(node.operand)
            return node
        if isinstance(node, ast.IfExp):
            return node
        if isinstance(node, ast.List):
            node.elts = self._linearize_list(node.elts)
            return node
        if isinstance(node, ast.Tuple):
            node.elts = self._linearize_list(node.elts)
            return node
        if isinstance(node, ast.Dict):
            return node
        return node


class SourceCallLinearizer(ast.NodeTransformer):
    def __init__(self):
        self.counter = random.randint(100, 999)

    def _temp_name(self):
        self.counter += 1
        # Keep source-level linearization temporaries indistinguishable from
        # other generated locals; the old _mcp_lz prefix leaked implementation
        # details to static scanners.
        return random_ident()

    def _linearize_expr(self, expr):
        linearizer = SourceLinearizeExpression(self._temp_name)
        expr = linearizer.linearize(expr)
        return linearizer.prefix, expr

    def _linearize_body(self, body):
        output = []
        for stmt in body:
            output.extend(self._linearize_stmt(stmt))
        return output

    def _linearize_stmt(self, stmt):
        if isinstance(stmt, ast.Assign):
            prefix, value = self._linearize_expr(stmt.value)
            stmt.value = value
            return prefix + [stmt]
        if isinstance(stmt, ast.AugAssign):
            prefix, value = self._linearize_expr(stmt.value)
            stmt.value = value
            return prefix + [stmt]
        if isinstance(stmt, ast.Expr):
            original = stmt.value
            prefix, value = self._linearize_expr(stmt.value)
            if prefix and isinstance(original, (ast.Call, ast.Attribute)):
                return prefix
            stmt.value = value
            return prefix + [stmt]
        if isinstance(stmt, ast.Return):
            prefix, value = self._linearize_expr(stmt.value)
            stmt.value = value
            return prefix + [stmt]
        if isinstance(stmt, ast.If):
            prefix, test = self._linearize_expr(stmt.test)
            stmt.test = test
            stmt.body = self._linearize_body(stmt.body)
            stmt.orelse = self._linearize_body(stmt.orelse)
            return prefix + [stmt]
        if isinstance(stmt, ast.For):
            prefix, iter_value = self._linearize_expr(stmt.iter)
            stmt.iter = iter_value
            stmt.body = self._linearize_body(stmt.body)
            stmt.orelse = self._linearize_body(stmt.orelse)
            return prefix + [stmt]
        if isinstance(stmt, ast.While):
            stmt.body = self._linearize_body(stmt.body)
            stmt.orelse = self._linearize_body(stmt.orelse)
            return [stmt]
        return [stmt]

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        prefix = []
        body = list(node.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Str):
            prefix.append(body.pop(0))
        node.body = prefix + self._linearize_body(body)
        return node


def linearize_source_calls(tree):
    tree = SourceCallLinearizer().visit(tree)
    ast.fix_missing_locations(tree)
    return tree


class SourceEmitter(object):
    BINOPS = {
        ast.Add: '+', ast.Sub: '-', ast.Mult: '*', ast.Div: '/', ast.FloorDiv: '//',
        ast.Mod: '%', ast.Pow: '**', ast.LShift: '<<', ast.RShift: '>>',
        ast.BitOr: '|', ast.BitXor: '^', ast.BitAnd: '&',
    }
    BOOLOPS = {ast.And: 'and', ast.Or: 'or'}
    UNARYOPS = {ast.Invert: '~', ast.Not: 'not ', ast.UAdd: '+', ast.USub: '-'}
    CMPOPS = {
        ast.Eq: '==', ast.NotEq: '!=', ast.Lt: '<', ast.LtE: '<=',
        ast.Gt: '>', ast.GtE: '>=', ast.Is: 'is', ast.IsNot: 'is not',
        ast.In: 'in', ast.NotIn: 'not in',
    }

    def __init__(self, parenthesis_noise=False):
        self.indent = '    '
        self.parenthesis_noise = bool(parenthesis_noise)

    def emit(self, tree):
        return '# -*- coding: utf-8 -*-\n' + self.block(tree.body, 0, top=True)

    def block(self, body, level, top=False):
        if not body:
            return self.indent * level + 'pass\n'
        return ''.join(self.stmt(stmt, level) for stmt in body)

    def line(self, level, text):
        return self.indent * level + text + '\n'

    def expr_without_noise(self, node):
        old = self.parenthesis_noise
        self.parenthesis_noise = False
        try:
            return self.expr(node)
        finally:
            self.parenthesis_noise = old

    def stmt(self, node, level):
        if isinstance(node, ast.FunctionDef):
            lines = []
            for deco in node.decorator_list:
                lines.append(self.line(level, '@' + self.expr_without_noise(deco)))
            lines.append(self.line(level, 'def %s(%s):' % (node.name, self.arguments(node.args))))
            lines.append(self.block(node.body, level + 1))
            return ''.join(lines)
        if isinstance(node, ast.ClassDef):
            lines = []
            for deco in getattr(node, 'decorator_list', []):
                lines.append(self.line(level, '@' + self.expr_without_noise(deco)))
            bases = ', '.join(self.expr(base) for base in node.bases)
            head = 'class %s(%s):' % (node.name, bases) if bases else 'class %s:' % node.name
            lines.append(self.line(level, head))
            lines.append(self.block(node.body, level + 1))
            return ''.join(lines)
        if isinstance(node, ast.Import):
            return self.line(level, 'import ' + ', '.join(self.alias(alias) for alias in node.names))
        if isinstance(node, ast.ImportFrom):
            module = '.' * node.level + (node.module or '')
            return self.line(level, 'from %s import %s' % (module, ', '.join(self.alias(alias) for alias in node.names)))
        if isinstance(node, ast.Assign):
            return self.line(level, '%s = %s' % (', '.join(self.expr(target) for target in node.targets), self.expr(node.value)))
        if isinstance(node, ast.AugAssign):
            return self.line(level, '%s %s= %s' % (self.expr(node.target), self.BINOPS[type(node.op)], self.expr(node.value)))
        if isinstance(node, ast.Expr):
            return self.line(level, self.expr(node.value))
        if isinstance(node, ast.Return):
            return self.line(level, 'return' if node.value is None else 'return ' + self.expr(node.value))
        if isinstance(node, ast.Pass):
            return self.line(level, 'pass')
        if isinstance(node, ast.Break):
            return self.line(level, 'break')
        if isinstance(node, ast.Continue):
            return self.line(level, 'continue')
        if isinstance(node, ast.Delete):
            return self.line(level, 'del ' + ', '.join(self.expr(target) for target in node.targets))
        if isinstance(node, ast.Global):
            return self.line(level, 'global ' + ', '.join(node.names))
        if isinstance(node, ast.If):
            return self.if_stmt(node, level)
        if isinstance(node, ast.For):
            text = self.line(level, 'for %s in %s:' % (self.expr(node.target), self.expr(node.iter)))
            text += self.block(node.body, level + 1)
            if node.orelse:
                text += self.line(level, 'else:')
                text += self.block(node.orelse, level + 1)
            return text
        if isinstance(node, ast.While):
            text = self.line(level, 'while %s:' % self.expr(node.test))
            text += self.block(node.body, level + 1)
            if node.orelse:
                text += self.line(level, 'else:')
                text += self.block(node.orelse, level + 1)
            return text
        if isinstance(node, ast.TryExcept):
            text = self.line(level, 'try:')
            text += self.block(node.body, level + 1)
            for handler in node.handlers:
                text += self.except_handler(handler, level)
            if node.orelse:
                text += self.line(level, 'else:')
                text += self.block(node.orelse, level + 1)
            return text
        if isinstance(node, ast.TryFinally):
            text = self.line(level, 'try:')
            text += self.block(node.body, level + 1)
            text += self.line(level, 'finally:')
            text += self.block(node.finalbody, level + 1)
            return text
        if isinstance(node, ast.With):
            text = 'with %s' % self.expr(node.context_expr)
            if node.optional_vars is not None:
                text += ' as %s' % self.expr(node.optional_vars)
            text += ':'
            return self.line(level, text) + self.block(node.body, level + 1)
        if isinstance(node, ast.Raise):
            parts = [self.expr(part) for part in (node.type, node.inst, node.tback) if part is not None]
            return self.line(level, 'raise' if not parts else 'raise ' + ', '.join(parts))
        if isinstance(node, ast.Assert):
            text = 'assert ' + self.expr(node.test)
            if node.msg is not None:
                text += ', ' + self.expr(node.msg)
            return self.line(level, text)
        if hasattr(ast, 'Print') and isinstance(node, ast.Print):
            text = 'print '
            if node.dest is not None:
                text += '>>%s, ' % self.expr(node.dest)
            text += ', '.join(self.expr(value) for value in node.values)
            if not node.nl:
                text += ','
            return self.line(level, text.rstrip())
        if hasattr(ast, 'Exec') and isinstance(node, ast.Exec):
            text = 'exec ' + self.expr(node.body)
            if node.globals is not None:
                text += ' in ' + self.expr(node.globals)
                if node.locals is not None:
                    text += ', ' + self.expr(node.locals)
            return self.line(level, text)
        raise SystemExit('source-only emitter does not support statement: %s' % node.__class__.__name__)

    def if_stmt(self, node, level):
        text = self.line(level, 'if %s:' % self.expr(node.test))
        text += self.block(node.body, level + 1)
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                nested = self.if_stmt(node.orelse[0], level)
                text += self.indent * level + 'el' + nested[len(self.indent * level):]
            else:
                text += self.line(level, 'else:')
                text += self.block(node.orelse, level + 1)
        return text

    def except_handler(self, node, level):
        if node.type is None:
            head = 'except:'
        else:
            head = 'except ' + self.expr(node.type)
            if node.name is not None:
                head += ' as ' + (node.name if isinstance(node.name, basestring) else self.expr(node.name))
            head += ':'
        return self.line(level, head) + self.block(node.body, level + 1)

    def alias(self, node):
        return node.name if node.asname is None else '%s as %s' % (node.name, node.asname)

    def arguments(self, node):
        args = [arg.id if isinstance(arg, ast.Name) else self.expr_without_noise(arg) for arg in node.args]
        defaults = [self.expr(default) for default in node.defaults]
        if defaults:
            offset = len(args) - len(defaults)
            for index, default in enumerate(defaults):
                args[offset + index] = args[offset + index] + '=' + default
        if node.vararg:
            args.append('*' + node.vararg)
        if node.kwarg:
            args.append('**' + node.kwarg)
        return ', '.join(args)

    def expr(self, node):
        if node is None:
            return 'None'
        if isinstance(node, ast.Name):
            if self.parenthesis_noise and random.randint(0, 3) == 0:
                return '((%s))' % node.id
            return node.id
        if isinstance(node, ast.Num):
            return repr(node.n)
        if isinstance(node, ast.Str):
            return repr(node.s)
        if isinstance(node, ast.Attribute):
            return '%s.%s' % (self.expr(node.value), node.attr)
        if isinstance(node, ast.Call):
            args = [self.expr(arg) for arg in node.args]
            args.extend(self.keyword(keyword) for keyword in node.keywords)
            if node.starargs is not None:
                args.append('*' + self.expr(node.starargs))
            if node.kwargs is not None:
                args.append('**' + self.expr(node.kwargs))
            return '%s(%s)' % (self.expr(node.func), ', '.join(args))
        if isinstance(node, ast.keyword):
            return self.keyword(node)
        if isinstance(node, ast.BinOp):
            return '(%s %s %s)' % (self.expr(node.left), self.BINOPS[type(node.op)], self.expr(node.right))
        if isinstance(node, ast.BoolOp):
            return '(' + (' %s ' % self.BOOLOPS[type(node.op)]).join(self.expr(value) for value in node.values) + ')'
        if isinstance(node, ast.UnaryOp):
            return '(%s%s)' % (self.UNARYOPS[type(node.op)], self.expr(node.operand))
        if isinstance(node, ast.Compare):
            parts = [self.expr(node.left)]
            for op, comp in zip(node.ops, node.comparators):
                parts.append(self.CMPOPS[type(op)])
                parts.append(self.expr(comp))
            return '(' + ' '.join(parts) + ')'
        if isinstance(node, ast.IfExp):
            return '(%s if %s else %s)' % (self.expr(node.body), self.expr(node.test), self.expr(node.orelse))
        if isinstance(node, ast.List):
            return '[' + ', '.join(self.expr(elt) for elt in node.elts) + ']'
        if isinstance(node, ast.Tuple):
            inner = ', '.join(self.expr(elt) for elt in node.elts)
            if len(node.elts) == 1:
                inner += ','
            return '(' + inner + ')'
        if isinstance(node, ast.Dict):
            return '{' + ', '.join('%s: %s' % (self.expr(k), self.expr(v)) for k, v in zip(node.keys, node.values)) + '}'
        if hasattr(ast, 'Set') and isinstance(node, ast.Set):
            return 'set([%s])' % ', '.join(self.expr(elt) for elt in node.elts)
        if isinstance(node, ast.Subscript):
            return '%s[%s]' % (self.expr(node.value), self.slice(node.slice))
        if isinstance(node, ast.Lambda):
            return '(lambda %s: %s)' % (self.arguments(node.args), self.expr(node.body))
        if isinstance(node, ast.Yield):
            return '(yield)' if node.value is None else '(yield %s)' % self.expr(node.value)
        if isinstance(node, ast.ListComp):
            return '[' + self.expr(node.elt) + ' ' + ' '.join(self.comprehension(gen) for gen in node.generators) + ']'
        if hasattr(ast, 'SetComp') and isinstance(node, ast.SetComp):
            return 'set([' + self.expr(node.elt) + ' ' + ' '.join(self.comprehension(gen) for gen in node.generators) + '])'
        if hasattr(ast, 'DictComp') and isinstance(node, ast.DictComp):
            return 'dict([(%s, %s) %s])' % (self.expr(node.key), self.expr(node.value), ' '.join(self.comprehension(gen) for gen in node.generators))
        if isinstance(node, ast.GeneratorExp):
            return '(' + self.expr(node.elt) + ' ' + ' '.join(self.comprehension(gen) for gen in node.generators) + ')'
        if hasattr(ast, 'Repr') and isinstance(node, ast.Repr):
            return '`%s`' % self.expr(node.value)
        raise SystemExit('source-only emitter does not support expression: %s' % node.__class__.__name__)

    def keyword(self, node):
        return '%s=%s' % (node.arg, self.expr(node.value))

    def slice(self, node):
        if isinstance(node, ast.Index):
            return self.expr(node.value)
        if isinstance(node, ast.Slice):
            lower = '' if node.lower is None else self.expr(node.lower)
            upper = '' if node.upper is None else self.expr(node.upper)
            if node.step is None:
                return lower + ':' + upper
            return lower + ':' + upper + ':' + self.expr(node.step)
        if isinstance(node, ast.ExtSlice):
            return ', '.join(self.slice(dim) for dim in node.dims)
        if isinstance(node, ast.Ellipsis):
            return '...'
        return self.expr(node)

    def comprehension(self, node):
        text = 'for %s in %s' % (self.expr(node.target), self.expr(node.iter))
        for item in node.ifs:
            text += ' if ' + self.expr(item)
        return text


def render_source_tree(tree, parenthesis_noise=False):
    return SourceEmitter(parenthesis_noise).emit(tree)


class SourceScheduleExtractor(ast.NodeTransformer):
    SAFE_EXPR_TYPES = (ast.BoolOp, ast.BinOp, ast.Compare)

    def __init__(self, max_exprs):
        self.max_exprs = max(0, max_exprs)
        self.items = []

    def _has_unsafe_child(self, node):
        unsafe = (
            ast.Call, ast.Yield, ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp,
            ast.GeneratorExp, ast.Attribute, ast.Subscript,
        )
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, unsafe):
                return True
        return False

    def _can_extract(self, node):
        return (
            self.max_exprs > 0 and
            len(self.items) < self.max_exprs and
            isinstance(node, self.SAFE_EXPR_TYPES) and
            not self._has_unsafe_child(node)
        )

    def _extract(self, node):
        name = random_ident('ss')
        self.items.append((name, node))
        return ast.copy_location(ast.Name(id=name, ctx=ast.Load()), node)

    def visit_Lambda(self, node):
        return node

    def visit_ListComp(self, node):
        return node

    def visit_SetComp(self, node):
        return node

    def visit_DictComp(self, node):
        return node

    def visit_GeneratorExp(self, node):
        return node

    def visit_BoolOp(self, node):
        self.generic_visit(node)
        if self._can_extract(node):
            return self._extract(node)
        return node

    def visit_BinOp(self, node):
        self.generic_visit(node)
        if self._can_extract(node):
            return self._extract(node)
        return node

    def visit_Compare(self, node):
        self.generic_visit(node)
        if self._can_extract(node):
            return self._extract(node)
        return node


class SourceScheduleTransformer(ast.NodeTransformer):
    def __init__(self, max_exprs=4, window=8):
        self.max_exprs = max(0, max_exprs)
        self.window = max(2, window)

    def _read_names(self, node):
        result = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                result.add(child.id)
        return result

    def _write_names(self, node):
        result = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                result.add(child.id)
        return result

    def _has_runtime_effect(self, node):
        unsafe = (
            ast.Call, ast.Yield, ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp,
            ast.GeneratorExp, ast.Attribute, ast.Subscript,
        )
        for child in ast.walk(node):
            if isinstance(child, unsafe):
                return True
        return False

    def _stmt_info(self, stmt):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name) and not self._has_runtime_effect(stmt.value):
                return (self._read_names(stmt.value), set([target.id]))
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, (ast.Str, ast.Num, ast.Name, ast.Tuple, ast.List, ast.Dict)):
            return (self._read_names(stmt), set())
        return None

    def _can_swap(self, left_info, right_info):
        left_reads, left_writes = left_info
        right_reads, right_writes = right_info
        if left_writes & right_reads:
            return False
        if right_writes & left_reads:
            return False
        if left_writes & right_writes:
            return False
        return True

    def _shuffle_window(self, window):
        items = [(stmt, self._stmt_info(stmt)) for stmt in window]
        if len(items) < 2 or any(info is None for _stmt, info in items):
            return window
        order = list(range(len(items)))
        for _ in range(len(order) * 2):
            index = random.randint(0, len(order) - 2)
            left = order[index]
            right = order[index + 1]
            if self._can_swap(items[left][1], items[right][1]):
                order[index], order[index + 1] = order[index + 1], order[index]
        if order == list(range(len(items))):
            return window
        return [items[index][0] for index in order]

    def _schedule_body(self, body):
        output = []
        index = 0
        while index < len(body):
            if self._stmt_info(body[index]) is None:
                output.append(body[index])
                index += 1
                continue
            window = [body[index]]
            index += 1
            while index < len(body) and len(window) < self.window and self._stmt_info(body[index]) is not None:
                window.append(body[index])
                index += 1
            output.extend(self._shuffle_window(window))
        return output

    def _should_skip_function(self, node):
        if getattr(node, 'decorator_list', None):
            return True
        skip_names = set([
            '__init__', 'InitClient', 'InitServer', 'DestroyClient', 'DestroyServer',
            'Update', 'Destroy',
        ])
        if getattr(node, 'name', None) in skip_names:
            return True
        unsafe = (ast.Yield, ast.Lambda, ast.Global, ast.TryExcept, ast.TryFinally, ast.With)
        for child in ast.walk(node):
            if isinstance(child, unsafe):
                return True
        return False

    def _transform_stmt(self, stmt):
        if not isinstance(stmt, (ast.Assign, ast.If, ast.Return, ast.Expr)):
            return [stmt]
        extractor = SourceScheduleExtractor(self.max_exprs)
        if isinstance(stmt, ast.If):
            # Visiting the whole If also walks its already-transformed body and
            # hoists branch-local expressions before the condition.  That can
            # read temporaries before their assignments (notably recursive
            # calls and Python 2 tuple/comprehension locals).  Only the test is
            # evaluated unconditionally, so only the test may be extracted.
            stmt.test = extractor.visit(stmt.test)
        else:
            stmt = extractor.visit(stmt)
        prefix = [
            ast.copy_location(ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=value), stmt)
            for name, value in extractor.items
        ]
        return prefix + [stmt]

    def _transform_body_once(self, body):
        output = []
        for stmt in body:
            if isinstance(stmt, ast.If):
                stmt.body = self._transform_body_once(stmt.body)
                stmt.orelse = self._transform_body_once(stmt.orelse)
            output.extend(self._transform_stmt(stmt))
        return self._schedule_body(output)

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if self._should_skip_function(node):
            return node
        prefix = []
        body = list(node.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], 'value', None), ast.Str):
            prefix.append(body.pop(0))
        node.body = prefix + self._transform_body_once(body)
        return node


def schedule_source_execution(tree, max_exprs=4, window=8):
    tree = SourceScheduleTransformer(max_exprs, window).visit(tree)
    ast.fix_missing_locations(tree)
    return tree
