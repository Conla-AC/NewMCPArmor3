# -*- coding: utf-8 -*-
"""Source VM installation transform."""


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
    byte_char, byte_value,
    random_ident,
)


try:
    import builtins as _source_vm_builtins
except ImportError:
    import __builtin__ as _source_vm_builtins


_SOURCE_VM_IMPLICIT_GLOBALS = set((
    '__name__', '__file__', '__package__', '__doc__', '__builtins__',
))
_SOURCE_VM_BUILTINS = set(dir(_source_vm_builtins))


def _source_vm_target_names(node):
    if isinstance(node, ast.Name):
        return set((node.id,))
    if isinstance(node, (ast.Tuple, ast.List)):
        names = set()
        for item in node.elts:
            names.update(_source_vm_target_names(item))
        return names
    return set()


def _source_vm_arg_name(item):
    """Return an argument name for Python 2 and Python 3 AST nodes."""
    if hasattr(item, 'arg'):
        return item.arg
    if hasattr(item, 'id'):
        return item.id
    return item


def _source_vm_docstring_stmt(body):
    """Return a leading docstring Expr statement for Python 2 and 3 ASTs."""
    if not body:
        return None
    first = body[0]
    if not isinstance(first, ast.Expr):
        return None
    value = first.value
    if isinstance(value, ast.Str):
        return first
    constant = getattr(ast, 'Constant', None)
    if (constant is not None and isinstance(value, constant) and
            isinstance(value.value, str)):
        return first
    return None


def _source_vm_prologue_index(tree):
    """Return the first legal insertion point after future imports."""
    body = list(getattr(tree, 'body', ()) or ())
    index = 0
    if body and isinstance(body[0], ast.Expr):
        value = body[0].value
        if isinstance(value, ast.Str) or (
                getattr(ast, 'Constant', None) is not None and
                isinstance(value, ast.Constant) and
                isinstance(getattr(value, 'value', None), str)):
            index = 1
    while index < len(body):
        statement = body[index]
        if not (isinstance(statement, ast.ImportFrom) and
                statement.module == '__future__'):
            break
        index += 1
    return index


def _source_vm_make_try(body, handlers, orelse, finalbody):
    try_node = getattr(ast, 'Try', None)
    if try_node is not None:
        return try_node(
            body=body, handlers=handlers, orelse=orelse, finalbody=finalbody)
    try_except = ast.TryExcept(body=body, handlers=handlers, orelse=orelse)
    return ast.TryFinally(body=[try_except], finalbody=finalbody)


def _source_vm_desugar_with(node):
    """Expand ``with EXPR as VAR:`` into enter/exit + try/except/finally.

    The traceback slot of ``__exit__`` is approximated as ``None``; cleanup,
    return/break/continue and exception-suppression semantics are preserved for
    the common context-manager shapes.
    """
    if getattr(node, 'items', None) is not None:
        # Python 3: With(items=[withitem], body).  Multi-item with stays native.
        if len(node.items) != 1:
            return [node]
        context_expr = node.items[0].context_expr
        optional_vars = node.items[0].optional_vars
    else:
        # Python 2: With(context_expr, optional_vars, body)
        context_expr = node.context_expr
        optional_vars = getattr(node, 'optional_vars', None)

    mgr = random_ident()
    exit_name = random_ident()
    flag = random_ident()
    exc_name = random_ident()

    def load(id_):
        # Python 2's AST/compile rejects True/False/None when they are emitted
        # as Name identifiers.  Keep the spelling for legacy mode; the source
        # renderer/compiler will normalize these builtins correctly.
        return ast.Name(id=id_, ctx=ast.Load())

    def store(id_):
        return ast.Name(id=id_, ctx=ast.Store())

    def call_exit(args):
        return ast.Call(func=load(exit_name), args=args, keywords=[],
                        starargs=None, kwargs=None)

    stmts = [
        ast.Assign(targets=[store(mgr)], value=context_expr),
        ast.Assign(
            targets=[store(exit_name)],
            value=ast.Attribute(value=load(mgr), attr='__exit__', ctx=ast.Load())),
    ]
    enter = ast.Call(
        func=ast.Attribute(value=load(mgr), attr='__enter__', ctx=ast.Load()),
        args=[], keywords=[], starargs=None, kwargs=None)
    if optional_vars is not None:
        stmts.append(ast.Assign(targets=[optional_vars], value=enter))
    else:
        stmts.append(ast.Expr(value=enter))
    # Numeric sentinels avoid Python 2's legacy AST treating True/False as
    # invalid identifier fields when this synthetic with-desugar tree is
    # compiled by the worker.
    stmts.append(ast.Assign(targets=[store(flag)], value=ast.Num(n=1)))

    handler = ast.ExceptHandler(
        type=load('BaseException'), name=exc_name,
        body=[
            ast.Assign(targets=[store(flag)], value=ast.Num(n=0)),
            ast.If(
                test=ast.UnaryOp(
                    op=ast.Not(),
                    operand=call_exit([
                        ast.Attribute(value=load(exc_name), attr='__class__',
                                      ctx=ast.Load()),
                        load(exc_name),
                        ast.Num(n=0),
                    ])),
                body=[_source_vm_bare_raise()],
                orelse=[]),
        ])
    finalbody = [
        ast.If(
            test=load(flag),
            body=[ast.Expr(value=call_exit(
                [ast.Num(n=0), ast.Num(n=0), ast.Num(n=0)]))],
            orelse=[]),
    ]
    try_stmt = _source_vm_make_try(
        body=node.body, handlers=[handler], orelse=[], finalbody=finalbody)
    stmts.append(try_stmt)
    return stmts


class SourceWithDesugar(ast.NodeTransformer):
    def visit_With(self, node):
        self.generic_visit(node)
        return _source_vm_desugar_with(node)


def _source_vm_scope_locals(node):
    """Return the local names of a FunctionDef or Lambda, excluding globals."""
    if isinstance(node, ast.Lambda):
        args = [_source_vm_arg_name(item) for item in node.args.args]
        if node.args.vararg:
            args.append(_source_vm_arg_name(node.args.vararg))
        if node.args.kwarg:
            args.append(_source_vm_arg_name(node.args.kwarg))
        body = [ast.Return(value=node.body)]
    else:
        args = [_source_vm_arg_name(item) for item in node.args.args]
        if node.args.vararg:
            args.append(_source_vm_arg_name(node.args.vararg))
        if node.args.kwarg:
            args.append(_source_vm_arg_name(node.args.kwarg))
        body = node.body
    names = set(args)

    class _Collect(ast.NodeVisitor):
        def visit_Name(self, child):
            if isinstance(child.ctx, (ast.Store, ast.Del)):
                names.add(child.id)

        def visit_FunctionDef(self, child):
            return

        def visit_Lambda(self, child):
            return

        def visit_ClassDef(self, child):
            return

    for stmt in body:
        _Collect().visit(stmt)
    return names


def _source_vm_captured(node, enclosing_locals):
    """Names loaded in a nested function/lambda that resolve to enclosing locals."""
    own_locals = _source_vm_scope_locals(node)
    if isinstance(node, ast.Lambda):
        body = [ast.Return(value=node.body)]
    else:
        body = node.body
    loads = set()
    globals_ = set()

    class _Collect(ast.NodeVisitor):
        def visit_Name(self, child):
            if isinstance(child.ctx, ast.Load):
                loads.add(child.id)

        def visit_Global(self, child):
            globals_.update(child.names)

        def visit_FunctionDef(self, child):
            return

        def visit_Lambda(self, child):
            return

        def visit_ClassDef(self, child):
            return

    for stmt in body:
        _Collect().visit(stmt)
    return set(name for name in loads
               if name in enclosing_locals and name not in own_locals
               and name not in globals_)


_MCP_CELL = '_mcp_cell'
_MCP_CLOSURE = '_mcp_closure'
_MCP_UNBOUND = '_mcp_unbound'

_HELPER_SOURCE = '''_mcp_unbound = object()

def _mcp_cell(_bx, _nm):
    _v = _bx[0]
    if _v is _mcp_unbound:
        raise UnboundLocalError("local variable '%s' referenced before assignment" % _nm)
    return _v

def _mcp_closure(_wk, _cl):
    def _cl2(*_a):
        return _wk(*(tuple(_cl) + tuple(_a)))
    return _cl2
'''


def _source_vm_arg_node(name):
    if hasattr(ast, 'arg'):
        return ast.arg(arg=name)
    return ast.Name(id=name, ctx=ast.Param())


def _source_vm_function_node(name, args, body):
    try:
        return ast.FunctionDef(name=name, args=args, body=body,
                               decorator_list=[], returns=None)
    except TypeError:
        return ast.FunctionDef(name=name, args=args, body=body,
                               decorator_list=[])


def _source_vm_bare_raise():
    """Build a bare ``raise`` node with all fields populated.

    Python 2.7's ``ast.Raise()`` constructor does not initialise its
    ``type``/``inst``/``tback`` fields, which later trips ``hasattr`` checks.
    """
    fields = getattr(ast.Raise, '_fields', ())
    if 'exc' in fields:
        return ast.Raise(exc=None, cause=None)
    return ast.Raise(type=None, inst=None, tback=None)


def _source_vm_cell_call(box, name):
    return ast.Call(
        func=ast.Name(id=_MCP_CELL, ctx=ast.Load()),
        args=[ast.Name(id=box, ctx=ast.Load()), ast.Str(s=name)],
        keywords=[], starargs=None, kwargs=None)


def _source_vm_closure_call(worker, boxes):
    return ast.Call(
        func=ast.Name(id=_MCP_CLOSURE, ctx=ast.Load()),
        args=[ast.Name(id=worker, ctx=ast.Load()),
              ast.Tuple(elts=[ast.Name(id=box, ctx=ast.Load())
                              for box in boxes], ctx=ast.Load())],
        keywords=[], starargs=None, kwargs=None)


def _source_vm_enclosing_names(node):
    names = set(_source_vm_scope_locals(node))

    class _Collect(ast.NodeVisitor):
        def visit_FunctionDef(self, child):
            names.add(child.name)

        def visit_Lambda(self, child):
            return

        def visit_ClassDef(self, child):
            return

    collector = _Collect()
    for stmt in node.body:
        collector.visit(stmt)
    return names


class _NestedCollector(ast.NodeVisitor):
    def __init__(self):
        self.items = []

    def visit_FunctionDef(self, node):
        self.items.append(node)

    def visit_Lambda(self, node):
        self.items.append(node)

    def visit_ClassDef(self, node):
        pass


def _name_in(node, names):
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_name_in(item, names) for item in node.elts)
    return False


def _cellvar_unsafe_target(node, cellvars):
    """A cellvar used as a loop/comprehension/with target cannot be rewritten
    to a subscript, so such functions must stay native."""
    for child in ast.walk(node):
        if isinstance(child, ast.For) and _name_in(child.target, cellvars):
            return True
        if isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp,
                              ast.GeneratorExp)):
            for generator in child.generators:
                if _name_in(generator.target, cellvars):
                    return True
        if isinstance(child, ast.With):
            items = getattr(child, 'items', None)
            if items:
                if any(_name_in(item.optional_vars, cellvars) for item in items):
                    return True
            elif _name_in(getattr(child, 'optional_vars', None), cellvars):
                return True
    return False


class _CellRewriter(ast.NodeTransformer):
    """Rewrite cell-variable Name access to box subscripting, stopping at
    nested function/lambda boundaries."""

    def __init__(self, cell_map):
        self.cell_map = cell_map

    def visit_Name(self, node):
        box = self.cell_map.get(node.id)
        if box is None:
            return node
        if isinstance(node.ctx, ast.Load):
            return _source_vm_cell_call(box, node.id)
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            return ast.Subscript(
                value=ast.Name(id=box, ctx=ast.Load()),
                slice=ast.Index(value=ast.Num(n=0)), ctx=node.ctx)
        return node

    def visit_FunctionDef(self, node):
        return node

    def visit_Lambda(self, node):
        return node

    def visit_ClassDef(self, node):
        return node


class _BodyTransformer(ast.NodeTransformer):
    def __init__(self, lifter, box_map, freevars_by_child):
        self.lifter = lifter
        self.box_map = box_map
        self.freevars_by_child = freevars_by_child

    def visit_Name(self, node):
        box = self.box_map.get(node.id)
        if box is None:
            return node
        if isinstance(node.ctx, ast.Load):
            return _source_vm_cell_call(box, node.id)
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            return ast.Subscript(
                value=ast.Name(id=box, ctx=ast.Load()),
                slice=ast.Index(value=ast.Num(n=0)), ctx=node.ctx)
        return node

    def visit_FunctionDef(self, node):
        return self._hoist_child(node)

    def visit_Lambda(self, node):
        return self._hoist_child(node)

    def visit_ClassDef(self, node):
        return node

    def _hoist_child(self, node):
        is_func = isinstance(node, ast.FunctionDef)
        worker_name = random_ident()
        fv = self.freevars_by_child.get(id(node), set())
        body = node.body if is_func else [ast.Return(value=node.body)]

        if not fv:
            worker = _source_vm_function_node(worker_name, node.args, body)
            worker._mcp_source_synthetic = True
            self.lifter._lift_function(worker)
            self.lifter.hoisted.append(worker)
            if is_func:
                return ast.Assign(
                    targets=[ast.Name(id=node.name, ctx=ast.Store())],
                    value=ast.Name(id=worker_name, ctx=ast.Load()))
            return ast.Name(id=worker_name, ctx=ast.Load())

        boxes = [self.box_map[name] for name in fv]
        worker_args = ast.arguments(
            args=[_source_vm_arg_node(box) for box in boxes] +
                 list(node.args.args),
            vararg=node.args.vararg, kwarg=node.args.kwarg,
            defaults=list(node.args.defaults))
        worker = _source_vm_function_node(worker_name, worker_args, body)
        worker._mcp_source_synthetic = True
        child_map = dict((name, self.box_map[name]) for name in fv)
        rewriter = _CellRewriter(child_map)
        rewritten = []
        for stmt in body:
            result = rewriter.visit(stmt)
            rewritten.extend(result if isinstance(result, list) else [result])
        worker.body = rewritten
        self.lifter._lift_function(worker)
        self.lifter.hoisted.append(worker)
        closure = _source_vm_closure_call(worker_name, boxes)
        if not is_func:
            return closure
        if node.name in self.box_map:
            return ast.Assign(
                targets=[ast.Subscript(
                    value=ast.Name(id=self.box_map[node.name], ctx=ast.Load()),
                    slice=ast.Index(value=ast.Num(n=0)), ctx=ast.Store())],
                value=closure)
        return ast.Assign(
            targets=[ast.Name(id=node.name, ctx=ast.Store())],
            value=closure)


class _ClosureLifter(object):
    """Lift nested functions/lambdas to module scope.

    Non-capturing children are hoisted plainly.  Capturing or recursive children
    are lifted with a mutable-box cell for each captured name, sharing reference
    semantics (and UnboundLocalError) with CPython's real closures.
    """

    def __init__(self):
        self.hoisted = []
        self.used_cells = False

    def visit(self, tree):
        for stmt in tree.body:
            if isinstance(stmt, ast.FunctionDef):
                self._lift_function(stmt)
        return tree

    def _lift_function(self, node):
        if getattr(node, 'decorator_list', None):
            return
        if _source_vm_has_yield(node):
            return
        enclosing = _source_vm_enclosing_names(node)
        collector = _NestedCollector()
        for stmt in node.body:
            collector.visit(stmt)
        children = collector.items
        if not children:
            return
        freevars_by_child = {}
        cellvars = set()
        for child in children:
            fv = _source_vm_captured(child, enclosing)
            freevars_by_child[id(child)] = fv
            cellvars |= fv
        if cellvars and _cellvar_unsafe_target(node, cellvars):
            return
        box_map = {}
        if cellvars:
            self.used_cells = True
            for name in cellvars:
                box_map[name] = random_ident()

        transformer = _BodyTransformer(self, box_map, freevars_by_child)
        new_body = []
        for stmt in node.body:
            result = transformer.visit(stmt)
            if isinstance(result, list):
                new_body.extend(result)
            else:
                new_body.append(result)

        inits = []
        param_names = set()
        for item in node.args.args:
            param_names.add(_source_vm_arg_name(item))
        if node.args.vararg:
            param_names.add(_source_vm_arg_name(node.args.vararg))
        if node.args.kwarg:
            param_names.add(_source_vm_arg_name(node.args.kwarg))
        for name, box in box_map.items():
            init_value = (
                ast.Name(id=name, ctx=ast.Load()) if name in param_names
                else ast.Name(id=_MCP_UNBOUND, ctx=ast.Load()))
            inits.append(ast.Assign(
                targets=[ast.Name(id=box, ctx=ast.Store())],
                value=ast.List(elts=[init_value], ctx=ast.Load())))
        doc = _source_vm_docstring_stmt(node.body)
        if doc is not None:
            new_body = [node.body[0]] + inits + new_body[1:]
        else:
            new_body = inits + new_body
        node.body = new_body


def _source_vm_has_yield(node):
    class _YieldCheck(ast.NodeVisitor):
        def __init__(self):
            self.found = False

        def visit_Yield(self, child):
            self.found = True

        def visit_FunctionDef(self, child):
            return

        def visit_Lambda(self, child):
            return

    checker = _YieldCheck()
    for stmt in node.body:
        checker.visit(stmt)
    return checker.found


class _GeneratorDesugar(ast.NodeTransformer):
    """Convert generator functions into a thin callable + a native generator.

    The body is hoisted to a module-level native generator worker, and the
    original function is reduced to ``return worker(args...)``.  The outer
    wrapper becomes virtualizable while the generator body stays native with
    its exact yield semantics.
    """

    def __init__(self):
        self.hoisted = []
        self.depth = 0

    def visit_FunctionDef(self, node):
        if (getattr(node, '_mcp_source_synthetic', False) or
                getattr(node, '_mcp_source_vm_wrapped', False) or
                getattr(node, 'decorator_list', None)):
            return node
        if self.depth > 0:
            return node
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1
        if not _source_vm_has_yield(node):
            return node
        doc = _source_vm_docstring_stmt(node.body)
        worker_name = random_ident()
        worker = _source_vm_function_node(worker_name, node.args, node.body)
        self.hoisted.append(worker)
        call_args = [ast.Name(id=_source_vm_arg_name(item), ctx=ast.Load())
                     for item in node.args.args]
        starargs = kwargs = None
        if node.args.vararg:
            starargs = ast.Name(
                id=_source_vm_arg_name(node.args.vararg), ctx=ast.Load())
        if node.args.kwarg:
            kwargs = ast.Name(
                id=_source_vm_arg_name(node.args.kwarg), ctx=ast.Load())
        ret = ast.Return(value=ast.Call(
            func=ast.Name(id=worker_name, ctx=ast.Load()),
            args=call_args, keywords=[], starargs=starargs, kwargs=kwargs))
        node.body = ([doc] if doc is not None else []) + [ret]
        return node

    def visit_ClassDef(self, node):
        return node


def _desugar_generators(tree):
    transformer = _GeneratorDesugar()
    tree = transformer.visit(tree)
    if transformer.hoisted:
        tree.body.extend(transformer.hoisted)
        ast.fix_missing_locations(tree)
    return tree, [worker.name for worker in transformer.hoisted]


def _hoist_nested_functions(tree):
    """Return (tree, hoisted_global_names) after lifting nested closures."""
    lifter = _ClosureLifter()
    tree = lifter.visit(tree)
    hoisted_names = [worker.name for worker in lifter.hoisted]
    helper_stmts = []
    if lifter.used_cells:
        helper_stmts = ast.parse(_HELPER_SOURCE).body
        for statement in helper_stmts:
            if isinstance(statement, (ast.FunctionDef, ast.ClassDef)):
                statement._mcp_source_synthetic = True
        insert_at = _source_vm_prologue_index(tree)
        hoisted_names.extend([_MCP_CELL, _MCP_CLOSURE, _MCP_UNBOUND])
    # Hoisted workers must exist before normal module statements execute.
    # Appending them at EOF breaks decorator factories: a top-level
    # ``@bind(...)`` calls its outer function during import, before the lifted
    # nested decorator worker has been defined.  Emit helpers and workers at
    # the module prologue instead.  Their global lookups still occur at call
    # time, preserving ordinary late-bound module globals.
    if helper_stmts or lifter.hoisted:
        insert_at = _source_vm_prologue_index(tree)
        tree.body[insert_at:insert_at] = helper_stmts + lifter.hoisted
    if lifter.hoisted or lifter.used_cells:
        ast.fix_missing_locations(tree)
    return tree, hoisted_names


def collect_source_vm_global_names(tree, generated_statements=None):
    """Return globals guaranteed to exist before normal module code runs.

    The VM resolves non-local names through ``globals()``.  A name supplied
    later by a framework, or captured by a closure, does not have that same
    guarantee.  Keep those functions native instead of emitting a VM GLOBAL
    operation that would turn a late binding into a NameError.
    """
    names = set(_SOURCE_VM_IMPLICIT_GLOBALS)
    names.update(_SOURCE_VM_BUILTINS)
    statements = list(getattr(tree, 'body', ()) or ())
    statements.extend(generated_statements or ())
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.ClassDef)):
            names.add(statement.name)
        elif isinstance(statement, ast.Assign):
            for target in statement.targets:
                names.update(_source_vm_target_names(target))
        elif isinstance(statement, ast.AugAssign):
            names.update(_source_vm_target_names(statement.target))
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                names.add(alias.asname or alias.name.split('.')[0])
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if alias.name != '*':
                    names.add(alias.asname or alias.name)
    return names


class SourceVMTransformer(ast.NodeTransformer):
    def __init__(self, ratio=15, min_ops=8, max_ops=160, max_functions=8,
                 includes=None, excludes=None, allow_loops=False, debug=False,
                 dotzero_relay=False, binary_payload=False,
                 encrypt_names=False, dialect_index=0, dialect_count=1,
                 flow_constants=False, exception_trap_ratio=0,
                 known_global_names=None):
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
        self.known_global_names = (set(known_global_names)
                                   if known_global_names is not None else None)
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
        self.tokens = dict(list(zip(SOURCE_VM_OPS, values)))
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
        # Runtime-discovered registration hooks are part of the host ABI.  In
        # particular command decorators such as ``__bind_command__`` execute
        # while the module is importing; virtualising them can move their
        # closure/global bindings into the VM worker and leave a generated
        # short name undefined (for example ``yNY``).  Keep dunder hooks
        # stable even when an unlimited VM profile clears the user exclude
        # list.  This mirrors the global-rename ABI guard.
        if (name.startswith('__') and name.endswith('__')):
            return False
        if name.startswith('_mcp_') or source_vm_name_matches(name, self.excludes):
            return False
        if self.includes and not source_vm_name_matches(name, self.includes):
            return False
        identity = qualname or name
        if (sum(byte_value(ch) for ch in identity) % self.dialect_count !=
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
                logical_row = dict(list(zip(
                    ('a', 'b', 'c', 'd', 'e', 'next'), instruction[1:])))
                logical_row['op'] = self.tokens[instruction[0]]
                physical_row = [0] * len(self.row_slots)
                for field, slot in list(self.row_slots.items()):
                    physical_row[slot] = logical_row[field]
                records.append(struct.pack(
                    '>8i', *([virtual_tokens[pc]] + physical_row)))
            binary = b''.join(records)
            if self.binary_payload:
                # Bytecode loaders already compress and encrypt the enclosing
                # code object, so a second textual encoding only wastes space.
                raw_payload = ('R', binary)
            else:
                binary = zlib.compress(binary, 9)
                binary_key = random.randint(1, 255)
                encrypted = b''.join(byte_char(byte_value(value) ^ (
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
                        (byte_value(ch) if not isinstance(ch, int) else ch) ^
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
                        encoded_name.append(byte_value(value) ^ key)
                    elif mode == 1:
                        key = ((name_seed ^ flow_seeds[leaders[0]] ^ site) + index * name_step) & 255
                        encoded_name.append((byte_value(value) + key + name_bias) & 255)
                    else:
                        key = ((name_seed ^ flow_seeds[leaders[0]] ^ site) + index * name_step) & 255
                        encoded_name.append(((byte_value(value) ^ key) + name_bias +
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
        for name, index in list(self.payload_slots.items()):
            payload[index] = logical[name]
        return payload

    def visit_FunctionDef(self, node):
        if (getattr(node, '_mcp_source_synthetic', False) or
                getattr(node, '_mcp_source_vm_wrapped', False)):
            return node
        # Only the parsed wrapper *body* is transplanted below; ``node.args``
        # and all defaults/annotations remain on the original FunctionDef.
        # Rejecting such functions here therefore reduced VM coverage without
        # protecting any signature state (and made the full VM regression
        # silently lose two functions). Keep only the real malformed-node
        # guard.
        args = getattr(node, 'args', None)
        if args is None:
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
        doc_statement = _source_vm_docstring_stmt(node.body)
        node.body = SourceWithDesugar().visit(
            ast.Module(body=node.body)).body
        body = node.body[1:] if doc_statement is not None else node.body
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
        if self.known_global_names is not None:
            global_refs = set()
            for instruction in compiler.instructions:
                if instruction[0] == 'GLOBAL':
                    global_refs.add(compiler.names[instruction[2]])
            if not global_refs.issubset(self.known_global_names):
                return node
        if len(compiler.instructions) > self.max_ops:
            return node
        # Preserve the pre-wrapper public signature for the AST smoke audit.
        # Predicate weaving may have appended private parameters, which are
        # deliberately excluded just like SourceASTSmokeCollector does.
        visible_args = list(getattr(node.args, 'args', []) or [])
        hidden_args = int(getattr(node, '_mcp_source_hidden_args', 0) or 0)
        if hidden_args:
            visible_args = visible_args[:-hidden_args]
        def smoke_arg_name(value):
            if value is None:
                return None
            if isinstance(value, str):
                return value
            return getattr(value, 'arg', getattr(value, 'id', str(value)))
        node._mcp_source_smoke_layout = (
            tuple(smoke_arg_name(item) for item in visible_args),
            tuple(smoke_arg_name(item) for item in
                  (getattr(node.args, 'kwonlyargs', []) or [])),
            smoke_arg_name(getattr(node.args, 'vararg', None)),
            smoke_arg_name(getattr(node.args, 'kwarg', None)))
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
        arg_names = [_source_vm_arg_name(item) for item in node.args.args]
        def_arg_names = list(arg_names)
        if node.args.vararg:
            def_arg_names.append('*' + _source_vm_arg_name(node.args.vararg))
        if node.args.kwarg:
            def_arg_names.append('**' + _source_vm_arg_name(node.args.kwarg))
        call_args = list(arg_names)
        if node.args.vararg:
            call_args.append(_source_vm_arg_name(node.args.vararg))
        if node.args.kwarg:
            call_args.append(_source_vm_arg_name(node.args.kwarg))
        flow_arg = getattr(node, '_mcp_source_flow_arg', None)
        flow_value = flow_arg if flow_arg else '0'
        tuple_src = '(' + ', '.join(call_args) + (',' if len(call_args) == 1 else '') + ')'
        # Rotate the wrapper shape so virtualized functions do not share a
        # single recognizable ``global X; if X.__class__ is E; ...`` skeleton.
        variant = self.count % 4
        opaque_seed = random.randint(0x10000, 0x7fffffff)
        common = {
            'p': payload_name, 'e': self.envelope_name,
            'o': self.envelope_open_name, 'c': self.capability_name,
            'r': self.runner_name, 't': tuple_src, 'f': flow_value,
            's': opaque_seed,
        }
        if variant == 0:
            body_src = (
                'global %(p)s\n'
                'if %(p)s.__class__ is %(e)s:\n'
                '    %(p)s = %(p)s.%(o)s(%(c)s)\n'
                'return %(r)s(%(p)s, %(t)s, %(f)s)\n') % common
        elif variant == 1:
            body_src = (
                'global %(p)s\n'
                'if %(p)s.__class__ == %(e)s and (%(s)d * %(s)d + %(s)d) %% 2 == 0:\n'
                '    %(p)s = %(p)s.%(o)s(%(c)s)\n'
                'return %(r)s(%(p)s, %(t)s, %(f)s)\n') % common
        elif variant == 2:
            common['l'] = random_ident()
            body_src = (
                'global %(p)s\n'
                '%(l)s = %(p)s.__class__\n'
                'if %(l)s is %(e)s:\n'
                '    %(p)s = %(p)s.%(o)s(%(c)s)\n'
                'return %(r)s(%(p)s, %(t)s, %(f)s)\n') % common
        else:
            body_src = (
                'global %(p)s\n'
                'try:\n'
                '    if isinstance(%(p)s, %(e)s):\n'
                '        %(p)s = %(p)s.%(o)s(%(c)s)\n'
                'except Exception:\n'
                '    pass\n'
                'return %(r)s(%(p)s, %(t)s, %(f)s)\n') % common
        indented_body = '\n'.join(
            '    ' + line if line else line for line in body_src.split('\n'))
        wrapper = ast.parse('def %s(%s):\n%s' % (
            node.name, ', '.join(def_arg_names), indented_body)).body[0]
        if doc_statement is not None:
            wrapper.body.insert(0, doc_statement)
        node.body = wrapper.body
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
        # VM helpers are hand-built and Python 2.7's fixer skips several
        # expression descendants. Seed coordinates on every generated node.
        for _node in ast.walk(tree):
            if isinstance(_node, (ast.stmt, ast.expr)):
                if getattr(_node, 'lineno', None) is None:
                    _node.lineno = 1
                if getattr(_node, 'col_offset', None) is None:
                    _node.col_offset = 0
        return tree


def virtualize_source_functions(tree, ratio=15, min_ops=8, max_ops=160,
                                max_functions=8, includes=None, excludes=None,
                                allow_loops=False, debug=False,
                                dotzero_relay=False, binary_payload=False,
                                encrypt_names=False, dialects=1,
                                flow_constants=False,
                                exception_trap_ratio=0,
                                known_global_names=None):
    tree, generator_names = _desugar_generators(tree)
    tree, hoisted_names = _hoist_nested_functions(tree)
    all_hoisted = generator_names + hoisted_names
    if known_global_names is not None and all_hoisted:
        known_global_names = set(known_global_names) | set(all_hoisted)
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
            index, dialects, flow_constants, exception_trap_ratio,
            known_global_names)
        tree = transformer.visit(tree)
        tree = transformer.finish(tree)
        total += transformer.count
        if max_functions:
            remaining -= transformer.count
    return tree, total\n