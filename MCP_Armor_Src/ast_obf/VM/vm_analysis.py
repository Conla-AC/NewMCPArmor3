# -*- coding: utf-8 -*-
"""Source VM eligibility analysis and instruction compilation."""


import ast

from MCP_Armor_Src.ast_obf.dead_flow import (
    SOURCE_VM_BINOPS,
    SOURCE_VM_CMPOPS,
    SOURCE_VM_INPLACEOPS,
    SOURCE_VM_UNARYOPS,
)


class SourceVMGlobalCollector(ast.NodeVisitor):
    def __init__(self):
        self.names = set()

    def visit_Global(self, node):
        self.names.update(node.names)

    def visit_FunctionDef(self, node):
        return

    def visit_Lambda(self, node):
        return

    def visit_ClassDef(self, node):
        return


class SourceVMLocalCollector(ast.NodeVisitor):
    def __init__(self, args, global_names=None):
        self.names = []
        self.seen = set()
        self.global_names = set(global_names or ())
        for value in args:
            self.add(value.id if isinstance(value, ast.Name) else str(value))

    def add(self, name):
        if name not in self.global_names and name not in self.seen:
            self.seen.add(name)
            self.names.append(name)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.add(node.id)

    def visit_ExceptHandler(self, node):
        # ``except E as name:`` binds a fresh local whose name lives in a
        # string field on the handler rather than an ast.Name node.
        if isinstance(node.name, str):
            self.add(node.name)
        self.generic_visit(node)

    def visit_Global(self, node):
        return

    def visit_FunctionDef(self, node):
        # Nested scopes are rejected by the eligibility pass and must not leak
        # their locals into the surrounding function.
        return

    def visit_Lambda(self, node):
        return

    def visit_ClassDef(self, node):
        return


class SourceVMEligibility(ast.NodeVisitor):
    SAFE_STMTS = (ast.Assign, ast.AugAssign, ast.Expr, ast.If, ast.Return, ast.Pass)
    SAFE_EXPRS = (
        ast.Name, ast.Num, ast.Str, ast.BinOp, ast.UnaryOp, ast.BoolOp,
        ast.Compare, ast.Attribute, ast.Subscript, ast.Call, ast.List,
        ast.Tuple, ast.Dict, ast.IfExp,
    )

    def __init__(self):
        self.ok = True
        self.reason = ''
        self.node_count = 0
        self.has_loop = False

    def reject(self, reason):
        if self.ok:
            self.ok = False
            self.reason = reason

    def generic_visit(self, node):
        if not self.ok:
            return
        self.node_count += 1
        ast.NodeVisitor.generic_visit(self, node)

    def visit_FunctionDef(self, node):
        self.reject('nested-function')

    def visit_ClassDef(self, node):
        self.reject('nested-class')

    def visit_Lambda(self, node):
        self.reject('lambda')

    def visit_GeneratorExp(self, node):
        self.reject('generator')

    def visit_Yield(self, node):
        self.reject('yield')

    def visit_Global(self, node):
        self.node_count += 1

    def visit_Exec(self, node):
        self.reject('exec')

    def visit_Stmt(self, node):
        self.reject('unknown-statement')

    def visit_Assign(self, node):
        for target in node.targets:
            if not isinstance(target, (ast.Name, ast.Attribute, ast.Subscript, ast.Tuple, ast.List)):
                self.reject('complex-assignment')
                return
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if (not isinstance(node.target, (ast.Name, ast.Attribute, ast.Subscript)) or
                type(node.op) not in SOURCE_VM_INPLACEOPS):
            self.reject('complex-augassign')
            return
        self.generic_visit(node)

    def visit_If(self, node):
        if getattr(node, '_mcp_source_dead_flow', False):
            self.node_count += 1
            return
        self.generic_visit(node)

    def visit_Return(self, node):
        self.generic_visit(node)

    def visit_Pass(self, node):
        self.node_count += 1

    def visit_Expr(self, node):
        self.generic_visit(node)

    def visit_For(self, node):
        self.has_loop = True
        if not isinstance(node.target, (ast.Name, ast.Tuple, ast.List)):
            self.reject('for-target')
            return
        self.generic_visit(node)

    def visit_While(self, node):
        self.has_loop = True
        self.generic_visit(node)

    def visit_Break(self, node):
        self.node_count += 1

    def visit_Continue(self, node):
        self.node_count += 1

    def visit_TryExcept(self, node):
        for index, handler in enumerate(node.handlers):
            if handler.type is None and index + 1 != len(node.handlers):
                self.reject('bare-except-order')
                return
            if (handler.name is not None and
                    not isinstance(handler.name, str) and
                    not isinstance(handler.name, ast.Name)):
                self.reject('except-target')
                return
        self.generic_visit(node)

    def _reject_finally_exit(self, finalbody):
        # A finally body with its own return/break/continue would re-enter the
        # inline-finally machinery; keep such functions native for now.
        for stmt in finalbody or ():
            for child in ast.walk(stmt):
                if isinstance(child, (ast.Return, ast.Break, ast.Continue)):
                    self.reject('finally-exit')
                    return True
        return False

    def visit_TryFinally(self, node):
        if self._reject_finally_exit(node.finalbody):
            return
        self.generic_visit(node)

    def visit_Try(self, node):
        # Python 3 unified Try(handlers, orelse, finalbody).
        if self._reject_finally_exit(getattr(node, 'finalbody', None)):
            return
        for index, handler in enumerate(node.handlers):
            if handler.type is None and index + 1 != len(node.handlers):
                self.reject('bare-except-order')
                return
            if (handler.name is not None and
                    not isinstance(handler.name, str) and
                    not isinstance(handler.name, ast.Name)):
                self.reject('except-target')
                return
        self.generic_visit(node)

    def visit_With(self, node):
        # ``with`` is desugared into enter/exit calls + try/except/finally by
        # SourceWithDesugar before this pass; a surviving node (e.g. Python 3
        # multi-item with) keeps the function native.
        self.reject('with')

    def visit_Raise(self, node):
        if hasattr(node, 'inst'):
            # Python 2 Raise(type, inst, tback)
            if node.inst is not None or node.tback is not None:
                self.reject('complex-raise')
                return
        elif getattr(node, 'cause', None) is not None:
            # Python 3 Raise(exc, cause)
            self.reject('complex-raise')
            return
        self.generic_visit(node)

    def visit_Delete(self, node):
        if any(not isinstance(target, (ast.Name, ast.Attribute, ast.Subscript))
               for target in node.targets):
            self.reject('complex-delete')
            return
        self.generic_visit(node)

    def visit_Print(self, node):
        self.reject('print')

    def visit_BinOp(self, node):
        if type(node.op) not in SOURCE_VM_BINOPS:
            self.reject('binop')
            return
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if type(node.op) not in SOURCE_VM_UNARYOPS:
            self.reject('unary')
            return
        self.generic_visit(node)

    def visit_Compare(self, node):
        if (len(node.ops) != len(node.comparators) or not node.ops or
                any(type(item) not in SOURCE_VM_CMPOPS for item in node.ops)):
            self.reject('compare')
            return
        self.generic_visit(node)

    def visit_Call(self, node):
        self.generic_visit(node)

    def visit_Subscript(self, node):
        # Python 2 wraps simple subscripts in ast.Index; Python 3 exposes the
        # value (Constant), ast.Slice, or an ast.Tuple for extended slices
        # directly.  Accept all three modern forms so subscripts stop being
        # silently rejected on the Python 3 host.
        if hasattr(ast, 'Index') and isinstance(node.slice, (ast.Index, ast.Slice)):
            self.generic_visit(node)
            return
        constant = getattr(ast, 'Constant', None)
        if constant is not None and isinstance(node.slice, (constant, ast.Slice, ast.Tuple)):
            self.generic_visit(node)
            return
        self.reject('slice')

    def visit_Name(self, node):
        self.node_count += 1

    def visit_Num(self, node):
        self.node_count += 1

    def visit_Str(self, node):
        self.node_count += 1

    def visit_Attribute(self, node):
        # Python performs class-name mangling for ``self.__private`` during
        # compilation. The VM ATTR instruction uses getattr with the literal
        # spelling and would bypass that transformation.
        if node.attr.startswith('__'):
            self.reject('private-attribute')
            return
        self.generic_visit(node)

    def visit_List(self, node):
        self.generic_visit(node)

    def visit_Tuple(self, node):
        self.generic_visit(node)

    def visit_Dict(self, node):
        self.generic_visit(node)

    def visit_Set(self, node):
        self.generic_visit(node)

    def visit_ListComp(self, node):
        for generator in node.generators:
            if not isinstance(generator.target, (ast.Name, ast.Tuple, ast.List)):
                self.reject('comprehension-target')
                return
        self.generic_visit(node)

    def visit_Slice(self, node):
        self.generic_visit(node)

    def visit_Assert(self, node):
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        if not isinstance(node.op, (ast.And, ast.Or)) or len(node.values) < 2:
            self.reject('boolop')
            return
        self.generic_visit(node)

    def visit_IfExp(self, node):
        self.generic_visit(node)


class SourceVMCompiler(object):
    def __init__(self, node):
        global_collector = SourceVMGlobalCollector()
        for stmt in node.body:
            global_collector.visit(stmt)
        self.global_names = global_collector.names
        # Python 2 exposes argument names as strings while Python 3 uses
        # ``ast.arg`` objects.  Normalize both forms before collecting locals;
        # otherwise every parameter is emitted as a GLOBAL reference.
        argument_names = [
            (item.arg if hasattr(item, 'arg') else
             (item.id if hasattr(item, 'id') else item))
            for item in node.args.args
        ]
        if node.args.vararg:
            argument_names.append(
                node.args.vararg.arg if hasattr(node.args.vararg, 'arg')
                else node.args.vararg)
        if node.args.kwarg:
            argument_names.append(
                node.args.kwarg.arg if hasattr(node.args.kwarg, 'arg')
                else node.args.kwarg)
        collector = SourceVMLocalCollector(argument_names, self.global_names)
        for stmt in node.body:
            collector.visit(stmt)
        self.local_names = collector.names
        self.locals = dict((name, index) for index, name in enumerate(self.local_names))
        self.local_count = len(self.local_names)
        self.next_reg = self.local_count
        self.free_regs = []
        self.free_reg_set = set()
        self.instructions = []
        self.constants = []
        self.names = []
        self.name_index = {}
        self.plans = []
        self.used_ops = set()
        self.loop_stack = []
        self.exception_stack = []
        self.active_exception_regs = []
        self.instruction_handlers = []
        self.exception_contexts = []
        self.finally_stack = []

    def new_reg(self):
        if self.free_regs:
            value = self.free_regs.pop()
            self.free_reg_set.remove(value)
            return value
        value = self.next_reg
        self.next_reg += 1
        return value

    def release_reg(self, value):
        if (value >= self.local_count and value < self.next_reg and
                value not in self.free_reg_set):
            self.free_regs.append(value)
            self.free_reg_set.add(value)

    def release_regs(self, values):
        for value in values:
            if value >= 0:
                self.release_reg(value)

    def add_const(self, value):
        self.constants.append(value)
        return len(self.constants) - 1

    def add_name(self, value):
        if value not in self.name_index:
            self.name_index[value] = len(self.names)
            self.names.append(value)
        return self.name_index[value]

    def add_plan(self, values):
        self.plans.append(tuple(values))
        return len(self.plans) - 1

    def emit(self, op, a=-1, b=-1, c=-1, d=-1, e=-1):
        self.used_ops.add(op)
        self.instructions.append([op, int(a), int(b), int(c), int(d), int(e)])
        self.instruction_handlers.append(tuple(self.exception_stack))
        return len(self.instructions) - 1

    def patch(self, index, field, value):
        self.instructions[index][field] = int(value)

    def const_reg(self, value):
        target = self.new_reg()
        self.emit('CONST', target, self.add_const(value))
        return target

    def compile_expr(self, node):
        if isinstance(node, ast.Name):
            if node.id in ('None', 'True', 'False') and node.id not in self.locals:
                return self.const_reg({'None': None, 'True': True, 'False': False}[node.id])
            if node.id in self.locals:
                target = self.new_reg()
                self.emit('LOCAL', target, self.locals[node.id], self.add_name(node.id))
                return target
            target = self.new_reg()
            self.emit('GLOBAL', target, self.add_name(node.id))
            return target
        if hasattr(ast, 'Constant') and isinstance(node, ast.Constant):
            # Python 3 folds Num/Str/NameConstant/Ellipsis into Constant.
            return self.const_reg(node.value)
        if isinstance(node, ast.Num):
            return self.const_reg(node.n)
        if isinstance(node, ast.Str):
            return self.const_reg(node.s)
        if isinstance(node, ast.BinOp):
            left = self.compile_expr(node.left)
            right = self.compile_expr(node.right)
            target = self.new_reg()
            self.emit(SOURCE_VM_BINOPS[type(node.op)], target, left, right)
            self.release_regs((left, right))
            return target
        if isinstance(node, ast.UnaryOp):
            value = self.compile_expr(node.operand)
            target = self.new_reg()
            self.emit(SOURCE_VM_UNARYOPS[type(node.op)], target, value)
            self.release_reg(value)
            return target
        if isinstance(node, ast.Attribute):
            value = self.compile_expr(node.value)
            target = self.new_reg()
            self.emit('ATTR', target, value, self.add_name(node.attr))
            self.release_reg(value)
            return target
        if isinstance(node, ast.Subscript):
            value = self.compile_expr(node.value)
            key = self.compile_expr(
                node.slice.value if isinstance(node.slice, ast.Index)
                else node.slice)
            target = self.new_reg()
            self.emit('SUBSCR', target, value, key)
            self.release_regs((value, key))
            return target
        if isinstance(node, ast.Call):
            func = self.compile_expr(node.func)
            args = [self.compile_expr(item) for item in node.args]
            target = self.new_reg()
            starargs = getattr(node, 'starargs', None)
            kwargs = getattr(node, 'kwargs', None)
            if node.keywords or starargs is not None or kwargs is not None:
                pairs = []
                for keyword in node.keywords:
                    pairs.extend([self.add_name(keyword.arg), self.compile_expr(keyword.value)])
                star_reg = self.compile_expr(starargs) if starargs is not None else -1
                kwargs_reg = self.compile_expr(kwargs) if kwargs is not None else -1
                plan = (tuple(args), tuple(pairs), star_reg, kwargs_reg)
                self.emit('CALL_EX', target, func, self.add_plan(plan))
            else:
                self.emit('CALL', target, func, self.add_plan(args))
            self.release_reg(func)
            self.release_regs(args)
            self.release_regs([pairs[index] for index in range(1, len(pairs), 2)]
                              if node.keywords else [])
            if starargs is not None:
                self.release_reg(star_reg)
            if kwargs is not None:
                self.release_reg(kwargs_reg)
            return target
        if isinstance(node, (ast.List, ast.Tuple)):
            values = [self.compile_expr(item) for item in node.elts]
            target = self.new_reg()
            self.emit('LIST' if isinstance(node, ast.List) else 'TUPLE', target, self.add_plan(values))
            self.release_regs(values)
            return target
        if isinstance(node, ast.Set):
            values = [self.compile_expr(item) for item in node.elts]
            target = self.new_reg()
            self.emit('SET', target, self.add_plan(values))
            self.release_regs(values)
            return target
        if isinstance(node, ast.Slice):
            lower = self.compile_expr(node.lower) if node.lower is not None else -1
            upper = self.compile_expr(node.upper) if node.upper is not None else -1
            step = self.compile_expr(node.step) if node.step is not None else -1
            target = self.new_reg()
            self.emit('SLICE', target, lower, upper, step)
            self.release_regs((lower, upper, step))
            return target
        if isinstance(node, ast.Dict):
            values = []
            for key, value in zip(node.keys, node.values):
                values.extend([self.compile_expr(key), self.compile_expr(value)])
            target = self.new_reg()
            self.emit('DICT', target, self.add_plan(values))
            self.release_regs(values)
            return target
        if isinstance(node, ast.ListComp):
            result = self.new_reg()
            self.emit('LIST', result, self.add_plan(()))

            def compile_generator(index):
                generator = node.generators[index]
                iterable = self.compile_expr(generator.iter)
                iterator = self.new_reg()
                self.emit('ITER', iterator, iterable)
                self.release_reg(iterable)
                start = len(self.instructions)
                item = self.new_reg()
                exhausted = self.emit('NEXT', item, iterator, -1)
                self.store_target(generator.target, item)
                self.release_reg(item)
                rejected = []
                for condition in generator.ifs:
                    test = self.compile_expr(condition)
                    rejected.append(self.emit('JFALSE', test, -1))
                    self.release_reg(test)
                if index + 1 < len(node.generators):
                    compile_generator(index + 1)
                else:
                    value = self.compile_expr(node.elt)
                    self.emit('APPEND', result, value)
                    self.release_reg(value)
                self.emit('JUMP', start)
                end = len(self.instructions)
                self.patch(exhausted, 3, end)
                for jump in rejected:
                    self.patch(jump, 2, start)
                self.release_reg(iterator)

            compile_generator(0)
            return result
        if isinstance(node, ast.Compare):
            left = self.compile_expr(node.left)
            target = self.new_reg()
            patches = []
            for index, (operator_node, comparator) in enumerate(zip(node.ops, node.comparators)):
                right = self.compile_expr(comparator)
                self.emit(SOURCE_VM_CMPOPS[type(operator_node)], target, left, right)
                self.release_reg(left)
                if index + 1 < len(node.ops):
                    patches.append(self.emit('JFALSE', target, -1))
                    left = right
                else:
                    self.release_reg(right)
            end = len(self.instructions)
            for index in patches:
                self.patch(index, 2, end)
            return target
        if isinstance(node, ast.BoolOp):
            result = self.new_reg()
            first = self.compile_expr(node.values[0])
            self.emit('MOVE', result, first)
            self.release_reg(first)
            patches = []
            jump_op = 'JFALSE' if isinstance(node.op, ast.And) else 'JTRUE'
            for value in node.values[1:]:
                patches.append(self.emit(jump_op, result, -1))
                item = self.compile_expr(value)
                self.emit('MOVE', result, item)
                self.release_reg(item)
            end = len(self.instructions)
            for index in patches:
                self.patch(index, 2, end)
            return result
        if isinstance(node, ast.IfExp):
            result = self.new_reg()
            test = self.compile_expr(node.test)
            false_jump = self.emit('JFALSE', test, -1)
            self.release_reg(test)
            body = self.compile_expr(node.body)
            self.emit('MOVE', result, body)
            self.release_reg(body)
            end_jump = self.emit('JUMP', -1)
            self.patch(false_jump, 2, len(self.instructions))
            other = self.compile_expr(node.orelse)
            self.emit('MOVE', result, other)
            self.release_reg(other)
            self.patch(end_jump, 1, len(self.instructions))
            return result
        raise ValueError('source VM expression unsupported: %s' % node.__class__.__name__)

    def store_target(self, target, value):
        if isinstance(target, ast.Name):
            if target.id in self.global_names:
                self.emit('STORE_GLOBAL', self.add_name(target.id), value)
            else:
                self.emit('MOVE', self.locals[target.id], value)
            return
        if isinstance(target, ast.Attribute):
            owner = self.compile_expr(target.value)
            self.emit('STORE_ATTR', owner, self.add_name(target.attr), value)
            self.release_reg(owner)
            return
        if isinstance(target, ast.Subscript):
            owner = self.compile_expr(target.value)
            key = self.compile_expr(
                target.slice.value if isinstance(target.slice, ast.Index)
                else target.slice)
            self.emit('STORE_SUBSCR', owner, key, value)
            self.release_regs((owner, key))
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            destinations = []
            for _item in target.elts:
                destinations.append(self.new_reg())
            self.emit('UNPACK', value, self.add_plan(destinations))
            for item, destination in zip(target.elts, destinations):
                self.store_target(item, destination)
                self.release_reg(destination)
            return
        raise ValueError('source VM target unsupported')

    def _compile_try_except(self, body, handlers, orelse):
        type_regs = []
        for handler in handlers:
            type_regs.append(
                self.compile_expr(handler.type)
                if handler.type is not None else -1)
        exception_reg = self.new_reg()
        context_id = len(self.exception_contexts)
        context = {'clauses': [], 'exception_reg': exception_reg}
        self.exception_contexts.append(context)
        self.exception_stack.append(context_id)
        for stmt in body:
            self.compile_stmt(stmt)
        self.exception_stack.pop()
        normal_jump = self.emit('JUMP', -1)
        handler_jumps = []
        for handler, type_reg in zip(handlers, type_regs):
            handler_start = len(self.instructions)
            context['clauses'].append((type_reg, handler_start))
            if handler.name is not None:
                target_name = (handler.name if isinstance(handler.name, str)
                               else getattr(handler.name, 'id', None))
                if target_name is None:
                    raise ValueError('source VM exception target unsupported')
                self.store_target(
                    ast.Name(id=target_name, ctx=ast.Store()), exception_reg)
            self.active_exception_regs.append(exception_reg)
            for stmt in handler.body:
                self.compile_stmt(stmt)
            self.active_exception_regs.pop()
            handler_jumps.append(self.emit('JUMP', -1))
        else_start = len(self.instructions)
        self.patch(normal_jump, 1, else_start)
        for stmt in orelse:
            self.compile_stmt(stmt)
        end = len(self.instructions)
        for index in handler_jumps:
            self.patch(index, 1, end)
        self.release_regs(type_regs)
        self.release_reg(exception_reg)

    def _compile_statements(self, stmts):
        for stmt in stmts:
            self.compile_stmt(stmt)

    def _emit_finally_inline(self, final_stmts):
        for stmt in final_stmts:
            self.compile_stmt(stmt)

    def _emit_pending_finally(self):
        # finally bodies never contain return/break/continue (rejected by the
        # eligibility pass), so inlining them cannot re-enter this helper.
        for final_stmts in reversed(self.finally_stack):
            self._emit_finally_inline(final_stmts)

    def _compile_try_finally(self, inner_fn, finalbody):
        self.finally_stack.append(finalbody)
        exception_reg = self.new_reg()
        context_id = len(self.exception_contexts)
        context = {'clauses': [], 'exception_reg': exception_reg}
        self.exception_contexts.append(context)
        self.exception_stack.append(context_id)
        try:
            inner_fn()
        finally:
            self.exception_stack.pop()
            self.finally_stack.pop()
        # Normal completion runs the finally block, then skips the re-raise
        # path.  Exceptions inside the protected region match the catch-all
        # clause below, run the finally block, and re-raise the original error.
        self._emit_finally_inline(finalbody)
        skip = self.emit('JUMP', -1)
        finally_start = len(self.instructions)
        context['clauses'].append((-1, finally_start))
        self._emit_finally_inline(finalbody)
        self.emit('RAISE', exception_reg)
        end = len(self.instructions)
        self.patch(skip, 1, end)
        self.release_reg(exception_reg)

    def compile_stmt(self, node):
        if isinstance(node, ast.Assign):
            value = self.compile_expr(node.value)
            for target in node.targets:
                self.store_target(target, value)
            self.release_reg(value)
            return
        if isinstance(node, ast.AugAssign):
            right = self.compile_expr(node.value)
            operation = SOURCE_VM_INPLACEOPS[type(node.op)]
            if isinstance(node.target, ast.Name):
                current = self.compile_expr(
                    ast.Name(id=node.target.id, ctx=ast.Load()))
                self.emit(operation, current, current, right)
                self.store_target(node.target, current)
                self.release_reg(current)
            elif isinstance(node.target, ast.Attribute):
                owner = self.compile_expr(node.target.value)
                current = self.new_reg()
                name_index = self.add_name(node.target.attr)
                self.emit('ATTR', current, owner, name_index)
                self.emit(operation, current, current, right)
                self.emit('STORE_ATTR', owner, name_index, current)
                self.release_regs((owner, current))
            elif isinstance(node.target, ast.Subscript):
                owner = self.compile_expr(node.target.value)
                key = self.compile_expr(
                    node.target.slice.value
                    if isinstance(node.target.slice, ast.Index)
                    else node.target.slice)
                current = self.new_reg()
                self.emit('SUBSCR', current, owner, key)
                self.emit(operation, current, current, right)
                self.emit('STORE_SUBSCR', owner, key, current)
                self.release_regs((owner, key, current))
            self.release_reg(right)
            return
        if isinstance(node, ast.Global):
            return
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id in self.global_names:
                        self.emit('DELETE_GLOBAL', self.add_name(target.id))
                    else:
                        self.emit('DELETE_LOCAL', self.locals[target.id],
                                  self.add_name(target.id))
                elif isinstance(target, ast.Attribute):
                    owner = self.compile_expr(target.value)
                    self.emit('DELETE_ATTR', owner, self.add_name(target.attr))
                    self.release_reg(owner)
                elif isinstance(target, ast.Subscript):
                    owner = self.compile_expr(target.value)
                    key = self.compile_expr(
                        target.slice.value if isinstance(target.slice, ast.Index)
                        else target.slice)
                    self.emit('DELETE_SUBSCR', owner, key)
                    self.release_regs((owner, key))
            return
        if isinstance(node, ast.Assert):
            test = self.compile_expr(node.test)
            message = self.compile_expr(node.msg) if node.msg is not None else -1
            self.emit('ASSERT', test, message)
            self.release_regs((test, message))
            return
        if isinstance(node, ast.Raise):
            if hasattr(node, 'type'):
                # Python 2 Raise(type, inst, tback)
                exc_node = node.type
            else:
                # Python 3 Raise(exc, cause)
                exc_node = node.exc
            if exc_node is None:
                if not self.active_exception_regs:
                    raise ValueError('source VM bare raise outside handler')
                value = self.active_exception_regs[-1]
            else:
                value = self.compile_expr(exc_node)
            self.emit('RAISE', value)
            if exc_node is not None:
                self.release_reg(value)
            return
        if isinstance(node, ast.Expr):
            self.release_reg(self.compile_expr(node.value))
            return
        if isinstance(node, ast.Return):
            value = self.compile_expr(node.value) if node.value is not None else self.const_reg(None)
            self._emit_pending_finally()
            self.emit('RETURN', value)
            self.release_reg(value)
            return
        if isinstance(node, ast.If):
            if getattr(node, '_mcp_source_dead_flow', False):
                return
            test = self.compile_expr(node.test)
            false_jump = self.emit('JFALSE', test, -1)
            self.release_reg(test)
            for stmt in node.body:
                self.compile_stmt(stmt)
            if node.orelse:
                end_jump = self.emit('JUMP', -1)
                self.patch(false_jump, 2, len(self.instructions))
                for stmt in node.orelse:
                    self.compile_stmt(stmt)
                self.patch(end_jump, 1, len(self.instructions))
            else:
                self.patch(false_jump, 2, len(self.instructions))
            return
        try_finally = getattr(ast, 'TryFinally', None)
        if try_finally is not None and isinstance(node, try_finally):
            self._compile_try_finally(
                lambda: self._compile_statements(node.body), node.finalbody)
            return
        try_except = getattr(ast, 'TryExcept', None)
        if try_except is not None and isinstance(node, try_except):
            self._compile_try_except(node.body, node.handlers, node.orelse)
            return
        try_node = getattr(ast, 'Try', None)
        if try_node is not None and isinstance(node, try_node):
            if node.finalbody:
                self._compile_try_finally(
                    lambda: self._compile_try_except(
                        node.body, node.handlers, node.orelse),
                    node.finalbody)
            else:
                self._compile_try_except(node.body, node.handlers, node.orelse)
            return
        if isinstance(node, ast.While):
            start = len(self.instructions)
            test = self.compile_expr(node.test)
            exhausted = self.emit('JFALSE', test, -1)
            self.release_reg(test)
            context = {'continue': start, 'breaks': []}
            self.loop_stack.append(context)
            for stmt in node.body:
                self.compile_stmt(stmt)
            self.loop_stack.pop()
            self.emit('JUMP', start)
            else_start = len(self.instructions)
            self.patch(exhausted, 2, else_start)
            for stmt in node.orelse:
                self.compile_stmt(stmt)
            end = len(self.instructions)
            for index in context['breaks']:
                self.patch(index, 1, end)
            return
        if isinstance(node, ast.For):
            iterable = self.compile_expr(node.iter)
            iterator = self.new_reg()
            self.emit('ITER', iterator, iterable)
            self.release_reg(iterable)
            start = len(self.instructions)
            item = self.new_reg()
            exhausted = self.emit('NEXT', item, iterator, -1)
            self.store_target(node.target, item)
            self.release_reg(item)
            context = {'continue': start, 'breaks': []}
            self.loop_stack.append(context)
            for stmt in node.body:
                self.compile_stmt(stmt)
            self.loop_stack.pop()
            self.emit('JUMP', start)
            else_start = len(self.instructions)
            self.patch(exhausted, 3, else_start)
            for stmt in node.orelse:
                self.compile_stmt(stmt)
            end = len(self.instructions)
            for index in context['breaks']:
                self.patch(index, 1, end)
            self.release_reg(iterator)
            return
        if isinstance(node, ast.Break):
            if not self.loop_stack:
                raise ValueError('source VM break outside loop')
            self._emit_pending_finally()
            self.loop_stack[-1]['breaks'].append(self.emit('JUMP', -1))
            return
        if isinstance(node, ast.Continue):
            if not self.loop_stack:
                raise ValueError('source VM continue outside loop')
            self._emit_pending_finally()
            self.emit('JUMP', self.loop_stack[-1]['continue'])
            return
        if isinstance(node, ast.Pass):
            return
        raise ValueError('source VM statement unsupported: %s' % node.__class__.__name__)

    def compile(self, body):
        for stmt in body:
            self.compile_stmt(stmt)
        value = self.const_reg(None)
        self.emit('RETURN', value)
        self.release_reg(value)
        return self\n