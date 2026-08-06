# -*- coding: utf-8 -*-
"""Local and definition name transformations."""
from __future__ import absolute_import, print_function

import ast
import random

from MCP_Armor_Src.utils.encoding import (
    random_ident,
)


class LocalRenameCollector(ast.NodeVisitor):
    def __init__(self):
        self.assigned = set()
        self.names = set()
        self.unsafe = False

    def visit_FunctionDef(self, node):
        # The collector is run on a function body one statement at a time, so
        # reaching another FunctionDef means the parent owns a closure scope.
        # Renaming only the parent's STORE_FAST while leaving child free-var
        # loads untouched turns the captured name into a global at runtime.
        self.unsafe = True
        return

    def visit_ClassDef(self, node):
        # A class nested in a function can contain methods that close over
        # the function's locals. Renaming the outer STORE while leaving those
        # method loads untouched turns the captured value into a global.
        self.unsafe = True
        return

    def visit_Lambda(self, node):
        self.unsafe = True

    def visit_Global(self, node):
        self.unsafe = True

    def visit_Exec(self, node):
        self.unsafe = True

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in ('locals', 'globals', 'vars', 'eval', 'exec', 'dir'):
            self.unsafe = True
        self.generic_visit(node)

    def visit_Name(self, node):
        self.names.add(node.id)
        if isinstance(node.ctx, ast.Store) and not (node.id.startswith('__') and node.id.endswith('__')):
            self.assigned.add(node.id)


class LocalRenameApplier(ast.NodeTransformer):
    def __init__(self, mapping):
        self.mapping = mapping

    def visit_FunctionDef(self, node):
        return node

    def visit_ClassDef(self, node):
        return node

    def visit_Lambda(self, node):
        return node

    def visit_Name(self, node):
        if node.id in self.mapping:
            return ast.copy_location(ast.Name(id=self.mapping[node.id], ctx=node.ctx), node)
        return node


class SourceLocalRenamer(ast.NodeTransformer):
    def __init__(self, max_names=48):
        self.max_names = max(0, int(max_names or 0))

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if self.max_names <= 0 or getattr(node, 'decorator_list', None):
            return node
        collector = LocalRenameCollector()
        for stmt in node.body:
            collector.visit(stmt)
        if collector.unsafe:
            return node
        arg_names = set()
        for arg in getattr(node.args, 'args', []) or []:
            if isinstance(arg, ast.Name):
                arg_names.add(arg.id)
            elif isinstance(arg, str):
                arg_names.add(arg)
        skip = arg_names | set(['self', 'cls'])
        names = [name for name in sorted(collector.assigned) if name not in skip and not name.startswith('_0x')]
        if not names:
            return node
        random.shuffle(names)
        names = names[:self.max_names]
        mapping = {}
        used = set(collector.names) | skip
        for name in names:
            new_name = random_ident('lv')
            while new_name in used:
                new_name = random_ident('lv')
            used.add(new_name)
            mapping[name] = new_name
        node.body = [LocalRenameApplier(mapping).visit(stmt) for stmt in node.body]
        return node


def rename_source_locals(tree, max_names=48):
    tree = SourceLocalRenamer(max_names).visit(tree)
    ast.fix_missing_locations(tree)
    return tree


SOURCE_NAME_KEEP = set([
    'self', 'cls', 'args', 'arg', 'kwargs', 'event', 'eventData', 'data',
    'playerId', 'entityId', 'Main', 'Init', 'NeteaseModServerInit', 'NeteaseModClientInit',
    'RegisterSystem', 'ListenForEvent', 'UnListenForEvent', 'NotifyToServer',
    'NotifyToClient', 'GetEngineCompFactory', 'extraServerApi', 'extraClientApi',
    # Common cross-module NetEase config API names; modMain.py is intentionally
    # kept readable and calls these through ``import config as Config``.
    'modName', 'severModClassName', 'HPseverModClassName', 'severModPath',
    'clinetModClassName', 'clinetModPath',
])


def source_name_is_safe(name):
    if not name or name in SOURCE_NAME_KEEP:
        return False
    if name.startswith('__') and name.endswith('__'):
        return False
    if name.startswith('_0x') or name.startswith('_ghost_'):
        return False
    # Long pre-obfuscated/exported names are commonly imported by sibling
    # modules (for example getapi.py). Renaming them without project-wide
    # symbol analysis would break ``from module import name``.
    if len(name) >= 20:
        return False
    lowered = name.lower()
    for marker in ('init', 'register', 'listen', 'event', 'system', 'server', 'client'):
        if marker in lowered:
            return False
    return True


class SourceDefinitionNameCollector(ast.NodeVisitor):
    def __init__(self):
        self.names = set()
        self.strings = set()
        self.imported = set()
        self.protected = set()
        self.class_bases = {}
        self.custom_metaclass_roots = set()
        self.in_class = 0
        self.in_function = 0

    def visit_Str(self, node):
        self.strings.add(node.s)

    def visit_Import(self, node):
        for alias in node.names:
            self.imported.add(alias.asname or alias.name.split('.')[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name != '*':
                self.imported.add(alias.asname or alias.name)

    def visit_Call(self, node):
        api_name = None
        if isinstance(node.func, ast.Name):
            api_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            api_name = node.func.attr
        if api_name in ('RegisterSystem', 'ListenForEvent', 'UnListenForEvent'):
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    self.protected.add(arg.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if not self.in_class and not self.in_function and source_name_is_safe(node.name):
            self.names.add(node.name)
        self.in_function += 1
        self.generic_visit(node)
        self.in_function -= 1

    def visit_ClassDef(self, node):
        bases = set()
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.add(base.id)
            elif isinstance(base, ast.Attribute):
                bases.add(base.attr)
        self.class_bases[node.name] = bases
        for statement in node.body:
            if not isinstance(statement, ast.Assign):
                continue
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id == '__metaclass__':
                    self.custom_metaclass_roots.add(node.name)
        if not self.in_function and source_name_is_safe(node.name):
            self.names.add(node.name)
        self.in_class += 1
        self.generic_visit(node)
        self.in_class -= 1

    def custom_metaclass_classes(self):
        """Return custom-metaclass roots and all local descendants.

        Their runtime ``name`` is observable by metaclass registration logic,
        so changing it is a behavior change rather than a cosmetic rename.
        """
        protected = set(self.custom_metaclass_roots)
        changed = True
        while changed:
            changed = False
            for name, bases in self.class_bases.items():
                if name not in protected and bases.intersection(protected):
                    protected.add(name)
                    changed = True
        return protected


class SourceDefinitionNameApplier(ast.NodeTransformer):
    def __init__(self, mapping):
        self.mapping = mapping
        self.shadowed = []
        self.function_depth = 0
        self.class_depth = 0

    def is_shadowed(self, name):
        return any(name in scope for scope in reversed(self.shadowed))

    def function_bindings(self, node):
        collector = LocalRenameCollector()
        for stmt in node.body:
            collector.visit(stmt)
        bound = set(collector.assigned)
        globals_used = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                globals_used.update(child.names)
        for arg in getattr(node.args, 'args', []) or []:
            if isinstance(arg, ast.Name):
                bound.add(arg.id)
            elif isinstance(arg, str):
                bound.add(arg)
        if node.args.vararg:
            bound.add(node.args.vararg)
        if node.args.kwarg:
            bound.add(node.args.kwarg)
        return bound - globals_used

    def visit_FunctionDef(self, node):
        if not hasattr(node, '_mcp_source_original_name'):
            node._mcp_source_original_name = node.name
        module_level = self.function_depth == 0 and self.class_depth == 0
        if module_level and node.name in self.mapping:
            node.name = self.mapping[node.name]
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        bindings = self.function_bindings(node)
        self.shadowed.append(bindings)
        self.function_depth += 1
        node.body = [self.visit(stmt) for stmt in node.body]
        self.function_depth -= 1
        self.shadowed.pop()
        return node

    def visit_ClassDef(self, node):
        module_level = self.function_depth == 0 and self.class_depth == 0
        if module_level and node.name in self.mapping:
            node.name = self.mapping[node.name]
        node.decorator_list = [self.visit(item) for item in getattr(node, 'decorator_list', [])]
        node.bases = [self.visit(item) for item in node.bases]
        self.class_depth += 1
        node.body = [self.visit(stmt) for stmt in node.body]
        self.class_depth -= 1
        return node

    def visit_Lambda(self, node):
        bindings = set()
        for arg in getattr(node.args, 'args', []) or []:
            if isinstance(arg, ast.Name):
                bindings.add(arg.id)
        if node.args.vararg:
            bindings.add(node.args.vararg)
        if node.args.kwarg:
            bindings.add(node.args.kwarg)
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        self.shadowed.append(bindings)
        node.body = self.visit(node.body)
        self.shadowed.pop()
        return node

    def visit_Name(self, node):
        if node.id in self.mapping and not self.is_shadowed(node.id):
            return ast.copy_location(ast.Name(id=self.mapping[node.id], ctx=node.ctx), node)
        return node


def obfuscate_source_definition_names(tree, max_names=64,
                                      protected_names=None):
    collector = SourceDefinitionNameCollector()
    collector.visit(tree)
    protected_names = set(protected_names or ())
    protected_names.update(collector.custom_metaclass_classes())
    candidates = [name for name in sorted(collector.names)
                  if name not in collector.imported and
                  name not in collector.protected and
                  name not in collector.strings and
                  name not in protected_names]
    random.shuffle(candidates)
    candidates = candidates[:max(0, int(max_names or 0))]
    used = set(collector.imported) | set(collector.names)
    mapping = {}
    for name in candidates:
        new_name = random_ident('fn')
        while new_name in used:
            new_name = random_ident('fn')
        used.add(new_name)
        mapping[name] = new_name
    if mapping:
        tree = SourceDefinitionNameApplier(mapping).visit(tree)
        ast.fix_missing_locations(tree)
    return tree
