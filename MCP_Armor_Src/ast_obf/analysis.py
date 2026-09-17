# -*- coding: utf-8 -*-
"""Conservative source call-graph and transformation budget analysis."""


import ast
import fnmatch
import os


DEFAULT_HOT_PATTERNS = (
    'On*', '*Tick*', '*Update*', '*Timer*', '*Frame*', '*Render*',
    'Listen*', 'Notify*', 'Callback', 'Destroy', '__*__',
)


class SourceFunctionInfo(object):
    def __init__(self, name, qualname, class_name, node):
        self.name = name
        self.qualname = qualname
        self.class_name = class_name
        self.node_count = sum(1 for _ in ast.walk(node))
        self.decorators = len(getattr(node, 'decorator_list', ()) or ())
        self.defaults = len(getattr(node.args, 'defaults', ()) or ())
        self.vararg = bool(getattr(node.args, 'vararg', None))
        self.kwarg = bool(getattr(node.args, 'kwarg', None))
        tail = qualname
        if class_name and tail.startswith(class_name + '.'):
            tail = tail[len(class_name) + 1:]
        self.nested = '.' in tail
        self.direct_calls = 0
        self.loads = 0
        self.escaped = False
        self.hot = False
        self.hot_depth = None
        self.budget = 100
        self.internal_predicate = False
        self.callees = set()


class SourceModuleAnalysis(object):
    def __init__(self, path=None, hot_patterns=None):
        self.path = os.path.abspath(path) if path else None
        self.hot_patterns = tuple(hot_patterns or DEFAULT_HOT_PATTERNS)
        self.functions = {}
        self.module_functions = {}
        self.class_methods = {}
        self.loaded_names = set()
        self.loaded_attrs = set()
        self.imported_names = set()
        self.string_names = set()
        self.external_names = set()
        self.dynamic_module = False
        self.dynamic_classes = set()
        self.stats = {}

    def info_for(self, qualname):
        return self.functions.get(qualname)

    def finalize(self, predicate_ratio=70):
        candidates = 0
        for info in list(self.functions.values()):
            info.hot = any(fnmatch.fnmatch(info.name, pattern)
                           for pattern in self.hot_patterns)
            info.hot_depth = 0 if info.hot else None
        pending = [item for item in list(self.functions.values()) if item.hot]
        while pending:
            current = pending.pop()
            for qualname in current.callees:
                target = self.functions.get(qualname)
                depth = current.hot_depth + 1
                if (target is None or
                        (target.hot_depth is not None and
                         target.hot_depth <= depth)):
                    continue
                target.hot_depth = depth
                pending.append(target)
        for info in list(self.functions.values()):
            if info.hot_depth is not None and info.hot_depth <= 1:
                info.budget = 0
            elif info.hot_depth == 2:
                info.budget = 15
            elif info.hot_depth == 3:
                info.budget = 35
            elif info.hot_depth is not None:
                info.budget = 60
            elif info.node_count > 1200:
                info.budget = 20
            elif info.node_count > 600:
                info.budget = 35
            elif info.node_count > 280:
                info.budget = 55
            elif info.node_count < 12:
                info.budget = 45
            else:
                info.budget = 100
            closed = (
                info.hot_depth is None and not info.escaped and not info.nested and
                not info.decorators and not info.defaults and
                not info.vararg and not info.kwarg and info.direct_calls > 0)
            if info.class_name:
                closed = (closed and info.name.startswith('_') and
                          not (info.name.startswith('__') and
                               info.name.endswith('__')) and
                          info.class_name not in self.dynamic_classes)
            else:
                closed = (closed and info.name.startswith('_') and
                          not self.dynamic_module)
            info.internal_predicate = False
            if closed:
                score = sum(ord(ch) for ch in info.qualname) % 100
                info.internal_predicate = score < max(
                    0, min(100, int(predicate_ratio or 0)))
            if info.internal_predicate:
                candidates += 1
        self.stats = {
            'functions': len(self.functions),
            'hot': sum(1 for item in list(self.functions.values()) if item.hot),
            'reachable': sum(1 for item in list(self.functions.values())
                             if item.hot_depth is not None),
            'escaped': sum(1 for item in list(self.functions.values())
                           if item.escaped),
            'internal': candidates,
        }
        return self


class _DefinitionCollector(ast.NodeVisitor):
    def __init__(self, result):
        self.result = result
        self.classes = []
        self.functions = []

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        self.generic_visit(node)
        self.classes.pop()

    def visit_FunctionDef(self, node):
        parts = list(self.classes) + list(self.functions) + [node.name]
        qualname = '.'.join(parts)
        class_name = self.classes[-1] if self.classes else None
        info = SourceFunctionInfo(node.name, qualname, class_name, node)
        self.result.functions[qualname] = info
        if class_name and not self.functions:
            self.result.class_methods.setdefault(class_name, {})[node.name] = info
        elif not class_name and not self.functions:
            self.result.module_functions[node.name] = info
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()


class _ReferenceCollector(ast.NodeVisitor):
    DYNAMIC_NAMES = set(('globals', 'locals', 'vars', 'eval', 'execfile'))
    REFLECTION_NAMES = set(('getattr', 'setattr', 'hasattr', 'delattr'))

    def __init__(self, result):
        self.result = result
        self.classes = []
        self.functions = []

    def visit_FunctionDef(self, node):
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    def _current_info(self):
        if not self.functions:
            return None
        qualname = '.'.join(self.classes + self.functions)
        return self.result.functions.get(qualname)

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        self.generic_visit(node)
        self.classes.pop()

    def _module_info(self, name):
        return self.result.module_functions.get(name)

    def _method_info(self, name):
        if not self.classes:
            return None
        return self.result.class_methods.get(self.classes[-1], {}).get(name)

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Name):
            info = self._module_info(func.id)
            if info is not None:
                info.direct_calls += 1
                current = self._current_info()
                if current is not None:
                    current.callees.add(info.qualname)
            if func.id in self.DYNAMIC_NAMES:
                self.result.dynamic_module = True
            if func.id in self.REFLECTION_NAMES:
                owner = node.args[0] if node.args else None
                name = node.args[1] if len(node.args) > 1 else None
                dynamic_name = not isinstance(name, ast.Str)
                if isinstance(name, ast.Str):
                    self.result.string_names.add(name.s)
                if isinstance(owner, ast.Name) and owner.id in ('self', 'cls'):
                    if self.classes and dynamic_name:
                        self.result.dynamic_classes.add(self.classes[-1])
                elif dynamic_name:
                    self.result.dynamic_module = True
        elif (isinstance(func, ast.Attribute) and
              isinstance(func.value, ast.Name) and
              func.value.id in ('self', 'cls')):
            info = self._method_info(func.attr)
            if info is not None:
                info.direct_calls += 1
                current = self._current_info()
                if current is not None:
                    current.callees.add(info.qualname)
        self.visit(func)
        for arg in node.args:
            self.visit(arg)
        for keyword in node.keywords:
            self.visit(keyword.value)
        if getattr(node, 'starargs', None) is not None:
            self.visit(node.starargs)
        if getattr(node, 'kwargs', None) is not None:
            self.visit(node.kwargs)

    def visit_Name(self, node):
        if not isinstance(node.ctx, ast.Load):
            return
        self.result.loaded_names.add(node.id)
        info = self._module_info(node.id)
        if info is not None:
            info.loads += 1

    def visit_Attribute(self, node):
        if isinstance(node.ctx, ast.Load):
            self.result.loaded_attrs.add(node.attr)
            if (isinstance(node.value, ast.Name) and
                    node.value.id in ('self', 'cls')):
                info = self._method_info(node.attr)
                if info is not None:
                    info.loads += 1
            else:
                for methods in list(self.result.class_methods.values()):
                    info = methods.get(node.attr)
                    if info is not None:
                        info.loads += 1
        self.visit(node.value)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.result.loaded_names.add(alias.name)
            if alias.name != '*':
                self.result.imported_names.add(alias.name)

    def visit_Str(self, node):
        if node.s in self.result.module_functions:
            self.result.string_names.add(node.s)
        for methods in list(self.result.class_methods.values()):
            if node.s in methods:
                self.result.string_names.add(node.s)


def analyze_source_tree(tree, path=None, hot_patterns=None,
                        predicate_ratio=70):
    result = SourceModuleAnalysis(path, hot_patterns)
    _DefinitionCollector(result).visit(tree)
    _ReferenceCollector(result).visit(tree)
    for info in list(result.functions.values()):
        if info.loads > info.direct_calls or info.name in result.string_names:
            info.escaped = True
    return result.finalize(predicate_ratio)


def analyze_source(source, path=None, hot_patterns=None, predicate_ratio=70):
    return analyze_source_tree(
        ast.parse(source), path, hot_patterns, predicate_ratio)


def analyze_source_project(root, hot_patterns=None, predicate_ratio=70):
    root = os.path.abspath(root)
    analyses = {}
    for current, dirs, files in os.walk(root):
        for name in files:
            if not name.lower().endswith('.py'):
                continue
            path = os.path.abspath(os.path.join(current, name))
            try:
                with open(path, 'rb') as handle:
                    source = handle.read()
                analyses[path] = analyze_source(
                    source, path, hot_patterns, predicate_ratio)
            except (SyntaxError, ValueError, TypeError):
                continue
    for path, analysis in list(analyses.items()):
        foreign_names = set()
        foreign_imported_names = set()
        foreign_attrs = set()
        foreign_strings = set()
        for other_path, other in list(analyses.items()):
            if other_path == path:
                continue
            foreign_names.update(other.loaded_names)
            foreign_imported_names.update(other.imported_names)
            foreign_attrs.update(other.loaded_attrs)
            foreign_strings.update(other.string_names)
        # Module-level definitions form a project ABI.  Keep names used by a
        # sibling through ``from x import y``, ``x.y`` or reflective strings;
        # per-file renaming has no cross-module rewrite table and must not
        # silently remove those exported bindings.
        analysis.external_names = (
            foreign_imported_names | foreign_attrs | foreign_strings)
        escaped = set()
        for info in list(analysis.functions.values()):
            if (info.name in foreign_names or info.name in foreign_attrs or
                    info.name in foreign_strings):
                info.escaped = True
                escaped.add(info.qualname)
        analysis.finalize(predicate_ratio)
        for qualname in escaped:
            analysis.functions[qualname].internal_predicate = False
    return analyses


class _AnalysisAnnotator(ast.NodeVisitor):
    def __init__(self, analysis):
        self.analysis = analysis
        self.classes = []
        self.functions = []

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        self.generic_visit(node)
        self.classes.pop()

    def visit_FunctionDef(self, node):
        qualname = '.'.join(self.classes + self.functions + [node.name])
        info = self.analysis.info_for(qualname)
        if info is not None:
            node._mcp_source_qualname = qualname
            node._mcp_source_hot = info.hot
            node._mcp_source_hot_depth = info.hot_depth
            node._mcp_source_cost_budget = info.budget
            node._mcp_source_internal_predicate = info.internal_predicate
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()


def annotate_source_tree(tree, analysis):
    if analysis is not None:
        _AnalysisAnnotator(analysis).visit(tree)
    return tree
