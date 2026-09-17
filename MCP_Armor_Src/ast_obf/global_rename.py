# -*- coding: utf-8 -*-
"""Project-wide, scope-aware source identifier renaming.

The planner sees every Python module before any file is transformed.  It can
therefore rewrite imports and module attributes consistently, while treating
files excluded from AST processing as immutable ABI consumers.
"""

import ast
import fnmatch
import keyword
import os
import re

from MCP_Armor_Src.utils.encoding import short_ident


try:
    _TEXT_TYPES = (basestring,)
except NameError:
    _TEXT_TYPES = (str,)


NETEASE_RESERVED_NAMES = set((
    # Python data model and common engine construction hooks.
    'self', 'cls', '__init__', '__new__', '__del__', '__getattr__',
    '__getattribute__', '__setattr__', '__enter__', '__exit__',
    '__iter__', '__next__', 'next',
    # Mod lifecycle decorators and their conventional method names.
    'Main', 'Init', 'InitClient', 'InitServer', 'Destroy',
    'DestroyClient', 'DestroyServer', 'NeteaseModClientInit',
    'NeteaseModServerInit',
    # Engine/system/UI callbacks that can be discovered by convention.
    'Update', 'Tick', 'Create', 'OnCreate', 'OnDestroy', 'OnTick',
    'OnScriptTickClient', 'OnScriptTickServer', 'OnGameTick',
    'OnUpdate', 'OnFrame', 'OnRender',
    # SDK registration, event and RPC surface.
    'RegisterSystem', 'UnregisterSystem', 'RegisterUI', 'CreateUI',
    'ListenForEvent', 'UnListenForEvent', 'UnListenAllEvents',
    'NotifyToServer', 'NotifyToClient', 'NotifyToMultiClients',
    'BroadcastEvent', 'BroadcastToAllClient',
    'GetEngineNamespace', 'GetEngineSystemName',
    'GetEngineCompFactory', 'GetServerSystemCls', 'GetClientSystemCls',
    'extraServerApi', 'extraClientApi',
    # Common modMain/config exports used as string ABI.
    'modName', 'modVersion', 'severModClassName', 'HPseverModClassName',
    'severModPath', 'clinetModClassName', 'clinetModPath',
    # Command/event registries are inspected by the host and by sibling UI
    # modules while import decorators are running.  Keep these explicit even
    # though most are dunder-shaped: legacy rename passes and generated
    # source loaders may not preserve dunder metadata consistently.
))

NETEASE_DECORATORS = set((
    'Binding', 'InitClient', 'InitServer', 'DestroyClient', 'DestroyServer',
    'Init', 'Destroy',
))

NETEASE_CALLBACK_APIS = set((
    'ListenForEvent', 'UnListenForEvent', 'RegisterSystem', 'RegisterUI',
    'RegisterComponent', 'RegisterComponentFactory',
))

NETEASE_RESERVED_PATTERNS = (
    'OnScriptTick*', '*TickClient', '*TickServer', '*GameTick*',
)

# Only Python data-model hooks need their spelling preserved.  Internal
# registries/decorators such as ``__commands__`` and ``__bind_command__`` are
# ordinary project symbols and can be renamed when every reference is updated
# by the project graph.
PYTHON_PROTOCOL_DUNDERS = set((
    '__init__', '__new__', '__del__', '__repr__', '__str__', '__unicode__',
    '__bytes__', '__format__', '__hash__', '__bool__', '__nonzero__',
    '__getattr__', '__getattribute__', '__setattr__', '__delattr__',
    '__dir__', '__call__', '__iter__', '__next__', '__getitem__',
    '__setitem__', '__delitem__', '__contains__', '__len__', '__enter__',
    '__exit__', '__get__', '__set__', '__delete__', '__set_name__',
    '__eq__', '__ne__', '__lt__', '__le__', '__gt__', '__ge__',
    '__add__', '__sub__', '__mul__', '__div__', '__truediv__',
    '__floordiv__', '__mod__', '__pow__', '__neg__', '__pos__', '__invert__',
    '__and__', '__or__', '__xor__', '__lshift__', '__rshift__',
    '__enter__', '__exit__', '__reduce__', '__reduce_ex__', '__copy__',
    '__deepcopy__', '__getstate__', '__setstate__',
))

DYNAMIC_SCOPE_NAMES = set((
    'globals', 'locals', 'vars', 'eval', 'exec', 'execfile', 'compile',
))

REFLECTION_NAMES = set(('getattr', 'setattr', 'hasattr', 'delattr'))

# Builtins whose lookup can be safely cached behind a short module-local alias.
# Runtime filtering keeps Python 2-only names out of Python 3 output and vice
# versa (notably ``print``, which is syntax rather than a Name on Python 2).
BUILTIN_ALIAS_CANDIDATES = set((
    'abs', 'all', 'any', 'bin', 'bool', 'bytearray', 'bytes', 'callable',
    'chr', 'classmethod', 'cmp', 'complex', 'dict', 'divmod', 'enumerate',
    'filter', 'float', 'format', 'frozenset', 'hash', 'hex', 'int',
    'isinstance', 'issubclass', 'iter', 'len', 'list', 'long', 'map', 'max',
    'min', 'next', 'object', 'oct', 'open', 'ord', 'pow', 'print', 'property',
    'range', 'reduce', 'repr', 'reversed', 'round', 'set', 'slice', 'sorted',
    'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'unicode',
    'xrange', 'zip',
    'ArithmeticError', 'AssertionError', 'AttributeError', 'EOFError',
    'EnvironmentError', 'Exception', 'IOError', 'ImportError', 'IndexError',
    'KeyError', 'LookupError', 'NameError', 'NotImplementedError', 'OSError',
    'OverflowError', 'RuntimeError', 'StandardError', 'StopIteration',
    'SyntaxError', 'SystemError', 'TypeError', 'ValueError', 'WindowsError',
    'ZeroDivisionError',
))


def _runtime_builtin_aliases():
    try:
        import builtins as runtime_builtins
    except ImportError:  # Python 2
        import __builtin__ as runtime_builtins
    return BUILTIN_ALIAS_CANDIDATES.intersection(dir(runtime_builtins))


RUNTIME_BUILTIN_ALIASES = _runtime_builtin_aliases()


def _string_value(node):
    if isinstance(node, ast.Str):
        return node.s
    constant = getattr(ast, 'Constant', None)
    if constant is not None and isinstance(node, constant):
        return node.value if isinstance(node.value, str) else None
    return None


def _decorator_tail(node):
    while isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _call_tail(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_dunder(name):
    return bool(name and name.startswith('__') and name.endswith('__'))


def _is_internal_dunder(name):
    """Return true for project-private dunders, not language protocols."""
    return _is_dunder(name) and name not in PYTHON_PROTOCOL_DUNDERS


def _is_netease_reserved(name):
    if not name or name in NETEASE_RESERVED_NAMES:
        return True
    if _is_dunder(name):
        return name in PYTHON_PROTOCOL_DUNDERS
    return any(fnmatch.fnmatch(name, pattern)
               for pattern in NETEASE_RESERVED_PATTERNS)


def _target_names(node):
    result = []
    if isinstance(node, ast.Name):
        result.append(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            result.extend(_target_names(item))
    return result


def _module_name(root, path):
    rel = os.path.relpath(path, root).replace('\\', '/')
    rel = rel[:-3] if rel.lower().endswith('.py') else rel
    parts = [part for part in rel.split('/') if part]
    is_package = bool(parts and parts[-1] == '__init__')
    if is_package:
        parts.pop()
    return '.'.join(parts), is_package


def _requires_reflection_compatibility(source):
    """Mirror the loader's live-frame compatibility gate for the planner."""
    if isinstance(source, bytes):
        try:
            source = source.decode('utf-8', 'replace')
        except Exception:
            return False
    lowered = source.lower()
    reflection_tokens = (
        '__subclasses__', '__mro__', '__globals__', 'func_globals',
        'f_locals', 'f_globals', '__builtins__',
    )
    execution_tokens = (
        'eval(', 'exec(', 'exec ', 'compile(', '__import__',
    )
    return (sum(token in lowered for token in reflection_tokens) >= 2 and
            sum(token in lowered for token in execution_tokens) >= 1)


def _resolve_import(current, is_package, module, level):
    module = module or ''
    if not level:
        return module
    package = current if is_package else current.rpartition('.')[0]
    parts = [part for part in package.split('.') if part]
    trim = max(0, int(level) - 1)
    if trim:
        parts = parts[:-trim] if trim <= len(parts) else []
    if module:
        parts.extend(module.split('.'))
    return '.'.join(parts)


class _ModuleInfo(object):
    def __init__(self, path, module, is_package, excluded):
        self.path = os.path.abspath(path)
        self.module = module
        self.is_package = is_package
        self.excluded = bool(excluded)
        # Reflection/bootstrap modules are intentionally emitted source-identical
        # by the processor.  They are still parsed so their explicit imports and
        # attribute references can form an ABI boundary, but their local eval/
        # globals usage must not disable renaming for the entire project.
        self.reflection_compatibility = False
        self.tree = None
        self.globals = set()
        self.loaded_names = set()
        self.classes = set()
        self.members = set()
        self.strings = set()
        self.keyword_names = set()
        self.protected = set(NETEASE_RESERVED_NAMES)
        self.dynamic_module = False
        self.dynamic_members = False
        self.import_from = []
        self.import_modules = {}
        self.class_bindings = set()
        self.known_instances = set()
        self.attribute_rows = []
        self.wildcard_imports = []


class _ProjectCollector(ast.NodeVisitor):
    def __init__(self, info):
        self.info = info
        self.class_stack = []
        self.function_depth = 0

    def visit_Import(self, node):
        for alias in node.names:
            binding = alias.asname or alias.name.split('.')[0]
            target = alias.name if alias.asname else alias.name.split('.')[0]
            self.info.import_modules[binding] = target
            # ``import package.child`` binds ``package`` whereas adding an
            # alias would bind ``package.child``.  Keep that uncommon form
            # unchanged rather than silently changing its runtime object.
            if alias.asname or '.' not in alias.name:
                self.info.globals.add(binding)

    def visit_ImportFrom(self, node):
        target = _resolve_import(
            self.info.module, self.info.is_package,
            node.module, getattr(node, 'level', 0))
        for alias in node.names:
            if alias.name == '*':
                self.info.wildcard_imports.append(target)
            else:
                binding = alias.asname or alias.name
                self.info.import_from.append((target, alias.name,
                                              binding))
                self.info.globals.add(binding)

    def visit_FunctionDef(self, node):
        if not self.class_stack and not self.function_depth:
            self.info.globals.add(node.name)
        elif self.class_stack and not self.function_depth:
            self.info.members.add(node.name)
        if any(_decorator_tail(item) in NETEASE_DECORATORS
               for item in getattr(node, 'decorator_list', ()) or ()):
            self.info.protected.add(node.name)
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        if not self.class_stack and not self.function_depth:
            self.info.globals.add(node.name)
            self.info.classes.add(node.name)
        self.class_stack.append(node.name)
        for statement in node.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    self.info.members.update(_target_names(target))
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_Assign(self, node):
        if not self.class_stack and not self.function_depth:
            for target in node.targets:
                self.info.globals.update(_target_names(target))
        for target in node.targets:
            if (isinstance(target, ast.Attribute) and
                    isinstance(target.value, ast.Name) and
                    target.value.id in ('self', 'cls')):
                self.info.members.add(target.attr)
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self.info.loaded_names.add(node.id)
        if isinstance(node.ctx, ast.Store) and not self.function_depth:
            if self.class_stack:
                self.info.members.add(node.id)
            else:
                self.info.globals.add(node.id)

    def visit_ExceptHandler(self, node):
        name = getattr(node, 'name', None)
        binding = name.id if isinstance(name, ast.Name) else name
        if isinstance(binding, _TEXT_TYPES) and not self.function_depth:
            # Exception targets have different AST representations between
            # Python 2 and Python 3.  Keep them as a small ABI boundary: a
            # mismatched target/body rename only surfaces when the exception
            # path runs, which makes this class of defect especially costly.
            self.info.protected.add(binding)
            if self.class_stack:
                self.info.members.add(binding)
            else:
                self.info.globals.add(binding)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if not self.class_stack and not self.function_depth:
            self.info.globals.update(_target_names(node.target))
        self.generic_visit(node)

    def visit_Call(self, node):
        tail = _call_tail(node.func)
        for keyword_node in getattr(node, 'keywords', ()) or ():
            if getattr(keyword_node, 'arg', None):
                self.info.keyword_names.add(keyword_node.arg)
        if tail in DYNAMIC_SCOPE_NAMES:
            if tail in ('globals', 'eval', 'exec', 'execfile', 'compile'):
                self.info.dynamic_module = True
            if tail in ('vars',):
                self.info.dynamic_members = True
        if tail in REFLECTION_NAMES and len(node.args) > 1:
            value = _string_value(node.args[1])
            if value:
                self.info.strings.add(value)
                self.info.protected.add(value)
            else:
                self.info.dynamic_members = True
        if tail in NETEASE_CALLBACK_APIS:
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    self.info.protected.add(arg.id)
                elif isinstance(arg, ast.Attribute):
                    self.info.protected.add(arg.attr)
                value = _string_value(arg)
                if value:
                    for part in re.split(r'[^A-Za-z0-9_]+', value):
                        if part:
                            self.info.protected.add(part)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        self.info.attribute_rows.append((node.value, node.attr))
        if node.attr in ('__dict__', '__members__'):
            self.info.dynamic_members = True
        self.generic_visit(node)

    def visit_Exec(self, node):
        self.info.dynamic_module = True
        self.generic_visit(node)

    def visit_Str(self, node):
        if isinstance(node.s, str):
            self.info.strings.add(node.s)
            for part in re.split(r'[^A-Za-z0-9_]+', node.s):
                if part:
                    self.info.protected.add(part)

    def visit_Constant(self, node):
        value = _string_value(node)
        if value is not None:
            self.info.strings.add(value)
            for part in re.split(r'[^A-Za-z0-9_]+', value):
                if part:
                    self.info.protected.add(part)


class GlobalRenameProject(object):
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.root_package = os.path.basename(self.root)
        self.infos = {}
        self.modules = {}
        self.global_maps = {}
        self.builtin_maps = {}
        self.member_map = {}
        self.keyword_names = set()
        self.reserved = set(NETEASE_RESERVED_NAMES)

    def normalize_module(self, module):
        if module in self.modules:
            return module
        prefix = self.root_package + '.'
        if module and module.startswith(prefix):
            inner = module[len(prefix):]
            if inner in self.modules:
                return inner
        # NetEase loads a project directory under its manifest package name
        # (usually ``nornwave``), while the source tree may have a different
        # local folder name.  Resolve that runtime prefix by the uniquely
        # matching module suffix so ``from nornwave.main import __commands__``
        # receives the same project-wide rename map as ``main.py``.
        if module and '.' in module:
            suffix = module.rsplit('.', 1)[-1]
            if suffix in self.modules:
                return suffix
        return module

    def module_info(self, module):
        return self.modules.get(self.normalize_module(module))

    def globals_for(self, module):
        return self.global_maps.get(self.normalize_module(module), {})

    def plan_for(self, path):
        info = self.infos.get(os.path.abspath(path))
        if info is None:
            return None
        return GlobalRenamePlan(self, info)


class GlobalRenamePlan(object):
    def __init__(self, project, info):
        self.project = project
        self.info = info
        self.module = info.module
        self.excluded = info.excluded
        self.own_globals = project.global_maps.get(info.module, {})
        self.builtin_map = project.builtin_maps.get(info.module, {})
        self.member_map = project.member_map


def _owner_is_known(info, owner, project):
    if isinstance(owner, ast.Name):
        return (owner.id in ('self', 'cls') or
                owner.id in info.classes or
                owner.id in info.class_bindings or
                owner.id in info.known_instances or
                owner.id in info.import_modules)
    if isinstance(owner, ast.Attribute):
        root = owner
        while isinstance(root, ast.Attribute):
            root = root.value
        return isinstance(root, ast.Name) and root.id in info.import_modules
    if isinstance(owner, ast.Call):
        func = owner.func
        if isinstance(func, ast.Name):
            return func.id in info.classes or func.id in info.class_bindings
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            target = info.import_modules.get(func.value.id)
            provider = project.module_info(target)
            return provider is not None and func.attr in provider.classes
    return False


class _KnownInstanceCollector(ast.NodeVisitor):
    def __init__(self, info, project):
        self.info = info
        self.project = project

    def _constructor(self, value):
        if not isinstance(value, ast.Call):
            return False
        func = value.func
        if isinstance(func, ast.Name):
            return func.id in self.info.classes or func.id in self.info.class_bindings
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            target = self.info.import_modules.get(func.value.id)
            provider = self.project.module_info(target)
            return provider is not None and func.attr in provider.classes
        return False

    def visit_Assign(self, node):
        if self._constructor(node.value):
            for target in node.targets:
                self.info.known_instances.update(_target_names(target))
        self.generic_visit(node)


def _excluded_cross_boundary_names(project):
    protected = set()
    unknown_attrs = set()
    dynamic = False
    boundary_strings = set()
    for info in list(project.infos.values()):
        if not info.excluded:
            continue
        if info.dynamic_module and not info.reflection_compatibility:
            dynamic = True
        boundary_strings.update(info.strings)
        for owner, attr in info.attribute_rows:
            if not _owner_is_known(info, owner, project):
                unknown_attrs.add(attr)
        for target, name, _binding in info.import_from:
            normalized = project.normalize_module(target)
            if normalized in project.modules:
                protected.add((normalized, name))
        for target in info.wildcard_imports:
            normalized = project.normalize_module(target)
            provider = project.module_info(target)
            if provider is not None:
                for name in provider.globals:
                    protected.add((normalized, name))
        for owner, attr in info.attribute_rows:
            if isinstance(owner, ast.Name):
                target = info.import_modules.get(owner.id)
                normalized = project.normalize_module(target)
                if normalized in project.modules:
                    protected.add((normalized, attr))
    if dynamic:
        for target, provider in list(project.modules.items()):
            for name in provider.globals:
                protected.add((target, name))
    if unknown_attrs:
        for target, provider in list(project.modules.items()):
            for name in provider.globals:
                if name in unknown_attrs:
                    protected.add((target, name))
    if boundary_strings:
        for target, provider in list(project.modules.items()):
            for name in provider.globals:
                if name in boundary_strings:
                    protected.add((target, name))
    return protected


def build_global_rename_project(root, excluded_paths=None, allowed_paths=None):
    """Build one deterministic rename graph for all Python files below root."""
    project = GlobalRenameProject(root)
    excluded = set(os.path.abspath(path) for path in (excluded_paths or ()))
    allowed = (set(os.path.abspath(path) for path in allowed_paths)
               if allowed_paths is not None else None)
    for current, dirs, files in os.walk(project.root):
        dirs[:] = [name for name in dirs if name not in (
            '__pycache__', '.git', '.svn')]
        for name in files:
            if not name.lower().endswith('.py'):
                continue
            path = os.path.abspath(os.path.join(current, name))
            if allowed is not None and path not in allowed:
                continue
            module, is_package = _module_name(project.root, path)
            info = _ModuleInfo(path, module, is_package, path in excluded)
            try:
                with open(path, 'rb') as handle:
                    source = handle.read()
                info.tree = ast.parse(source)
            except (SyntaxError, ValueError, TypeError):
                info.excluded = True
                project.infos[path] = info
                project.modules[module] = info
                continue
            if _requires_reflection_compatibility(source):
                info.excluded = True
                info.reflection_compatibility = True
            _ProjectCollector(info).visit(info.tree)
            project.infos[path] = info
            project.modules[module] = info
            project.keyword_names.update(info.keyword_names)
            project.reserved.update(info.protected)

    cross_boundary = _excluded_cross_boundary_names(project)
    # Attribute references whose owner cannot be resolved statically are an
    # ABI boundary for project modules.  They commonly come from lazy module
    # getters (``m = _get_feature(); m.set_speed(value)``) and are later
    # rewritten by the reference obfuscator into ``getattr(m, 'set_speed')``.
    # Renaming the provider's module-level ``set_speed`` would leave that
    # dynamic lookup pointing at a stale spelling.  Keep such exported names
    # stable across the project; direct, statically-resolved module accesses
    # still use the per-module map below.
    dynamic_attribute_names = set()
    for info in list(project.infos.values()):
        for owner, attr in info.attribute_rows:
            if not _owner_is_known(info, owner, project):
                dynamic_attribute_names.add(attr)
    wildcard_targets = set()
    for info in list(project.infos.values()):
        wildcard_targets.update(
            project.normalize_module(target)
            for target in info.wildcard_imports)

    used = set(project.reserved)
    for info in list(project.infos.values()):
        for target, name, binding in info.import_from:
            provider = project.module_info(target)
            if provider is not None and name in provider.classes:
                info.class_bindings.add(binding)
    for info in list(project.infos.values()):
        if info.tree is not None:
            _KnownInstanceCollector(info, project).visit(info.tree)
    for info in list(project.infos.values()):
        used.update(info.globals)
        used.update(info.members)
    index = [0]

    def allocate():
        while True:
            value = short_ident(index[0])
            index[0] += 1
            if (value in used or value in keyword.kwlist or
                    _is_netease_reserved(value)):
                continue
            used.add(value)
            return value

    for module in sorted(project.modules):
        info = project.modules[module]
        mapping = {}
        if not info.excluded:
            for name in sorted(info.globals):
                # A module using eval/globals can still hide statically
                # traceable private dunders.  Ordinary globals remain stable
                # because a computed dynamic lookup may address them.  Names
                # present as strings/reflection targets are protected below.
                if info.dynamic_module and not _is_internal_dunder(name):
                    continue
                if (_is_netease_reserved(name) or name in info.protected or
                        name in dynamic_attribute_names or
                        (module, name) in cross_boundary or
                        module in wildcard_targets):
                    continue
                mapping[name] = allocate()
        project.global_maps[module] = mapping

    member_candidates = set()
    protected_members = set(project.reserved) | set(project.keyword_names)
    for info in list(project.infos.values()):
        if not info.excluded:
            member_candidates.update(info.members)
        else:
            protected_members.update(attr for _owner, attr in info.attribute_rows)
        for owner, attr in info.attribute_rows:
            if not _owner_is_known(info, owner, project):
                protected_members.add(attr)
        if info.dynamic_members:
            protected_members.update(info.members)
    for name in sorted(member_candidates):
        if (_is_netease_reserved(name) or name in protected_members):
            continue
        project.member_map[name] = allocate()

    for module in sorted(project.modules):
        info = project.modules[module]
        mapping = {}
        if (not info.excluded and not info.dynamic_module and
                not info.wildcard_imports):
            candidates = (info.loaded_names & RUNTIME_BUILTIN_ALIASES) - info.globals
            for name in sorted(candidates):
                if name in info.protected:
                    continue
                mapping[name] = allocate()
        project.builtin_maps[module] = mapping
    return project


class _LocalBindingCollector(ast.NodeVisitor):
    def __init__(self):
        self.bindings = set()
        self.used = set()
        self.globals = set()
        self.nonlocals = set()
        self.protected = set()
        self.strings = set()
        self.dynamic = False

    def visit_FunctionDef(self, node):
        self.bindings.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.bindings.add(node.name)

    def visit_Lambda(self, node):
        return

    def visit_Name(self, node):
        self.used.add(node.id)
        if isinstance(node.ctx, (ast.Store, ast.Param)):
            self.bindings.add(node.id)

    def visit_Global(self, node):
        self.globals.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocals.update(node.names)

    def visit_Import(self, node):
        for alias in node.names:
            binding = alias.asname or alias.name.split('.')[0]
            self.bindings.add(binding)
            if not alias.asname and '.' in alias.name:
                self.protected.add(binding)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name != '*':
                self.bindings.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node):
        name = getattr(node, 'name', None)
        if isinstance(name, _TEXT_TYPES):
            self.bindings.add(name)
            self.protected.add(name)
        elif isinstance(name, ast.Name):
            # Python 2 represents ``except E as value`` with an ast.Name,
            # while Python 3 stores the binding as a plain string.  Record the
            # Python 2 form as the same protected local binding.
            self.bindings.add(name.id)
            self.protected.add(name.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        if _call_tail(node.func) in DYNAMIC_SCOPE_NAMES:
            self.dynamic = True
        self.generic_visit(node)

    def visit_Exec(self, node):
        self.dynamic = True
        self.generic_visit(node)

    def visit_Str(self, node):
        if isinstance(node.s, str):
            self.strings.add(node.s)

    def visit_Constant(self, node):
        value = _string_value(node)
        if value is not None:
            self.strings.add(value)


def _argument_names(args):
    result = []
    for arg in getattr(args, 'args', ()) or ():
        if isinstance(arg, (ast.Name, ast.Tuple, ast.List)):
            # Python 2 permits tuple-unpacking parameters and represents them
            # as nested ast.Tuple/ast.List targets in ``arguments.args``.
            result.extend(_target_names(arg))
        else:
            result.append(arg.arg)
    for arg in getattr(args, 'posonlyargs', ()) or ():
        result.append(arg.arg)
    for arg in getattr(args, 'kwonlyargs', ()) or ():
        result.append(arg.arg)
    for arg in (getattr(args, 'vararg', None), getattr(args, 'kwarg', None)):
        if arg:
            result.append(arg if isinstance(arg, str) else arg.arg)
    return result


def _rename_argument_target(arg, mapping):
    """Rename a Python 2/3 argument target without losing tuple bindings."""
    if isinstance(arg, ast.Name):
        arg.id = mapping.get(arg.id, arg.id)
    elif isinstance(arg, (ast.Tuple, ast.List)):
        for item in arg.elts:
            _rename_argument_target(item, mapping)
    else:
        arg.arg = mapping.get(arg.arg, arg.arg)


class GlobalRenameTransformer(ast.NodeTransformer):
    def __init__(self, plan):
        self.plan = plan
        self.scope_maps = []
        self.class_body = False

    def _resolve_name(self, name):
        for mapping in reversed(self.scope_maps):
            if name in mapping:
                return mapping[name]
        renamed = self.plan.own_globals.get(name)
        if renamed is not None:
            return renamed
        return self.plan.builtin_map.get(name, name)

    def _local_map(self, node, protected_function=False):
        collector = _LocalBindingCollector()
        for statement in node.body:
            collector.visit(statement)
        args = set(_argument_names(node.args))
        collector.bindings.update(args)
        if collector.dynamic:
            return {}
        protected = (collector.globals | collector.nonlocals |
                     collector.protected |
                     collector.strings | NETEASE_RESERVED_NAMES)
        if protected_function:
            protected.update(args)
        protected.update(self.plan.project.keyword_names)
        # A local short name must never shadow a renamed module builtin/global
        # or a captured name allocated by an enclosing scope.  For example,
        # with ``a = int`` at module scope, renaming a function argument to
        # ``a`` changes ``int(value)`` into ``value(value)`` and produces
        # ``TypeError: 'int' object is not callable``.  The same collision can
        # surface as cell/string or builtin/int arithmetic in nested helpers.
        used = (set(collector.used) |
                set(self.plan.own_globals.values()) |
                set(self.plan.builtin_map.values()) |
                set(self.plan.member_map.values()))
        for enclosing in self.scope_maps:
            used.update(enclosing.values())
        mapping = {}
        index = 0
        for name in sorted(collector.bindings):
            if name in protected or _is_netease_reserved(name):
                continue
            while True:
                candidate = short_ident(index)
                index += 1
                if (candidate not in used and candidate not in keyword.kwlist and
                        candidate not in NETEASE_RESERVED_NAMES):
                    break
            used.add(candidate)
            mapping[name] = candidate
        return mapping

    def _visit_arguments(self, args, mapping):
        for arg in list(getattr(args, 'args', ()) or ()) + list(
                getattr(args, 'posonlyargs', ()) or ()) + list(
                getattr(args, 'kwonlyargs', ()) or ()):
            _rename_argument_target(arg, mapping)
        for field in ('vararg', 'kwarg'):
            arg = getattr(args, field, None)
            if isinstance(arg, str):
                setattr(args, field, mapping.get(arg, arg))
            elif arg is not None:
                arg.arg = mapping.get(arg.arg, arg.arg)

    def visit_FunctionDef(self, node):
        original_name = node.name
        protected_function = (
            _is_netease_reserved(original_name) or
            any(_decorator_tail(item) in NETEASE_DECORATORS
                for item in getattr(node, 'decorator_list', ()) or ()))
        if not hasattr(node, '_mcp_source_original_name'):
            node._mcp_source_original_name = original_name
        direct_method = self.class_body
        if direct_method:
            node.name = self.plan.member_map.get(node.name, node.name)
        else:
            node.name = self._resolve_name(node.name)
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        if hasattr(node.args, 'kw_defaults'):
            node.args.kw_defaults = [self.visit(item) if item is not None else None
                                     for item in node.args.kw_defaults]
        mapping = self._local_map(node, protected_function)
        self._visit_arguments(node.args, mapping)
        self.scope_maps.append(mapping)
        previous_class_body = self.class_body
        self.class_body = False
        node.body = [self.visit(item) for item in node.body]
        self.class_body = previous_class_body
        self.scope_maps.pop()
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        # Lambda arguments use the same local rules, represented with a
        # synthetic function body for the binding collector.
        holder = type('LambdaHolder', (object,), {})()
        holder.args = node.args
        holder.body = [ast.Expr(value=node.body)]
        mapping = self._local_map(holder, False)
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        self._visit_arguments(node.args, mapping)
        self.scope_maps.append(mapping)
        node.body = self.visit(node.body)
        self.scope_maps.pop()
        return node

    def visit_ClassDef(self, node):
        node.name = self._resolve_name(node.name)
        node.decorator_list = [self.visit(item) for item in
                               getattr(node, 'decorator_list', ()) or ()]
        node.bases = [self.visit(item) for item in node.bases]
        node.keywords = [self.visit(item) for item in
                         getattr(node, 'keywords', ()) or ()]
        previous_class_body = self.class_body
        self.class_body = True
        node.body = [self.visit(item) for item in node.body]
        self.class_body = previous_class_body
        return node

    def visit_Name(self, node):
        name = node.id
        if self.class_body:
            name = self.plan.member_map.get(name, name)
        else:
            name = self._resolve_name(name)
        if name != node.id:
            node.id = name
        return node

    def visit_Global(self, node):
        node.names = [self.plan.own_globals.get(name, name)
                      for name in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._resolve_name(name) for name in node.names]
        return node

    def visit_ImportFrom(self, node):
        target = _resolve_import(
            self.plan.info.module, self.plan.info.is_package,
            node.module, getattr(node, 'level', 0))
        mapping = self.plan.project.globals_for(target)
        for alias in node.names:
            original = alias.name
            binding = alias.asname or original
            renamed = mapping.get(original)
            if renamed:
                alias.name = renamed
            local_binding = self._resolve_name(binding)
            if local_binding != binding:
                alias.asname = local_binding
            elif renamed and not alias.asname:
                alias.asname = original
        return node

    def visit_Import(self, node):
        for alias in node.names:
            binding = alias.asname or alias.name.split('.')[0]
            local_binding = self._resolve_name(binding)
            if local_binding != binding:
                alias.asname = local_binding
        return node

    def visit_ExceptHandler(self, node):
        name = getattr(node, 'name', None)
        original = None
        renamed = None
        if isinstance(name, _TEXT_TYPES):
            original = name
            renamed = self._resolve_name(name)
            node.name = renamed
        elif isinstance(name, ast.Name):
            original = name.id
            renamed = self._resolve_name(name.id)
            name.id = renamed
        node.type = self.visit(node.type) if node.type is not None else None
        # Bind the handler body explicitly even if a future allocator elects
        # to rename exception targets again.  This prevents an outer short-name
        # mapping from winning over the exception-local binding.
        binding_map = ({original: renamed}
                       if original is not None and renamed is not None else {})
        self.scope_maps.append(binding_map)
        try:
            node.body = [self.visit(item) for item in node.body]
        finally:
            self.scope_maps.pop()
        return node

    def visit_Attribute(self, node):
        original_owner = node.value
        original_attr = node.attr
        target = None
        if isinstance(original_owner, ast.Name):
            target = self.plan.info.import_modules.get(original_owner.id)
        node.value = self.visit(node.value)
        if target:
            node.attr = self.plan.project.globals_for(
                target).get(original_attr, original_attr)
        if node.attr == original_attr:
            node.attr = self.plan.member_map.get(original_attr, original_attr)
        return node


def apply_global_rename(tree, plan):
    if plan is None or plan.excluded:
        return tree
    tree = GlobalRenameTransformer(plan).visit(tree)
    if plan.builtin_map:
        aliases = []
        for original, renamed in sorted(plan.builtin_map.items()):
            aliases.append(ast.Assign(
                targets=[ast.Name(id=renamed, ctx=ast.Store())],
                value=ast.Name(id=original, ctx=ast.Load())))
        insert_at = 0
        body = getattr(tree, 'body', ()) or ()
        if body and isinstance(body[0], ast.Expr) and _string_value(
                getattr(body[0], 'value', None)) is not None:
            insert_at = 1
        while (insert_at < len(body) and
               isinstance(body[insert_at], ast.ImportFrom) and
               body[insert_at].module == '__future__'):
            insert_at += 1
        tree.body[insert_at:insert_at] = aliases
    ast.fix_missing_locations(tree)
    return tree
