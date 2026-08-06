# -*- coding: utf-8 -*-
"""Static compliance checks for source files about to be obfuscated."""
from __future__ import absolute_import

import ast
import base64
import binascii
import hashlib
import os

from MCP_Armor_Src.utils.filesystem import python_compile_filename

from MCP_Armor_Src.static_check.whitelist import (
    RULESET_VERSION,
    is_whitelisted_module,
)


BYPASS_FILENAME = '__BY_PASS_STATIC__.txt'
BYPASS_TOKEN = '__CONLAPASSED__'
_SCAN_CACHE = {}
_SCAN_CACHE_LIMIT = 512
_FAST_SKIP_TOKENS = (
    'import', 'from', '__import__', 'eval', 'exec', 'compile', 'reload',
    '__class__', '__mro__', '__base__', '__bases__', '__dict__',
    '__subclasses__', '__globals__', 'func_', 'getattr', 'globals',
    'vars', 'base64', 'binascii')


class StaticIssue(object):
    def __init__(self, path, line, column, code, message):
        self.path = path
        self.line = int(line or 0)
        self.column = int(column or 0)
        self.code = code
        self.message = message


class StaticCheckReport(object):
    def __init__(self, root, files, issues, bypassed=False):
        self.root = root
        self.files = list(files)
        self.issues = list(issues)
        self.bypassed = bool(bypassed)

    @property
    def valid(self):
        return self.bypassed or not self.issues


class StaticCheckFailure(Exception):
    def __init__(self, report):
        Exception.__init__(self)
        self.report = report

    def __str__(self):
        count = len(self.report.issues)
        rows = ['Static source compliance check failed: %d issue(s).' % count]
        for issue in self.report.issues:
            location = issue.path
            if issue.line:
                location += ':%d' % issue.line
                if issue.column:
                    location += ':%d' % issue.column
            rows.append('  %s [%s] %s' % (
                location, issue.code, issue.message))
        rows.append('Obfuscation was stopped before writing output.')
        return '\n'.join(rows)


def _normal_path(path):
    return os.path.normcase(os.path.abspath(path))


def _is_within(path, root):
    path = _normal_path(path)
    root = _normal_path(root)
    return path == root or path.startswith(root + os.sep)


def _bypass_enabled(root):
    marker = os.path.join(root, BYPASS_FILENAME)
    if not os.path.isfile(marker):
        return False
    try:
        with open(marker, 'rb') as handle:
            value = handle.read(256)
    except (IOError, OSError):
        return False
    if value.startswith('\xef\xbb\xbf'):
        value = value[3:]
    return value.strip() == BYPASS_TOKEN


def _iter_python_files(root, excluded_roots=None):
    excluded = [_normal_path(path) for path in (excluded_roots or ())]
    result = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs
                   if name not in ('.git', '.hg', '.svn', '__pycache__') and
                   not any(_is_within(os.path.join(current, name), item)
                           for item in excluded)]
        for name in files:
            if name.lower().endswith('.py'):
                result.append(os.path.join(current, name))
    result.sort()
    return result


def _module_names(root, python_files):
    modules = set()
    package_root = os.path.basename(os.path.normpath(root))
    for path in python_files:
        relative = os.path.relpath(path, root)
        parts = relative.replace('\\', '/').split('/')
        stem = os.path.splitext(parts[-1])[0]
        if stem == '__init__':
            parts = parts[:-1]
        else:
            parts[-1] = stem
        if not parts:
            continue
        module_name = '.'.join(parts)
        modules.add(module_name)
        modules.add(package_root + '.' + module_name)
        for index in range(1, len(parts)):
            modules.add('.'.join(parts[:index]))
            modules.add(package_root + '.' + '.'.join(parts[:index]))
    if any(os.path.basename(path).lower() == '__init__.py'
           for path in python_files):
        modules.add(package_root)
    return modules


def _is_local_module(module_name, local_modules):
    return module_name in local_modules


def _constant_string(node):
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left)
        right = _constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    if hasattr(ast, 'Index') and isinstance(node, ast.Index):
        return _constant_string(node.value)
    return None


_DYNAMIC_NAMES = frozenset((
    '__import__', 'eval', 'exec', 'execfile', 'compile', 'reload'))
_DANGEROUS_DUNDERS = frozenset((
    '__subclasses__', '__mro__', '__bases__', '__base__',
    '__globals__', 'func_globals', '__closure__', 'func_closure',
    '__code__', 'func_code', '__getattribute__', '__reduce__',
    '__reduce_ex__'))
_CARRIER_NAMES = frozenset(('__builtins__',))
_BASE64_DECODERS = frozenset(('b64decode', 'b64decodebytes', 'decodestring'))
_BINASCII_DECODERS = frozenset(('a2b_base64', 'unhexlify'))
_PROTECTED_IMPORT_ROOTS = frozenset((
    'os', 'sys', 'subprocess', 'socket', 'ctypes', 'inspect', 'dis',
    'marshal', 'imp', 'importlib', 'pkgutil', 'site', 'pathlib',
    'shutil', 'tempfile', 'multiprocessing', 'winreg', '_winreg',
    '__builtin__', 'builtins', 'types', 'gc', 'pdb', 'bdb', 'code',
    'compileall', 'py_compile',
))


def _symbol(kind, value=None):
    return (kind, value)


def _symbol_kind(value, kind):
    return isinstance(value, tuple) and value and value[0] == kind


class _SourceVisitor(ast.NodeVisitor):
    def __init__(self, display_path, local_modules):
        self.display_path = display_path
        self.local_modules = local_modules
        self.issues = []
        self._dynamic_nodes = set()
        self._issue_keys = set()
        self._bindings = [{}]
        self._resolve_cache = {}

    def _lookup_binding(self, name):
        for scope in reversed(self._bindings):
            if name in scope:
                return scope[name]
        return None

    def _bind_name(self, name, value):
        self._bindings[-1][name] = value

    def _push_scope(self):
        self._bindings.append({})

    def _pop_scope(self):
        self._bindings.pop()

    def _issue(self, node, code, message):
        line = getattr(node, 'lineno', 0)
        column = getattr(node, 'col_offset', 0) + 1
        key = (line, code)
        if key in self._issue_keys:
            return
        self._issue_keys.add(key)
        self.issues.append(StaticIssue(
            self.display_path, line, column, code, message))

    def _check_module(self, node, module_name):
        if not module_name:
            return
        module_root = module_name.split('.', 1)[0]
        if (module_root not in _PROTECTED_IMPORT_ROOTS and
                (_is_local_module(module_name, self.local_modules) or
                 is_whitelisted_module(module_name))):
            return
        if is_whitelisted_module(module_name):
            return
        self._issue(
            node, 'NETEASE_MODULE_NOT_WHITELISTED',
            'module %r is not in the NetEase whitelist or this source project' %
            module_name)

    def visit_Import(self, node):
        for alias in node.names:
            self._check_module(node, alias.name)
            binding = alias.asname or alias.name.split('.', 1)[0]
            self._bind_name(binding, _symbol('module', alias.name))

    def visit_ImportFrom(self, node):
        if not getattr(node, 'level', 0):
            self._check_module(node, node.module)
        module = node.module or ''
        for alias in node.names:
            if module == 'base64' and alias.name in _BASE64_DECODERS:
                value = _symbol('decoder', 'base64')
            elif module == 'binascii' and alias.name in _BINASCII_DECODERS:
                value = _symbol('decoder', 'binascii')
            else:
                value = _symbol('unknown')
            self._bind_name(alias.asname or alias.name, value)

    def _dynamic_import_issue(self, node):
        identity = id(node)
        if identity in self._dynamic_nodes:
            return
        self._dynamic_nodes.add(identity)
        self._issue(
            node, 'DYNAMIC_IMPORT_NOT_ALLOWED',
            '__import__ access is not allowed in source submitted for obfuscation')

    def _dynamic_code_issue(self, node, name):
        self._issue(
            node, 'DYNAMIC_CODE_EXECUTION_NOT_ALLOWED',
            '%s is not allowed in source submitted for obfuscation' % name)

    def _sandbox_issue(self, node, detail):
        self._issue(
            node, 'SANDBOX_ESCAPE_PATTERN',
            'suspicious sandbox/introspection escape pattern: %s' % detail)

    def _resolve(self, node):
        key = id(node)
        if key in self._resolve_cache:
            return self._resolve_cache[key]
        value = self._resolve_uncached(node)
        self._resolve_cache[key] = value
        return value

    def _resolve_uncached(self, node):
        """Resolve only small, side-effect-free expressions."""
        if hasattr(ast, 'Index') and isinstance(node, ast.Index):
            return self._resolve(node.value)
        if isinstance(node, ast.Name):
            if node.id in _CARRIER_NAMES:
                return _symbol('carrier')
            if node.id in _DYNAMIC_NAMES:
                return _symbol('callable', node.id)
            return self._lookup_binding(node.id)
        value = _constant_string(node)
        if value is not None:
            return _symbol('string', value)
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            if node.attr == '__dict__' and _symbol_kind(base, 'carrier'):
                return _symbol('carrier')
            if node.attr == '__dict__' and _symbol_kind(base, 'module'):
                return _symbol('module_namespace', base[1])
            if (_symbol_kind(base, 'module') and
                    node.attr in _PROTECTED_IMPORT_ROOTS and
                    not is_whitelisted_module(node.attr)):
                return _symbol('module', node.attr)
            if (_symbol_kind(base, 'module') and
                    base[1] == 'base64' and
                    node.attr in _BASE64_DECODERS):
                return _symbol('decoder', 'base64')
            if (_symbol_kind(base, 'module') and
                    base[1] == 'binascii' and
                    node.attr in _BINASCII_DECODERS):
                return _symbol('decoder', 'binascii')
            if node.attr in _DYNAMIC_NAMES:
                return _symbol('callable', node.attr)
            return None
        if isinstance(node, ast.Subscript):
            base = self._resolve(node.value)
            key = self._resolve(node.slice)
            key_text = key[1] if _symbol_kind(key, 'string') else None
            if _symbol_kind(base, 'carrier'):
                if key_text in _DYNAMIC_NAMES:
                    return _symbol('callable', key_text)
                if key_text == '__builtins__':
                    return _symbol('carrier')
            if _symbol_kind(base, 'module_namespace') and key_text:
                if key_text in _PROTECTED_IMPORT_ROOTS:
                    return _symbol('module', key_text)
                return _symbol('module_member', key_text)
            return None
        if isinstance(node, ast.Call):
            function = self._resolve(node.func)
            if _symbol_kind(function, 'decoder') and node.args:
                raw = self._resolve(node.args[0])
                if _symbol_kind(raw, 'string'):
                    try:
                        if function[1] == 'base64':
                            decoded = base64.b64decode(raw[1])
                        elif function[1] == 'binascii':
                            decoded = binascii.a2b_base64(raw[1])
                        else:
                            decoded = None
                        if decoded is not None:
                            return _symbol('string', decoded)
                    except (TypeError, ValueError, binascii.Error):
                        pass
            if isinstance(node.func, ast.Name):
                if node.func.id == 'globals':
                    return _symbol('carrier')
                if node.func.id == 'vars':
                    if node.args:
                        target = self._resolve(node.args[0])
                        if _symbol_kind(target, 'module'):
                            return _symbol('module_namespace', target[1])
                    return _symbol('carrier')
                if node.func.id == 'getattr' and len(node.args) >= 2:
                    target = self._resolve(node.args[0])
                    key = self._resolve(node.args[1])
                    if (_symbol_kind(target, 'module') and
                            _symbol_kind(key, 'string')):
                        if key[1] == '__dict__':
                            return _symbol('module_namespace', target[1])
                        if key[1] in _PROTECTED_IMPORT_ROOTS:
                            return _symbol('module', key[1])
                    if (_symbol_kind(key, 'string') and
                            key[1] in _DYNAMIC_NAMES):
                        return _symbol('callable', key[1])
            if isinstance(node.func, ast.Attribute):
                base = self._resolve(node.func.value)
                if node.func.attr == 'get' and node.args:
                    key = self._resolve(node.args[0])
                    if (_symbol_kind(base, 'carrier') and
                            _symbol_kind(key, 'string') and
                            key[1] in _DYNAMIC_NAMES):
                        return _symbol('callable', key[1])
                    if (_symbol_kind(base, 'module_namespace') and
                            _symbol_kind(key, 'string')):
                        if key[1] in _PROTECTED_IMPORT_ROOTS:
                            return _symbol('module', key[1])
                        return _symbol('module_member', key[1])
                if (node.func.attr == 'decode' and node.args and
                        _symbol_kind(base, 'string')):
                    encoding = self._resolve(node.args[0])
                    if (_symbol_kind(encoding, 'string') and
                            encoding[1].lower() == 'base64'):
                        try:
                            return _symbol('string', base64.b64decode(base[1]))
                        except (TypeError, ValueError, binascii.Error):
                            pass
                if node.func.attr == 'join' and node.args:
                    separator = self._resolve(node.func.value)
                    values = node.args[0]
                    if (_symbol_kind(separator, 'string') and
                            isinstance(values, (ast.List, ast.Tuple))):
                        parts = [self._resolve(item) for item in values.elts]
                        if all(_symbol_kind(item, 'string') for item in parts):
                            return _symbol(
                                'string', separator[1].join(item[1] for item in parts))
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left = self._resolve(node.left)
            right = node.right
            if _symbol_kind(left, 'string'):
                values = []
                if isinstance(right, (ast.Tuple, ast.List)):
                    values = [self._resolve(item) for item in right.elts]
                else:
                    values = [self._resolve(right)]
                if values and all(_symbol_kind(item, 'string') for item in values):
                    try:
                        value = tuple(item[1] for item in values)
                        return _symbol('string', left[1] % value)
                    except (TypeError, ValueError):
                        pass
        return None

    def _bind_target(self, target, value):
        if isinstance(target, ast.Name):
            if value is None:
                self._bindings[-1].pop(target.id, None)
            else:
                self._bind_name(target.id, value)

    def _check_sandbox_attribute(self, node):
        attrs = []
        current = node
        while isinstance(current, ast.Attribute):
            attrs.append(current.attr)
            current = current.value
        attrs_set = set(attrs)
        if attrs_set.intersection(_DANGEROUS_DUNDERS):
            self._sandbox_issue(node, '.'.join(reversed(attrs)))
        elif ('__dict__' in attrs_set and
              _symbol_kind(self._resolve(current), 'carrier')):
            self._sandbox_issue(node, '.'.join(reversed(attrs)))
        elif ('__dict__' in attrs_set and
              _symbol_kind(self._resolve(current), 'module')):
            self._sandbox_issue(
                node, 'module namespace via ' + '.'.join(reversed(attrs)))
        elif ('__class__' in attrs_set and
              ('__dict__' in attrs_set or 'mro' in attrs_set)):
            self._sandbox_issue(node, '.'.join(reversed(attrs)))

    def visit_Assign(self, node):
        value = self._resolve(node.value)
        self.visit(node.value)
        for target in node.targets:
            self._bind_target(target, value)

    def _bind_argument(self, argument):
        """Bind Python 2 names, tuple-unpacked args and newer ast.arg nodes."""
        if argument is None:
            return
        if isinstance(argument, basestring):
            self._bind_name(argument, _symbol('unknown'))
            return
        name = getattr(argument, 'id', None)
        if name is None:
            name = getattr(argument, 'arg', None)
        if name is not None:
            self._bind_name(name, _symbol('unknown'))
            return
        if isinstance(argument, (ast.Tuple, ast.List)):
            for item in argument.elts:
                self._bind_argument(item)

    def visit_FunctionDef(self, node):
        self._bind_name(node.name, _symbol('unknown'))
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults:
            self.visit(default)
        self._push_scope()
        for argument in list(node.args.args) + list(getattr(node.args, 'kwonlyargs', [])):
            self._bind_argument(argument)
        self._bind_argument(getattr(node.args, 'vararg', None))
        self._bind_argument(getattr(node.args, 'kwarg', None))
        for statement in node.body:
            self.visit(statement)
        self._pop_scope()

    def visit_ClassDef(self, node):
        self._bind_name(node.name, _symbol('unknown'))
        for decorator in getattr(node, 'decorator_list', []):
            self.visit(decorator)
        self._push_scope()
        for statement in node.body:
            self.visit(statement)
        self._pop_scope()

    def visit_Name(self, node):
        if node.id == '__import__':
            self._dynamic_import_issue(node)
        elif node.id in _DYNAMIC_NAMES - frozenset(('__import__',)):
            self._dynamic_code_issue(node, node.id)

    def visit_Attribute(self, node):
        self._check_sandbox_attribute(node)
        if node.attr == '__import__':
            self._dynamic_import_issue(node)
        elif node.attr in _DYNAMIC_NAMES:
            self._dynamic_code_issue(node, node.attr)
        self.generic_visit(node)

    def visit_Subscript(self, node):
        base = self._resolve(node.value)
        key = self._resolve(node.slice)
        if (_symbol_kind(base, 'carrier') and
                _symbol_kind(key, 'string') and key[1] in _DYNAMIC_NAMES):
            if key[1] == '__import__':
                self._dynamic_import_issue(node)
            else:
                self._dynamic_code_issue(node, key[1])
        if _symbol_kind(base, 'module_namespace'):
            key_text = key[1] if _symbol_kind(key, 'string') else '<dynamic>'
            self._sandbox_issue(
                node, 'module namespace item %r' % key_text)
        self.generic_visit(node)

    def visit_Call(self, node):
        resolved = self._resolve(node.func)
        if _symbol_kind(resolved, 'callable'):
            if resolved[1] == '__import__':
                self._dynamic_import_issue(node)
            elif resolved[1] in _DYNAMIC_NAMES:
                self._dynamic_code_issue(node, resolved[1])
        function_name = None
        if isinstance(node.func, ast.Name):
            function_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr
        if function_name == 'getattr' and len(node.args) >= 2:
            target = self._resolve(node.args[0])
            key = self._resolve(node.args[1])
            if (_symbol_kind(target, 'module') and
                    _symbol_kind(key, 'string') and
                    (key[1] == '__dict__' or
                     key[1] in _PROTECTED_IMPORT_ROOTS)):
                self._sandbox_issue(
                    node, 'module attribute %r' % key[1])
            if _symbol_kind(key, 'string') and key[1] in _DYNAMIC_NAMES:
                if key[1] == '__import__':
                    self._dynamic_import_issue(node)
                else:
                    self._dynamic_code_issue(node, key[1])
        elif function_name == 'vars' and node.args:
            target = self._resolve(node.args[0])
            if _symbol_kind(target, 'module'):
                self._sandbox_issue(node, 'vars(module) namespace access')
        elif function_name in ('get', '__getitem__') and node.args:
            base = self._resolve(node.func.value) if isinstance(
                node.func, ast.Attribute) else None
            key = self._resolve(node.args[0])
            if _symbol_kind(base, 'module_namespace'):
                key_text = key[1] if _symbol_kind(key, 'string') else '<dynamic>'
                self._sandbox_issue(
                    node, 'module namespace item %r' % key_text)
            if _symbol_kind(key, 'string') and key[1] in _DYNAMIC_NAMES:
                if key[1] == '__import__':
                    self._dynamic_import_issue(node)
                else:
                    self._dynamic_code_issue(node, key[1])
        self.generic_visit(node)

    def visit_Exec(self, node):
        self._dynamic_code_issue(node, 'exec')
        self.generic_visit(node)


def _scan_file(path, root, local_modules, local_key=None):
    display_path = os.path.relpath(path, root).replace('\\', '/')
    try:
        with open(path, 'rb') as handle:
            source = handle.read()
        digest = hashlib.sha256(source).digest()
        if local_key is None:
            local_key = tuple(sorted(local_modules))
        cache_key = (_normal_path(path), digest, RULESET_VERSION, local_key)
        cached = _SCAN_CACHE.get(cache_key)
        if cached is not None:
            return list(cached)
        tree = ast.parse(source, python_compile_filename(path))
    except (IOError, OSError) as error:
        issues = [StaticIssue(
            display_path, 0, 0, 'SOURCE_READ_ERROR', str(error))]
        return issues
    except SyntaxError as error:
        issues = [StaticIssue(
            display_path, getattr(error, 'lineno', 0),
            getattr(error, 'offset', 0), 'SOURCE_SYNTAX_ERROR',
            getattr(error, 'msg', str(error)))]
        return issues
    if not any(token in source for token in _FAST_SKIP_TOKENS):
        if len(_SCAN_CACHE) >= _SCAN_CACHE_LIMIT:
            _SCAN_CACHE.clear()
        _SCAN_CACHE[cache_key] = ()
        return []
    visitor = _SourceVisitor(display_path, local_modules)
    visitor.visit(tree)
    if len(_SCAN_CACHE) >= _SCAN_CACHE_LIMIT:
        _SCAN_CACHE.clear()
    _SCAN_CACHE[cache_key] = tuple(visitor.issues)
    return list(visitor.issues)


def scan_source(source_path, folder=None, excluded_roots=None):
    source_path = os.path.abspath(source_path)
    if folder is None:
        folder = os.path.isdir(source_path)
    root = source_path if folder else os.path.dirname(source_path)
    if _bypass_enabled(root):
        return StaticCheckReport(root, [], [], True)
    project_files = _iter_python_files(root, excluded_roots)
    local_modules = _module_names(root, project_files)
    files = project_files if folder else [source_path]
    local_key = tuple(sorted(local_modules))
    issues = []
    for path in files:
        issues.extend(_scan_file(path, root, local_modules, local_key))
    return StaticCheckReport(root, files, issues, False)


def enforce_source_compliance(source_path, folder=None, excluded_roots=None):
    report = scan_source(source_path, folder, excluded_roots)
    if not report.valid:
        raise StaticCheckFailure(report)
    return report
