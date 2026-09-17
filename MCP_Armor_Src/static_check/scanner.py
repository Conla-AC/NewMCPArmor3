# -*- coding: utf-8 -*-
"""Static compliance checks for source files about to be obfuscated."""


import ast
import base64
import binascii
import hashlib
import io
import os
import re
import subprocess
import sys
import token
import tokenize

from MCP_Armor_Src.compat.python27 import resolve_python27
from MCP_Armor_Src.utils.filesystem import decode_source_bytes, python_compile_filename

from MCP_Armor_Src.static_check.whitelist import (
    RULESET_VERSION,
    is_whitelisted_module,
)


BYPASS_FILENAME = '__BY_PASS_STATIC__.txt'
BYPASS_TOKEN = '__CONLAPASSED__'
SCANNER_RULESET_VERSION = 'static-scanner-2026-08-20-r4-py27-syntax'
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
    if value.startswith(b'\xef\xbb\xbf'):
        value = value[3:]
    return value.strip() == BYPASS_TOKEN.encode('utf-8')


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
        # Python 2 permits implicit relative imports from a package's sibling
        # directory (``import socket`` inside ``pkg/consumer.py``).  Keep the
        # basename alias in the project index so that form is recognized as a
        # source-local edge rather than an SDK whitelist lookup.
        if stem != '__init__':
            modules.add(stem)
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
        # Python resolves a same-directory module before the SDK/stdlib path.
        # Check the complete project index first; otherwise a legitimate
        # sibling such as ``socket.py`` or ``os.py`` is reported as a blocked
        # external import merely because its filename matches a protected
        # root.  The source file itself is still scanned for dangerous calls.
        if _is_local_module(module_name, self.local_modules):
            return
        module_root = module_name.split('.', 1)[0]
        if (module_root not in _PROTECTED_IMPORT_ROOTS and
                is_whitelisted_module(module_name)):
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
        if isinstance(argument, str):
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


def _python27_executable():
    """Find the target parser used for legacy NetEase Python-2 sources."""
    return resolve_python27()


def _validate_python27_source(path):
    """Return ``(valid, diagnostic)`` for source rejected by Python 3 AST.

    A Python-2 parse is deliberately a separate syntax gate.  The static
    scanner still applies the token-level checks below, so accepting legacy
    syntax does not disable import or dynamic-execution rules.
    """
    if sys.version_info[0] < 3:
        return None, None
    executable = _python27_executable()
    if not executable:
        return None, None
    command = [executable, '-c',
               "compile(open(__import__('sys').argv[1], 'rb').read(), "
               "__import__('sys').argv[1], 'exec')", path]
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = process.communicate()[1]
    except (IOError, OSError):
        return None, None
    if process.returncode == 0:
        return True, None
    if not isinstance(output, str):
        output = output.decode('utf-8', 'replace')
    line_match = re.search(r'line\s+(\d+)', output)
    line = int(line_match.group(1)) if line_match else 0
    return False, (line, output.strip() or 'Python 2 syntax error')


def _legacy_token_scan(source_text, display_path, local_modules):
    """Apply conservative checks when Python-2 syntax has no Python-3 AST."""
    issues = []
    seen = set()

    def issue(line, column, code, message):
        key = (int(line or 0), code)
        if key in seen:
            return
        seen.add(key)
        issues.append(StaticIssue(
            display_path, line, column, code, message))

    # Imports are simple enough to classify without depending on the AST
    # grammar.  Relative imports are project-local by definition.
    for line_no, line in enumerate(source_text.splitlines(), 1):
        import_match = re.match(r'^\s*import\s+(.+)$', line)
        if import_match:
            values = import_match.group(1).split(',')
            for value in values:
                module = re.split(r'\s+as\s+', value.strip(), 1)[0]
                module = module.split('#', 1)[0].strip()
                if not module:
                    continue
                if (_is_local_module(module, local_modules) or
                        is_whitelisted_module(module)):
                    continue
                issue(line_no, line.find(module) + 1,
                      'NETEASE_MODULE_NOT_WHITELISTED',
                      'module %r is not in the NetEase whitelist or this source project' %
                      module)
        from_match = re.match(r'^\s*from\s+([^\s]+)\s+import\s+', line)
        if from_match:
            module = from_match.group(1)
            if module.startswith('.'):
                continue
            if (_is_local_module(module, local_modules) or
                    is_whitelisted_module(module)):
                continue
            issue(line_no, line.find(module) + 1,
                  'NETEASE_MODULE_NOT_WHITELISTED',
                  'module %r is not in the NetEase whitelist or this source project' %
                  module)

    try:
        tokens = tokenize.generate_tokens(
            io.StringIO(source_text).readline)
    except (AttributeError, TypeError):
        tokens = ()
    try:
        for item in tokens:
            if item.type != token.NAME:
                continue
            name = item.string
            if name == '__import__':
                issue(item.start[0], item.start[1] + 1,
                      'DYNAMIC_IMPORT_NOT_ALLOWED',
                      '__import__ access is not allowed in source submitted for obfuscation')
            elif name in _DYNAMIC_NAMES - frozenset(('__import__',)):
                issue(item.start[0], item.start[1] + 1,
                      'DYNAMIC_CODE_EXECUTION_NOT_ALLOWED',
                      '%s is not allowed in source submitted for obfuscation' % name)
            elif name in _DANGEROUS_DUNDERS or name in _CARRIER_NAMES:
                issue(item.start[0], item.start[1] + 1,
                      'SANDBOX_ESCAPE_PATTERN',
                      'suspicious sandbox/introspection escape pattern: %s' % name)
    except (tokenize.TokenError, IndentationError):
        # Python 2 validation already accepted the source.  A tokenization
        # edge case should not turn a valid legacy module into a syntax error.
        pass

    # Lightweight constant tracking for the common obfuscated-import idiom:
    # getattr(__builtins__, '__imp' + 'ort__')('os').
    for line_no, line in enumerate(source_text.splitlines(), 1):
        compact = line.replace(' ', '').replace('\t', '')
        if (('__imp' in compact and 'ort__' in compact) or
                ('__builtins__' in compact and '__import__' in compact)):
            issue(line_no, 1, 'DYNAMIC_IMPORT_NOT_ALLOWED',
                  'obfuscated __import__ access is not allowed in source submitted for obfuscation')
    return issues


def _scan_file(path, root, local_modules, local_key=None):
    display_path = os.path.relpath(path, root).replace('\\', '/')
    try:
        with open(path, 'rb') as handle:
            source = handle.read()
        digest = hashlib.sha256(source).digest()
        if local_key is None:
            local_key = tuple(sorted(local_modules))
        cache_key = (_normal_path(path), digest,
                     RULESET_VERSION + ':' + SCANNER_RULESET_VERSION,
                     local_key)
        cached = _SCAN_CACHE.get(cache_key)
        if cached is not None:
            return list(cached)
        source_text = decode_source_bytes(source)
        try:
            tree = ast.parse(source_text, python_compile_filename(path))
        except SyntaxError as python3_error:
            # NetEase source is Python 2.7.  Python 3.13's AST rejects valid
            # statements such as ``print value`` before any policy rule can
            # run, so validate with the target parser and use token checks.
            legacy_valid, legacy_error = _validate_python27_source(path)
            if legacy_valid is True:
                legacy_issues = _legacy_token_scan(
                    source_text, display_path, local_modules)
                if len(_SCAN_CACHE) >= _SCAN_CACHE_LIMIT:
                    _SCAN_CACHE.clear()
                _SCAN_CACHE[cache_key] = tuple(legacy_issues)
                return legacy_issues
            if legacy_valid is False and legacy_error is not None:
                line, message = legacy_error
                issues = [StaticIssue(
                    display_path, line, 0, 'SOURCE_SYNTAX_ERROR', message)]
                return issues
            raise python3_error
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
    if not any(token in source_text for token in _FAST_SKIP_TOKENS):
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
