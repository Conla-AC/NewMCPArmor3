# -*- coding: utf-8 -*-
"""Project-wide Python module/file renaming and NetEase path relinking."""

import ast
import fnmatch
import keyword
import os
import re

try:
    text_types = (basestring,)
except NameError:
    text_types = (str,)


def _ast_identifier(value):
    """Python 2's compiler requires identifier fields to be byte strings."""
    if value is None or isinstance(value, str):
        return value
    return value.encode('ascii')


MANDATORY_FILE_EXCLUDES = set(('modmain.py', 'config.py', '__init__.py'))
REGISTRATION_CALLS = set((
    'RegisterSystem', 'RegisterUI', 'RegisterComponent',
    'RegisterComponentFactory',
))
DYNAMIC_IMPORT_CALLS = set((
    '__import__', 'import_module', 'ImportModule', 'Module',
    'GetModuleByName',
))
REGISTER_PATH_KEYWORDS = set((
    'clspath', 'class_path', 'classpath', 'system_path', 'systempath',
    'ui_path', 'uipath', 'component_path', 'componentpath',
))


def _is_split_module(module):
    """Identify a sibling module produced by source function splitting."""
    return bool(module and module.rsplit('.', 1)[-1].startswith('__mcp_fn_'))


def _is_path_keyword(name):
    if not name:
        return False
    compact = name.replace('-', '_').lower()
    return (compact in REGISTER_PATH_KEYWORDS or 'class' in compact or
            compact.endswith('path'))


def _file_ident(index):
    """Windows-safe mixed-case module name sequence.

    One-character names are ``a..z``. Longer names use a lowercase leading
    letter and uppercase/digit continuation alphabet: ``aA..aZ, a0..a9,
    bA..``.  We never emit a lowercase continuation, so case-folding filesystems
    cannot collapse two generated paths.  Digits raise two-character capacity
    from 676 to 936 without producing an invalid leading digit.
    """
    value = int(index)
    if value < 0:
        raise ValueError('module filename index must be non-negative')
    leading = 'abcdefghijklmnopqrstuvwxyz'
    continuation = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    if value < len(leading):
        return leading[value]
    value -= len(leading)
    length = 2
    while True:
        tail_width = length - 1
        block = len(leading) * (len(continuation) ** tail_width)
        if value < block:
            scale = len(continuation) ** tail_width
            first = value // scale
            remainder = value % scale
            chars = [leading[first]]
            for power in range(tail_width - 1, -1, -1):
                unit = len(continuation) ** power
                chars.append(continuation[remainder // unit])
                remainder %= unit
            return ''.join(chars)
        value -= block
        length += 1


def _module_name(root, path):
    rel = os.path.relpath(path, root).replace('\\', '/')
    rel = rel[:-3] if rel.lower().endswith('.py') else rel
    parts = [part for part in rel.split('/') if part]
    is_package = bool(parts and parts[-1] == '__init__')
    if is_package:
        parts.pop()
    return '.'.join(parts), is_package


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


def _excluded(rel, patterns):
    rel_norm = rel.replace('\\', '/')
    base = os.path.basename(rel_norm)
    if base.lower() in MANDATORY_FILE_EXCLUDES:
        return True
    for pattern in patterns or ():
        if (fnmatch.fnmatch(rel_norm, pattern) or
                fnmatch.fnmatch(base, pattern)):
            return True
    return False


def _string_value(node):
    if isinstance(node, ast.Str):
        return node.s
    constant = getattr(ast, 'Constant', None)
    if constant is not None and isinstance(node, constant):
        return node.value if isinstance(node.value, text_types) else None
    return None


def _set_string_value(node, value):
    if isinstance(node, ast.Str):
        node.s = value
        return
    if hasattr(node, 'value'):
        node.value = value


def _call_tail(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class ModuleRenameProject(object):
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.root_package = os.path.basename(self.root)
        self.root_aliases = set([self.root_package])
        self.module_map = {}
        self.rel_map = {}
        self.path_modules = {}
        self.package_flags = {}
        self.symbol_maps = {}
        self.source_exports = {}
        self.unresolved_dynamic = []
        self.unresolved_registrations = []

    def plan_for(self, path):
        path = os.path.abspath(path)
        module = self.path_modules.get(path)
        if module is None:
            return None
        return ModuleRenamePlan(self, module,
                                self.package_flags.get(path, False))

    def output_rel(self, rel):
        return self.rel_map.get(rel.replace('\\', '/'),
                                rel.replace('\\', '/'))

    def mapped_module(self, module):
        return self.module_map.get(module, module)

    def source_module(self, reference):
        """Return the canonical project module for a runtime reference."""
        if reference in self.module_map or reference in self.path_modules.values():
            return reference
        for root_alias in self.root_aliases:
            prefix = root_alias + '.'
            if reference.startswith(prefix):
                inner = reference[len(prefix):]
                if inner in self.module_map or inner in self.path_modules.values():
                    return inner
        # Function splitting can create sibling modules after a package has
        # already been analyzed.  Some generated wrappers retain the short
        # module spelling (``aFP``) while the canonical project key contains
        # a package prefix.  Resolve an unqualified reference by its final
        # component so the linker and emitted filename stay in agreement.
        if reference and '.' not in reference:
            matches = [item for item in self.module_map
                       if item.rpartition('.')[2] == reference]
            if len(matches) == 1:
                return matches[0]
        return reference

    def mapped_reference(self, module):
        # Normalize short references (``from aFP import ...``) against the
        # canonical project map.  This matters for Python 2 loaders, which
        # resolve sibling imports without the package prefix.  Returning the
        # mapped short stem keeps the emitted import and filename identical.
        if module and '.' not in module:
            source = self.source_module(module)
            if source != module:
                mapped = self.mapped_module(source)
                return mapped.rsplit('.', 1)[-1]
        mapped = self.mapped_module(module)
        if mapped != module or not self.root_package:
            return mapped
        for root_alias in self.root_aliases:
            prefix = root_alias + '.'
            if module.startswith(prefix):
                inner = module[len(prefix):]
                mapped_inner = self.mapped_module(inner)
                if mapped_inner != inner:
                    return prefix + mapped_inner
        return module

    def mapped_exports(self, mapped_module):
        """Return source exports under their emitted global-rename names."""
        result = set()
        for module, exports in self.source_exports.items():
            if self.mapped_module(module) != mapped_module:
                continue
            symbols = self.symbol_maps.get(module, {})
            # Registration/lifecycle exports can be deliberately preserved by
            # global Rename even when the analysis map also contains an alias.
            # A bytecode loader executes the original module namespace, so both
            # the stable public spelling and the renamed spelling are valid.
            result.update(exports)
            result.update(symbols.get(name, name) for name in exports)
        return result

    def _variants(self, module):
        values = [(module, self.mapped_module(module))]
        if module:
            for root_alias in self.root_aliases:
                values.append((root_alias + '.' + module,
                               root_alias + '.' + self.mapped_module(module)))
        return values

    def rewrite_module_prefix(self, value, rewrite_symbol=False):
        if not isinstance(value, text_types) or not value:
            return value
        output = value
        for module in sorted(self.module_map, key=len, reverse=True):
            mapped = self.module_map[module]
            for old, new in self._variants(module):
                symbol_map = self.symbol_maps.get(module, {})
                if rewrite_symbol and symbol_map:
                    for symbol, renamed in sorted(
                            symbol_map.items(), key=lambda item: len(item[0]),
                            reverse=True):
                        pattern = (r'(?<![A-Za-z0-9_])' +
                                   re.escape(old + '.' + symbol) +
                                   r'(?=\.|$)')
                        output = re.sub(
                            pattern, new + '.' + renamed, output)
                # In registration paths the trailing component is a class
                # (symbol), already handled by the symbol rewrite above.  Only
                # match module names followed by another component so a class
                # named like its module (``ServerSystem.ServerSystem``) is not
                # double-renamed.
                suffix = r'(?=\.)' if rewrite_symbol else r'(?=\.|$)'
                pattern = (r'(?<![A-Za-z0-9_])' + re.escape(old) + suffix)
                output = re.sub(pattern, new, output)
        return output


class ModuleRenamePlan(object):
    def __init__(self, project, module, is_package):
        self.project = project
        self.module = module
        self.is_package = is_package


def _parse_source_tree(source):
    """Parse source, tolerating common Python 2-only syntax on a Python 3 host.

    The controller (Python 3) re-derives source exports for the link audit, but
    NetEase modules often use the ``print "..."`` statement form which the
    Python 3 grammar rejects.  Normalise those tokens before reparsing.
    """
    if not isinstance(source, text_types):
        source = source.decode('utf-8-sig', 'replace')
    try:
        return ast.parse(source)
    except SyntaxError:
        compatible = re.sub(
            r'(?<![A-Za-z0-9_])((?:0[xX][0-9A-Fa-f]+|[0-9]+))[lL]\b',
            r'\1', source)
        compatible = re.sub(
            r'(?m)^([ \t]*)print[ \t]+([^\n]+)$', r'\1print(\2)', compatible)
        return ast.parse(compatible)


def build_module_rename_project(root, exclude_patterns=None):
    project = ModuleRenameProject(root)
    rows = []
    reserved = set()
    for current, dirs, files in os.walk(project.root):
        # ``os.walk`` does not guarantee directory or file order on Windows.
        # The Python 3 controller and Python 2 worker must derive the exact
        # same filename map; an order drift makes one side emit ``fP.py``
        # while imports reference ``aFP.py``.
        dirs.sort()
        dirs[:] = [name for name in dirs if name not in (
            '__pycache__', '.git', '.svn')]
        for name in sorted(files):
            if not name.lower().endswith('.py'):
                continue
            path = os.path.abspath(os.path.join(current, name))
            rel = os.path.relpath(path, project.root).replace('\\', '/')
            module, is_package = _module_name(project.root, path)
            project.path_modules[path] = module
            project.package_flags[path] = is_package
            try:
                with open(path, 'rb') as source_handle:
                    # Python 2's compiler attempts ASCII coercion for the
                    # diagnostic filename.  Keep Unicode filesystem paths out
                    # of that field while parsing the exact source bytes.
                    source_tree = _parse_source_tree(source_handle.read())
                project.source_exports[module] = _top_level_exports(
                    source_tree)[0]
            except (SyntaxError, ValueError, TypeError):
                project.source_exports[module] = set()
            if rel.lower() == 'modmain.py':
                try:
                    with open(path, 'rb') as alias_handle:
                        alias_tree = ast.parse(
                            alias_handle.read(), '<module-root-alias>')
                    constants = _scope_constants(
                        getattr(alias_tree, 'body', ()) or ())
                    for key in ('mod_name', 'MOD_NAME', 'package_name'):
                        value = constants.get(key)
                        if (isinstance(value, text_types) and
                                re.match(r'^[A-Za-z_]\w*$', value)):
                            project.root_aliases.add(value)
                except (IOError, OSError, SyntaxError, ValueError, TypeError):
                    pass
            if _excluded(rel, exclude_patterns) or is_package:
                reserved.add(os.path.splitext(name)[0].lower())
            else:
                rows.append((rel, path, module))

    used = set(reserved)
    index = 0
    for rel, _path, module in sorted(rows):
        while True:
            candidate = _file_ident(index)
            index += 1
            if (candidate.lower() not in used and
                    candidate not in keyword.kwlist):
                break
        used.add(candidate.lower())
        directory = os.path.dirname(rel).replace('\\', '/')
        mapped_rel = ((directory + '/') if directory else '') + candidate + '.py'
        mapped_module = (module.rpartition('.')[0] + '.' + candidate
                         if '.' in module else candidate)
        project.rel_map[rel] = mapped_rel
        project.module_map[module] = mapped_module
    return project


def ensure_module_aliases(root, project):
    """Create tiny compatibility aliases for short sibling imports.

    Older generated wrappers may contain an unqualified import stem while
    the corresponding source file is emitted under a renamed stem.  A one
    line alias is harmless for both Python 2 and 3 and prevents NetEase's
    redirect loader from failing before the package can initialize.
    """
    if project is None:
        return 0
    created = 0
    for module, mapped in project.module_map.items():
        old = module.rsplit('.', 1)[-1]
        new = mapped.rsplit('.', 1)[-1]
        if old == new or not old.isidentifier():
            continue
        target = os.path.join(root, old + '.py')
        renamed = os.path.join(root, new + '.py')
        if os.path.exists(target) or not os.path.exists(renamed):
            continue
        with open(target, 'wb') as handle:
            handle.write(('from %s import *\n' % new).encode('ascii'))
        created += 1
    return created


class _StringExpressionRewriter(ast.NodeVisitor):
    def __init__(self, project, rewrite_symbol):
        self.project = project
        self.rewrite_symbol = rewrite_symbol
        self.changed = False

    def visit_Str(self, node):
        before = _string_value(node)
        after = self.project.rewrite_module_prefix(
            before, self.rewrite_symbol)
        if after != before:
            _set_string_value(node, after)
            self.changed = True

    def visit_Constant(self, node):
        self.visit_Str(node)


def _static_value(node, env):
    value = _string_value(node)
    if value is not None:
        return value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.Num):
        return node.n
    if isinstance(node, (ast.Tuple, ast.List)):
        values = [_static_value(item, env) for item in node.elts]
        if any(item is None for item in values):
            return None
        return tuple(values) if isinstance(node, ast.Tuple) else values
    if isinstance(node, ast.Dict):
        keys = [_static_value(item, env) for item in node.keys]
        values = [_static_value(item, env) for item in node.values]
        if any(item is None for item in keys + values):
            return None
        return dict(zip(keys, values))
    if isinstance(node, ast.BinOp):
        left = _static_value(node.left, env)
        right = _static_value(node.right, env)
        if left is None or right is None:
            return None
        try:
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Mod):
                return left % right
        except (TypeError, ValueError, KeyError, IndexError):
            return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        owner = _static_value(node.func.value, env)
        if owner is None:
            return None
        if node.func.attr == 'format' and isinstance(owner, text_types):
            args = [_static_value(item, env) for item in node.args]
            kwargs = {}
            for item in getattr(node, 'keywords', ()) or ():
                key = getattr(item, 'arg', None)
                value = _static_value(item.value, env)
                if key is None or value is None:
                    return None
                kwargs[key] = value
            if any(item is None for item in args):
                return None
            try:
                return owner.format(*args, **kwargs)
            except (KeyError, IndexError, ValueError, TypeError):
                return None
        if node.func.attr == 'join' and isinstance(owner, text_types) and node.args:
            rows = _static_value(node.args[0], env)
            if rows is not None:
                try:
                    return owner.join(rows)
                except (TypeError, ValueError):
                    return None
    return None


def _scope_constants(statements, inherited=None):
    env = dict(inherited or {})
    for _round in range(4):
        changed = False
        for statement in statements:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if not isinstance(target, ast.Name):
                continue
            value = _static_value(statement.value, env)
            if value is not None and env.get(target.id) != value:
                env[target.id] = value
                changed = True
        if not changed:
            break
    return env


ROOT_ALIAS_NAMES = (
    'ModName', 'MODNAME', 'modname', 'MOD_NAME', 'mod_name',
    'package_name', 'PACKAGE_NAME',
)


def _with_root_aliases(env, project):
    """Resolve root-package aliases such as ``ModName`` to the project root.

    NetEase mods commonly register providers through ``ModName +
    '.ServerSystem.ServerSystem'`` where ``ModName`` is the (never renamed)
    root package.  Injecting that alias lets path resolution treat the dynamic
    concatenation as a static, verifiable provider path.
    """
    if not project.root_aliases and not ROOT_ALIAS_NAMES:
        return env
    result = dict(env)
    for alias in project.root_aliases:
        if alias not in result:
            result[alias] = project.root_package
    for name in ROOT_ALIAS_NAMES:
        if name not in result:
            result[name] = project.root_package
    return result


def _call_alias_name(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _scope_call_aliases(statements, inherited=None):
    aliases = dict(inherited or {})
    for _round in range(3):
        changed = False
        for statement in statements:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if not isinstance(target, ast.Name):
                continue
            name = _call_alias_name(statement.value, aliases)
            if name in DYNAMIC_IMPORT_CALLS and aliases.get(target.id) != name:
                aliases[target.id] = name
                changed = True
        if not changed:
            break
    return aliases


class ModuleRenameTransformer(ast.NodeTransformer):
    def __init__(self, plan):
        self.plan = plan
        self.changed = False
        self.constant_scopes = []
        self.call_alias_scopes = []

    def _constants(self):
        base = self.constant_scopes[-1] if self.constant_scopes else {}
        project = self.plan.project
        return _with_root_aliases(base, project)

    def _call_aliases(self):
        return self.call_alias_scopes[-1] if self.call_alias_scopes else {}

    def _visit_scope(self, node, statements):
        inherited_constants = self._constants()
        inherited_aliases = self._call_aliases()
        self.constant_scopes.append(_scope_constants(
            statements, inherited_constants))
        self.call_alias_scopes.append(_scope_call_aliases(
            statements, inherited_aliases))
        node.body = [self.visit(item) for item in statements]
        self.call_alias_scopes.pop()
        self.constant_scopes.pop()
        return node

    def visit_Module(self, node):
        return self._visit_scope(node, list(node.body))

    def visit_FunctionDef(self, node):
        node.decorator_list = [self.visit(item) for item in
                               getattr(node, 'decorator_list', ()) or ()]
        node.args.defaults = [self.visit(item) for item in
                              getattr(node.args, 'defaults', ()) or ()]
        return self._visit_scope(node, list(node.body))

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        node.body = self.visit(node.body)
        return node

    def visit_ClassDef(self, node):
        node.decorator_list = [self.visit(item) for item in
                               getattr(node, 'decorator_list', ()) or ()]
        node.bases = [self.visit(item) for item in node.bases]
        return self._visit_scope(node, list(node.body))

    def visit_Import(self, node):
        for alias in node.names:
            original = alias.name
            mapped = self.plan.project.mapped_reference(original)
            if mapped != original:
                alias.name = _ast_identifier(mapped)
                if alias.asname is None and '.' not in original:
                    alias.asname = _ast_identifier(original)
                self.changed = True
        return node

    def visit_ImportFrom(self, node):
        target = _resolve_import(
            self.plan.module, self.plan.is_package, node.module,
            getattr(node, 'level', 0))
        original_target = target
        source_target = self.plan.project.source_module(original_target)
        mapped_target = self.plan.project.mapped_reference(target)
        if mapped_target != target:
            if getattr(node, 'level', 0):
                old_tail = (node.module or '').split('.')
                new_tail = mapped_target.split('.')
                count = len(old_tail)
                node.module = _ast_identifier(
                    '.'.join(new_tail[-count:]) if count else None)
            else:
                node.module = _ast_identifier(mapped_target)
            self.changed = True
            target = mapped_target
        symbol_map = self.plan.project.symbol_maps.get(source_target, {})
        for alias in node.names:
            if alias.name == '*':
                continue
            original = alias.name
            renamed_symbol = symbol_map.get(original)
            if renamed_symbol and renamed_symbol != original:
                alias.name = _ast_identifier(renamed_symbol)
                if alias.asname is None:
                    alias.asname = _ast_identifier(original)
                self.changed = True
                continue
            # ``from package import child_module`` links a module rather than
            # a provider export; preserve the existing child-module rewrite.
            child = (original_target + '.' + original
                     if original_target else original)
            mapped_child = self.plan.project.mapped_reference(child)
            if mapped_child != child:
                alias.name = _ast_identifier(
                    mapped_child.rsplit('.', 1)[-1])
                if alias.asname is None:
                    alias.asname = _ast_identifier(original)
                self.changed = True
        return node

    def _rewrite_path_value(self, value, target_name):
        """Relink registration path constants before they reach a call.

        NetEase modules commonly keep a UI/system class path in a module
        constant such as ``CLS_PATH`` and pass that name to a registration
        helper later.  Call-site rewriting cannot see through every alias or
        wrapper, so rewrite the assignment as well.  Restricting this to
        path-shaped targets avoids changing ordinary user-facing strings.
        """
        if not _is_path_keyword(target_name):
            return value
        resolved = _static_value(value, self._constants())
        if isinstance(resolved, text_types):
            after = self.plan.project.rewrite_module_prefix(resolved, True)
            if after != resolved:
                return ast.copy_location(ast.Str(s=after), value)
        visitor = _StringExpressionRewriter(self.plan.project, True)
        visitor.visit(value)
        if visitor.changed:
            self.changed = True
        return value

    def visit_Assign(self, node):
        self.generic_visit(node)
        targets = list(getattr(node, 'targets', ()) or ())
        for target in targets:
            if isinstance(target, ast.Name):
                before = node.value
                after = self._rewrite_path_value(before, target.id)
                if after is not before:
                    node.value = after
                    self.changed = True
                break
        return node

    def visit_AnnAssign(self, node):
        # Python 3-only syntax is accepted by the host-side parser even when
        # the emitted project targets the legacy runtime.
        self.generic_visit(node)
        target = getattr(node, 'target', None)
        if isinstance(target, ast.Name):
            before = node.value
            if before is not None:
                after = self._rewrite_path_value(before, target.id)
                if after is not before:
                    node.value = after
                    self.changed = True
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        tail = _call_tail(node.func)
        args = list(getattr(node, 'args', ()) or ())
        if tail in REGISTRATION_CALLS:
            # The third positional item is the provider class path.  The
            # namespace and registration key before it are runtime IDs, not
            # import paths.  Rewriting every argument turned a valid key such
            # as ``arraylist`` into its renamed file stem, so RegisterUI and
            # CreateUI no longer addressed the same UI instance.
            candidates = []
            if len(args) >= 3:
                candidates.append((args[2], 'arg', 2))
            for keyword_item in getattr(node, 'keywords', ()) or ():
                if _is_path_keyword(getattr(keyword_item, 'arg', None)):
                    candidates.append((keyword_item.value, 'keyword',
                                       keyword_item))
            path_resolved = bool(
                len(args) >= 3 and isinstance(
                    _static_value(args[2], self._constants()), text_types))
            for item in getattr(node, 'keywords', ()) or ():
                if (_is_path_keyword(getattr(item, 'arg', None)) and
                        isinstance(_static_value(
                            item.value, self._constants()), text_types)):
                    path_resolved = True
            for arg, kind, position in candidates:
                value = _static_value(arg, self._constants())
                if isinstance(value, text_types):
                    after = self.plan.project.rewrite_module_prefix(
                        value, True)
                    if after != value:
                        replacement = ast.copy_location(ast.Str(s=after), arg)
                        if kind == 'arg':
                            node.args[position] = replacement
                        else:
                            position.value = replacement
                        self.changed = True
                else:
                    visitor = _StringExpressionRewriter(
                        self.plan.project, True)
                    visitor.visit(arg)
                    self.changed = self.changed or visitor.changed
            has_path_candidate = (len(args) >= 3 or any(
                _is_path_keyword(getattr(item, 'arg', None))
                for item in getattr(node, 'keywords', ()) or ()))
            if (not path_resolved and has_path_candidate and
                    not _is_split_module(self.plan.module)):
                self.plan.project.unresolved_registrations.append((
                    self.plan.module, getattr(node, 'lineno', 0), tail))
        else:
            dynamic_tail = _call_alias_name(node.func, self._call_aliases())
            if dynamic_tail in DYNAMIC_IMPORT_CALLS and args:
                value = _static_value(args[0], self._constants())
                if isinstance(value, text_types):
                    after = self.plan.project.rewrite_module_prefix(
                        value, False)
                    if after != value:
                        node.args[0] = ast.copy_location(
                            ast.Str(s=after), args[0])
                        self.changed = True
                else:
                    visitor = _StringExpressionRewriter(
                        self.plan.project, False)
                    visitor.visit(args[0])
                    self.changed = self.changed or visitor.changed
                    if not visitor.changed:
                        self.plan.project.unresolved_dynamic.append((
                            self.plan.module, getattr(node, 'lineno', 0),
                            dynamic_tail))
        return node


def apply_module_rename(tree, plan):
    if plan is None:
        return tree
    transformer = ModuleRenameTransformer(plan)
    tree = transformer.visit(tree)
    ast.fix_missing_locations(tree)
    return tree


def rewrite_module_source(source, plan, renderer):
    if plan is None:
        return source
    parse_source = source
    if not isinstance(parse_source, str):
        parse_source = parse_source.encode('utf-8')
    tree = ast.parse(parse_source)
    transformer = ModuleRenameTransformer(plan)
    tree = transformer.visit(tree)
    if not transformer.changed:
        return source
    ast.fix_missing_locations(tree)
    return renderer(tree, False)


class ModuleLinkError(ValueError):
    def __init__(self, issues):
        self.issues = list(issues)
        lines = ['Python module link audit failed: %d issue(s).' % len(issues)]
        for path, lineno, code, detail in self.issues[:80]:
            lines.append('  %s:%s [%s] %s' % (
                path, lineno or 0, code, detail))
        if len(self.issues) > 80:
            lines.append('  ... %d more' % (len(self.issues) - 80))
        ValueError.__init__(self, '\n'.join(lines))


def _target_names(node):
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        output = []
        for item in node.elts:
            output.extend(_target_names(item))
        return output
    return []


def _top_level_exports(tree):
    exports = set()
    wildcard = False
    for node in getattr(tree, 'body', ()) or ():
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            exports.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                exports.update(_target_names(target))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                exports.add(alias.asname or alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == '*':
                    wildcard = True
                else:
                    exports.add(alias.asname or alias.name)
    return exports, wildcard


class _OutputModule(object):
    def __init__(self, path, rel, module, is_package, tree):
        self.path = path
        self.rel = rel
        self.module = module
        self.is_package = is_package
        self.tree = tree
        self.exports, self.wildcard = _top_level_exports(tree)
        self.constants = _scope_constants(getattr(tree, 'body', ()) or ())
        self.call_aliases = _scope_call_aliases(
            getattr(tree, 'body', ()) or ())


def _normalize_output_module(reference, current, is_package, modules,
                             root_package, level=0):
    target = _resolve_import(current, is_package, reference, level)
    if target in modules:
        return target
    if root_package:
        if target == root_package and '' in modules:
            return ''
        prefix = root_package + '.'
        if target.startswith(prefix):
            inner = target[len(prefix):]
            if inner in modules:
                return inner
    package = current if is_package else current.rpartition('.')[0]
    sibling = package + '.' + target if package and target else target
    if sibling in modules:
        return sibling
    return None


def _looks_like_stale_module(reference, project):
    if not reference:
        return False
    value = reference
    prefix = project.root_package + '.'
    if value.startswith(prefix):
        value = value[len(prefix):]
    return value in project.module_map and project.module_map[value] != value


def _registration_target(value, modules, root_package):
    if not isinstance(value, text_types):
        return None
    parts = value.split('.')
    starts = [0]
    if root_package and parts and parts[0] == root_package:
        starts.insert(0, 1)
    # SDK registration namespaces are not always the source-directory name.
    # Search suffixes as well, so ``namespace.renamed_module.Class`` is linked
    # against the actual emitted provider without hard-coding that namespace.
    starts.extend(range(1, max(1, len(parts) - 1)))
    seen = set()
    for start in starts:
        if start in seen:
            continue
        seen.add(start)
        for count in range(len(parts), start, -1):
            module = '.'.join(parts[start:count])
            if module in modules:
                symbol = parts[count] if count < len(parts) else None
                return module, symbol
    if root_package and value.startswith(root_package + '.'):
        return False
    return None


def audit_module_links(output_root, project, wrapped_modules=False):
    """Parse emitted source and verify internal modules, symbols and SDK paths."""
    output_root = os.path.abspath(output_root)
    modules = {}
    issues = []
    emitted_unresolved_dynamic = []
    checked = {
        'imports': 0,
        'attributes': 0,
        'registrations': 0,
        'dynamic_imports': 0,
    }
    split_output_modules = set(
        project.mapped_module(module) for module in project.module_map
        if _is_split_module(module))
    for current, dirs, files in os.walk(output_root):
        dirs[:] = [name for name in dirs if name != '__pycache__']
        for name in files:
            if not name.lower().endswith('.py'):
                continue
            path = os.path.abspath(os.path.join(current, name))
            rel = os.path.relpath(path, output_root).replace('\\', '/')
            module, is_package = _module_name(output_root, path)
            try:
                with open(path, 'rb') as handle:
                    source = handle.read()
                try:
                    tree = ast.parse(source, path)
                except SyntaxError:
                    # The controller runs on Python 3.13 while emitted source
                    # may intentionally target Python 2.7.  Long integer
                    # suffixes are semantically irrelevant to link analysis;
                    # strip only that token form and parse the same program.
                    if not isinstance(source, text_types):
                        source = source.decode('utf-8-sig', 'replace')
                    compatible = re.sub(
                        r'(?<![A-Za-z0-9_])((?:0[xX][0-9A-Fa-f]+|[0-9]+))[lL]\b',
                        r'\1', source)
                    tree = ast.parse(compatible, path)
            except (SyntaxError, ValueError, TypeError, MemoryError) as error:
                issues.append((rel, getattr(error, 'lineno', 0),
                               'OUTPUT_PARSE_ERROR', str(error)))
                continue
            modules[module] = _OutputModule(
                path, rel, module, is_package, tree)
            # cPickle/function loaders preserve the executed module namespace
            # but hide its class/function definitions from the emitted outer
            # AST.  Merge the already analysed source contract so registration
            # and import audits still see those runtime exports.
            if wrapped_modules:
                modules[module].exports.update(project.mapped_exports(module))

    for info in list(modules.values()):
        module_aliases = {}
        for node in ast.walk(info.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    checked['imports'] += 1
                    target = _normalize_output_module(
                        alias.name, info.module, info.is_package, modules,
                        project.root_package, 0)
                    if target is not None:
                        binding = alias.asname or alias.name.split('.')[0]
                        module_aliases[binding] = target
                    elif _looks_like_stale_module(alias.name, project):
                        issues.append((info.rel, getattr(node, 'lineno', 0),
                                       'STALE_MODULE_IMPORT', alias.name))
            elif isinstance(node, ast.ImportFrom):
                checked['imports'] += len(node.names)
                target = _normalize_output_module(
                    node.module or '', info.module, info.is_package, modules,
                    project.root_package, getattr(node, 'level', 0))
                if target is None:
                    if _looks_like_stale_module(node.module, project):
                        issues.append((info.rel, getattr(node, 'lineno', 0),
                                       'STALE_FROM_MODULE', node.module))
                    continue
                provider = modules[target]
                for alias in node.names:
                    if alias.name == '*':
                        continue
                    child = target + '.' + alias.name if target else alias.name
                    if (alias.name not in provider.exports and
                            child not in modules and not provider.wildcard):
                        issues.append((
                            info.rel, getattr(node, 'lineno', 0),
                            'MISSING_IMPORTED_SYMBOL',
                            '%s has no export %s' % (target or '<root>',
                            alias.name)))

        for node in ast.walk(info.tree):
            if not isinstance(node, ast.Attribute):
                continue
            owner = node.value
            if not isinstance(owner, ast.Name):
                continue
            target = module_aliases.get(owner.id)
            if target is None or target not in modules:
                continue
            provider = modules[target]
            child = target + '.' + node.attr
            checked['attributes'] += 1
            if (node.attr not in provider.exports and child not in modules and
                    not provider.wildcard):
                issues.append((
                    info.rel, getattr(node, 'lineno', 0),
                    'MISSING_MODULE_ATTRIBUTE',
                    '%s has no attribute %s' % (target, node.attr)))

        for node in ast.walk(info.tree):
            if not isinstance(node, ast.Call):
                continue
            tail = _call_tail(node.func)
            if tail in REGISTRATION_CALLS:
                args = list(getattr(node, 'args', ()) or ())
                path_nodes = []
                if len(args) >= 3:
                    path_nodes.append(args[2])
                path_nodes.extend(
                    item.value for item in
                    (getattr(node, 'keywords', ()) or ())
                    if _is_path_keyword(getattr(item, 'arg', None)))
                if path_nodes:
                    checked['registrations'] += len(path_nodes)
                resolved = False
                path_env = _with_root_aliases(info.constants, project)
                for path_node in path_nodes:
                    path_value = _static_value(path_node, path_env)
                    if not isinstance(path_value, text_types):
                        continue
                    resolved = True
                    target = _registration_target(
                        path_value, modules, project.root_package)
                    if target is False:
                        issues.append((
                            info.rel, getattr(node, 'lineno', 0),
                            'MISSING_REGISTER_MODULE', repr(path_value)))
                    elif target:
                        module, symbol = target
                        if (symbol and
                                symbol not in modules[module].exports and
                                not modules[module].wildcard):
                            issues.append((
                                info.rel, getattr(node, 'lineno', 0),
                                'MISSING_REGISTER_SYMBOL',
                                '%s has no export %s' % (module, symbol)))
                if (path_nodes and not resolved and
                        info.module not in split_output_modules and
                        not wrapped_modules):
                    issues.append((
                        info.rel, getattr(node, 'lineno', 0),
                        'UNRESOLVED_REGISTER_PATH', tail))
            dynamic_tail = _call_alias_name(node.func, info.call_aliases)
            if dynamic_tail in DYNAMIC_IMPORT_CALLS and node.args:
                checked['dynamic_imports'] += 1
                value = _static_value(
                    node.args[0], _with_root_aliases(info.constants, project))
                if isinstance(value, text_types):
                    target = _normalize_output_module(
                        value, info.module, info.is_package, modules,
                        project.root_package, 0)
                    if target is None and _looks_like_stale_module(
                            value, project):
                        issues.append((
                            info.rel, getattr(node, 'lineno', 0),
                            'STALE_DYNAMIC_MODULE', value))
                else:
                    emitted_unresolved_dynamic.append((
                        info.module, getattr(node, 'lineno', 0),
                        dynamic_tail))

    for module, lineno, tail in project.unresolved_registrations:
        if _is_split_module(module) or wrapped_modules:
            continue
        issues.append((module or '<root>', lineno,
                       'UNRESOLVED_REGISTER_SOURCE', tail))
    if issues:
        raise ModuleLinkError(issues)
    # Prefer emitted module/line locations. Source-transform tracking may use
    # the old module name and pre-header line number for the same call.
    unresolved = list(emitted_unresolved_dynamic)
    unresolved_keys = set((row[0], row[2]) for row in unresolved)
    for module, lineno, call_name in project.unresolved_dynamic:
        mapped_module = project.mapped_module(module)
        key = (mapped_module, call_name)
        if key not in unresolved_keys:
            unresolved.append((mapped_module, lineno, call_name))
            unresolved_keys.add(key)
    return {
        'modules': len(modules),
        'dynamic_unresolved': len(unresolved),
        'issues': 0,
        'checked': checked,
        'unresolved_dynamic': unresolved,
    }
