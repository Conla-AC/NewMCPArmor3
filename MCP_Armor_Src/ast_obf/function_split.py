# -*- coding: utf-8 -*-
"""AST-driven function/class splitting for project mode.

The splitter never uses regular expressions to find Python blocks.  AST line
spans preserve multiline signatures and nested statements, while generated
modules receive the original module globals after import so third-party and
cross-module imports continue to resolve.
"""
from __future__ import print_function

import ast
import hashlib
import os
import textwrap


def _parse_text(text, filename):
    """Parse decoded source on both Python 2 and Python 3.

    Python 2 rejects a Unicode string that still contains a PEP-263 coding
    declaration (``encoding declaration in Unicode string``). The declaration
    has already served its purpose during decoding, so remove only that first
    header line before the AST parse on legacy interpreters.
    """
    try:
        return ast.parse(text, filename)
    except SyntaxError as error:
        if not isinstance(text, unicode):
            raise
        lines = text.splitlines(True)
        if lines and ('coding' in lines[0] or
                      (len(lines) > 1 and 'coding' in lines[1])):
            if lines and 'coding' in lines[0]:
                lines = lines[1:]
            elif len(lines) > 1 and 'coding' in lines[1]:
                lines = [lines[0]] + lines[2:]
            return ast.parse(u''.join(lines), filename)
        raise


def _end_lineno(node):
    end = int(getattr(node, 'lineno', 1) or 1)
    explicit = getattr(node, 'end_lineno', None)
    if explicit:
        return int(explicit)
    for child in ast.walk(node):
        end = max(end, int(getattr(child, 'lineno', end) or end))
    return end


def _has_nested_code(node):
    for child in ast.walk(node):
        if child is node:
            continue
        if isinstance(child, (ast.FunctionDef, ast.ClassDef, ast.Lambda, ast.Yield)):
            return True
    return False


def _eligible(node):
    # Special methods are part of Python's class protocol.  Moving a
    # ``__init__``/``__iter__``/descriptor hook to a sibling module changes
    # the class construction order and, with module renaming enabled, can
    # leave an import pointing at a generated file that the target worker
    # does not emit.  Keep dunder methods in their defining class; regular
    # methods and top-level functions remain eligible for splitting.
    name = getattr(node, 'name', '') or ''
    if name.startswith('__') and name.endswith('__'):
        return False
    args = getattr(node, 'args', None)
    if args is None or getattr(args, 'defaults', None):
        return False
    if getattr(args, 'kw_defaults', None) or getattr(args, 'annotations', None):
        return False
    if getattr(node, 'decorator_list', None) or getattr(node, 'returns', None):
        return False
    return not _has_nested_code(node)


def _module_import(module_name, function_name, package, ordinal):
    alias = '_mcp_bind_%s_%d' % (function_name, ordinal)
    if package:
        statement = ('try:\n'
                     '    from .%s import %s as %s\n'
                     'except (ImportError, ValueError):\n'
                     '    from %s import %s as %s\n' %
                     (module_name, function_name, alias,
                      module_name, function_name, alias))
    else:
        statement = 'from %s import %s as %s\n' % (module_name, function_name, alias)
    # Python 2 uses func_globals; Python 3 uses __globals__.  Updating the
    # extracted function's globals makes imported SDK names and sibling-module
    # bindings behave exactly as in the source module.
    statement += ('try:\n'
                  '    %s.func_globals.update(globals())\n'
                  'except AttributeError:\n'
                  '    try:\n'
                  '        %s.__globals__.update(globals())\n'
                  '    except AttributeError:\n'
                  '        pass\n'
                  '%s = %s\n' % (alias, alias, function_name, alias))
    return statement


def _refresh_statement(alias):
    """Refresh an extracted function's globals after module initialization."""
    return ('try:\n'
            '    %s.func_globals.update(globals())\n'
            'except AttributeError:\n'
            '    try:\n'
            '        %s.__globals__.update(globals())\n'
            '    except AttributeError:\n'
            '        pass\n' % (alias, alias))


def _split_file(path):
    try:
        with open(path, 'rb') as handle:
            raw = handle.read()
        text = raw.decode('utf-8-sig')
        tree = _parse_text(text, path)
    except (IOError, OSError, UnicodeDecodeError, SyntaxError, ValueError):
        return 0
    lines = text.splitlines(True)
    candidates = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and _eligible(node):
            candidates.append((node, None))
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, ast.FunctionDef) and _eligible(child):
                    candidates.append((child, node.name))
    if not candidates:
        return 0
    package = os.path.isfile(os.path.join(os.path.dirname(path), '__init__.py'))
    digest = hashlib.sha1(os.path.abspath(path).encode('utf-8')).hexdigest()[:8]
    inserts, replacements, generated, refreshes = [], {}, [], []
    for ordinal, (node, class_name) in enumerate(candidates):
        start, end = int(node.lineno) - 1, _end_lineno(node)
        block = ''.join(lines[start:end])
        if class_name:
            # ``textwrap.dedent`` treats a CR left on whitespace-only CRLF
            # lines as visible content.  A class method containing such a
            # blank line can therefore retain its four-space class indent and
            # make the generated standalone module fail at line 2. Normalize
            # newlines before dedenting, then validate the generated block.
            block = block.replace('\r\n', '\n').replace('\r', '\n')
            block = textwrap.dedent(block)
        try:
            ast.parse(block, '<function-split:%s>' % node.name)
        except (SyntaxError, ValueError):
            # Preserve the original definition rather than emitting a broken
            # sibling module when an exotic source layout is encountered.
            continue
        module_name = '__mcp_fn_%s_%d' % (digest, ordinal)
        module_path = os.path.join(os.path.dirname(path), module_name + '.py')
        with open(module_path, 'wb') as handle:
            handle.write(('# -*- coding: utf-8 -*-\n' + block).encode('utf-8'))
        inserts.append(_module_import(module_name, node.name, package, ordinal))
        refreshes.append('_mcp_bind_%s_%d' % (node.name, ordinal))
        generated.append(module_path)
        if class_name:
            indent = lines[start][:len(lines[start]) - len(lines[start].lstrip(' \t'))]
            replacements[start] = (end, '%s%s = _mcp_bind_%s_%d\n' %
                                   (indent, node.name, node.name, ordinal))
        else:
            replacements[start] = (end, '')
    # Replace source blocks in reverse order while leaving imports, globals and
    # third-party imports untouched.
    output, index = [], 0
    while index < len(lines):
        replacement = replacements.get(index)
        if replacement:
            end, replacement_text = replacement
            if replacement_text:
                output.append(replacement_text)
            index = end
            continue
        output.append(lines[index]); index += 1
    # Generated imports must run after the source module's own imports.  That
    # way ``func_globals.update(globals())`` captures third-party SDK modules
    # and cross-module imports rather than an incomplete prologue namespace.
    # AST determines the boundary; no textual import matching is used.
    insert_line = 0
    body_nodes = list(getattr(tree, 'body', ()) or ())
    for position, top in enumerate(body_nodes):
        is_doc = (position == 0 and isinstance(top, ast.Expr) and
                  isinstance(getattr(top, 'value', None), ast.Str))
        if is_doc or isinstance(top, (ast.Import, ast.ImportFrom)):
            insert_line = max(insert_line, _end_lineno(top))
            continue
        break
    insert_at = min(len(output), insert_line)
    if insert_at == 0:
        insert_at = 1 if output and output[0].startswith('#!') else 0
        if insert_at < len(output) and output[insert_at].lstrip().startswith('#') and 'coding' in output[insert_at]:
            insert_at += 1
    output[insert_at:insert_at] = [item + '\n' for item in inserts]
    # Repeat the global refresh at the end so names assigned below the import
    # block (constants, SDK handles and sibling imports) are visible when the
    # extracted function is eventually called.
    output.extend(['\n' + _refresh_statement(alias) for alias in refreshes])
    with open(path, 'wb') as handle:
        handle.write(''.join(output).encode('utf-8'))
    return len(candidates)


def split_project_functions(root, include=None, exclude=None):
    """Split eligible top-level functions and class methods in *root*."""
    excluded = set(os.path.normcase(str(item).replace('\\', '/'))
                   for item in (exclude or ()))
    count = 0
    for current, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            if not name.lower().endswith('.py') or name.startswith('__mcp_fn_'):
                continue
            if name.lower() in ('modmain.py', '__init__.py'):
                continue
            rel = os.path.relpath(os.path.join(current, name), root).replace('\\', '/')
            if rel in excluded or os.path.normcase(name) in excluded:
                continue
            count += _split_file(os.path.join(current, name))
    return count
