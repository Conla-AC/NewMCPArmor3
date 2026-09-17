#!/usr/bin/env python2
# -*- coding: utf-8 -*-



import ast
import os
import sys


DEFAULT_FORBIDDEN_IMPORTS = set([
    'os', 'sys', 'subprocess', 'socket', 'ctypes', 'inspect', 'dis', 'py_compile',
    'pdb', 'bdb', 'trace', 'traceback', 'thread', 'threading', 'multiprocessing',
])

DEFAULT_FORBIDDEN_CALLS = set([
    'execfile', 'eval', 'compile', 'open', 'file', 'input', 'reload',
])

DEFAULT_FORBIDDEN_TOKENS = [
    'exec ', 'exec\t', '__import__(', 'import os', 'import sys',
]


def read_file(path):
    with open(path, 'rb') as handle:
        return handle.read()


def iter_python_files(path):
    if os.path.isfile(path):
        if path.endswith('.py'):
            yield path
        return
    for base, dirs, files in os.walk(path):
        for filename in files:
            if filename.endswith('.py'):
                yield os.path.join(base, filename)


def root_name(name):
    return name.split('.', 1)[0]


def add_issue(issues, path, line, kind, value):
    issues.append({
        'path': path,
        'line': line or 1,
        'kind': kind,
        'value': value,
    })


def scan_ast(path, source, issues, forbidden_imports, forbidden_calls):
    try:
        tree = ast.parse(source)
    except Exception as exc:
        add_issue(issues, path, 1, 'parse-error', str(exc))
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if root_name(alias.name) in forbidden_imports:
                    add_issue(issues, path, getattr(node, 'lineno', 1), 'forbidden-import', alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            if root_name(module) in forbidden_imports:
                add_issue(issues, path, getattr(node, 'lineno', 1), 'forbidden-import', module)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in forbidden_calls:
                add_issue(issues, path, getattr(node, 'lineno', 1), 'forbidden-call', func.id)
            elif isinstance(func, ast.Name) and func.id == '__import__':
                add_issue(issues, path, getattr(node, 'lineno', 1), 'dynamic-import', '__import__')


def scan_tokens(path, source, issues, forbidden_tokens):
    lines = source.splitlines()
    for index, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        for token in forbidden_tokens:
            if token in line:
                add_issue(issues, path, index, 'forbidden-token', token)


def scan_path(path, forbidden_imports=None, forbidden_calls=None, forbidden_tokens=None):
    forbidden_imports = set(forbidden_imports or DEFAULT_FORBIDDEN_IMPORTS)
    forbidden_calls = set(forbidden_calls or DEFAULT_FORBIDDEN_CALLS)
    forbidden_tokens = list(forbidden_tokens or DEFAULT_FORBIDDEN_TOKENS)
    issues = []
    for filename in iter_python_files(path):
        source = read_file(filename)
        scan_ast(filename, source, issues, forbidden_imports, forbidden_calls)
        scan_tokens(filename, source, issues, forbidden_tokens)
    return issues


def format_issues(issues):
    if not issues:
        return 'OK: no policy issues found'
    lines = []
    for issue in issues:
        lines.append('%s:%s: %s: %s' % (
            issue['path'], issue['line'], issue['kind'], issue['value']
        ))
    return '\n'.join(lines)


def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        sys.stderr.write('usage: netease_policy_checker.py <file-or-folder> [...]\n')
        return 2
    all_issues = []
    for path in argv:
        all_issues.extend(scan_path(path))
    print(format_issues(all_issues))
    return 1 if all_issues else 0


if __name__ == '__main__':
    sys.exit(main())
