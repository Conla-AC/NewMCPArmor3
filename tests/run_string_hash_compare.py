# -*- coding: utf-8 -*-
"""Exercise string hash guards through the Python 3 host and Python 2 worker."""

from __future__ import print_function

import ast
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MCP_Armor_Src.ast_obf.control_flow import build_source_tree
from MCP_Armor_Src.ast_obf.string_compare import (
    _inline_hash_source, stable_text_hash,
)
from MCP_Armor_Src.ast_obf.structure import render_source_tree
from MCP_Armor_Src.cli.parser import build_arg_parser
from MCP_Armor_Src.pipeline.options import merge_options
from MCP_Armor_Src.pipeline.processor import process_single


SOURCE = '''# -*- coding: utf-8 -*-
def check(value):
    return value == "xxxb"

def check_unicode(value):
    return value == u"测试"

def check_reverse(value):
    return "xxxb" == value

RESULTS = [check("xxxb"), check("other"), check(123),
           check_unicode(u"测试"), check_unicode(u"其他"),
           check_reverse("xxxb"), check_reverse(123)]
'''


def _run_python27(executable, path):
    code = (
        "import runpy; ns=runpy.run_path(r'%s'); "
        "print(repr(ns['RESULTS']))" % path.replace("'", "\\'")
    )
    output = subprocess.check_output([executable, '-c', code])
    if not isinstance(output, str):
        output = output.decode('utf-8', 'replace')
    return output.strip()


def _assert_ast_mode(inline, variants):
    tree = build_source_tree(
        SOURCE, source_string_hash_compare=True,
        source_string_hash_mode='guard',
        source_string_hash_inline=inline,
        source_string_hash_inline_obfuscate=inline,
        source_string_hash_inline_variants=variants,
        source_string_hash_min_length=3)
    rendered = render_source_tree(tree)
    compile(rendered, '<string-hash-ast-test>', 'exec')
    assert '_mcp_hash' in rendered


def _assert_inline_variant_two():
    seed, prime, step, salt = 12345, 1099511628211, 17, 0
    source, _ = _inline_hash_source(
        'value', 2, seed, prime, step, salt, True)
    scope = {'value': 'xxxb', '_mcp_hash_unicode': str}
    assert eval(source, scope) == stable_text_hash(
        'xxxb', seed, prime, 2, step, salt)


def _run_pipeline(python27, inline, variants):
    root = tempfile.mkdtemp(prefix='mcparmor_hash_test_')
    try:
        source = os.path.join(root, 'sample.py')
        output = os.path.join(root, 'out.py')
        with open(source, 'wb') as handle:
            handle.write(SOURCE.encode('utf-8'))
        parser = build_arg_parser()
        argv = [
            source, '-o', output,
            '--python27', python27,
            '--no-static-check',
            '--no-source-global-rename',
            '--loader-mode', 'function',
            '--source-string-hash-compare',
            '--source-string-hash-mode', 'guard',
            '--source-string-hash-min-length', '3',
        ]
        if inline:
            argv.append('--source-string-hash-inline')
        if inline:
            argv.append('--source-string-hash-inline-obfuscate')
        if variants:
            argv.append('--source-string-hash-inline-variants')
        args = parser.parse_args(argv)
        opts = merge_options(args)
        result = process_single(source, output, args, opts)
        assert result == 'obfuscated'
        assert os.path.isfile(output)
        assert _run_python27(python27, output) == '[True, False, False, True, False, True, False]'
        return output
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    python27 = os.environ.get('MCPARMOR_PY27')
    if not python27:
        python27 = r'C:\Users\26962\source\mcp2pyc\py27\python.exe'
    if not os.path.isfile(python27):
        raise SystemExit('Python 2.7 not found: %s' % python27)
    _assert_ast_mode(False, False)
    _assert_ast_mode(True, True)
    _assert_inline_variant_two()
    _run_pipeline(python27, False, False)
    _run_pipeline(python27, True, True)
    print('string hash compare: PASS')


if __name__ == '__main__':
    main()
