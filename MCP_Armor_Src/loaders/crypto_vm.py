# -*- coding: utf-8 -*-
"""Compile the payload crypto runtime through the AST VM before embedding.

The plaintext crypto helpers (CityHash64 / ChaCha20 / MT19937_64 / chained
XChaCha20) are renamed to fresh random identifiers and compiled into register
machine programs, so the generated loader carries VM bytecode instead of
recognizable algorithm source.
"""

import ast
import io
import sys
import tokenize
import re

from MCP_Armor_Src.ast_obf.VM.vm import (
    collect_source_vm_global_names,
    virtualize_source_functions,
)
from MCP_Armor_Src.ast_obf.structure import render_source_tree
from MCP_Armor_Src.loaders.crypto_runtime import CRYPTO_RUNTIME_SOURCE
from MCP_Armor_Src.utils.encoding import random_ident


def _rename_mcp(source):
    """Rename ``_mcp_*`` NAME tokens to fresh random identifiers."""
    token_source = source
    if sys.version_info[0] < 3 and isinstance(source, str):
        token_source = source.decode('utf-8')
    tokens = list(tokenize.generate_tokens(io.StringIO(token_source).readline))
    mapping = {}
    used = set()
    replacements = []
    lines = token_source.splitlines(True)
    offsets = []
    cursor = 0
    for line in lines:
        offsets.append(cursor)
        cursor += len(line)
    for tok_type, tok_text, _start, _end, _line in tokens:
        if tok_type == tokenize.NAME:
            used.add(tok_text)
    for tok_type, tok_text, start, end, _line in tokens:
        if tok_type != tokenize.NAME or not tok_text.startswith('_mcp_'):
            continue
        if tok_text not in mapping:
            value = random_ident()
            while value in used:
                value = random_ident()
            mapping[tok_text] = value
            used.add(value)
        start_offset = offsets[start[0] - 1] + start[1]
        end_offset = offsets[end[0] - 1] + end[1]
        replacements.append((start_offset, end_offset, mapping[tok_text]))
    out = list(token_source)
    for start_offset, end_offset, value in reversed(replacements):
        out[start_offset:end_offset] = value
    result = ''.join(out)
    if sys.version_info[0] < 3:
        result = result.encode('utf-8')
    return result, mapping


_cached = {}


def _wrap_numeric_tuple_lines(source, width=120):
    """Keep generated VM tables below conservative loader line limits."""
    out = []
    pattern = re.compile(r'^(\s*(?:[A-Za-z_]\w*\s*=|return)\s*)\(([-+]?\d+(?:\s*,\s*[-+]?\d+)+)\)\s*$')
    for line in source.splitlines(True):
        raw = line.rstrip('\r\n')
        match = pattern.match(raw)
        if not match and 'return (' in raw:
            head, tail = raw.split('return (', 1)
            if tail.endswith(')') and all(ch in '0123456789+-, \t' for ch in tail[:-1]):
                class _TupleMatch(object):
                    def __init__(self, prefix, values):
                        self.prefix, self.values = prefix, values
                    def group(self, index):
                        return self.prefix if index == 1 else self.values
                match = _TupleMatch(head + 'return ', tail[:-1])
        if not match or len(line.rstrip('\r\n')) <= width:
            out.append(line)
            continue
        values = [item.strip() for item in match.group(2).split(',')]
        prefix = match.group(1)
        rows = [prefix + '(']
        current = '    '
        for value in values:
            piece = value + ','
            if len(current) + len(piece) > width - len(prefix):
                rows.append(current)
                current = '    '
            current += piece + ' '
        if current.strip():
            rows.append(current)
        rows.append(')')
        out.append('\n'.join(rows) + ('\n' if line.endswith(('\n', '\r')) else ''))
    return ''.join(out)


def virtualize_crypto_source(enabled=True):
    """Return the crypto runtime, optionally without loader VM virtualization."""
    cache_key = bool(enabled)
    if cache_key in _cached:
        return _cached[cache_key]
    renamed, mapping = _rename_mcp(CRYPTO_RUNTIME_SOURCE)
    if enabled:
        tree = ast.parse(renamed)
        known = collect_source_vm_global_names(tree)
        for key in ('_mcp_d0', '_mcp_d1', '_mcp_d2', '_mcp_d3'):
            known.add(mapping[key])
        tree, _count = virtualize_source_functions(
            tree, ratio=100, min_ops=1, max_ops=100000, max_functions=0,
            allow_loops=True, known_global_names=known, encrypt_names=True)
        rendered = render_source_tree(tree)
        rendered = _wrap_numeric_tuple_lines(rendered)
    else:
        rendered = renamed
    result = (rendered, mapping['_mcp_decrypt'],
              mapping['_mcp_d0'], mapping['_mcp_d1'], mapping['_mcp_d2'], mapping['_mcp_d3'],
              mapping['_mcp_fake0'], mapping['_mcp_fake1'], mapping['_mcp_fake2'], mapping['_mcp_fake3'], mapping['_mcp_fake4'])
    _cached[cache_key] = result
    return result\n