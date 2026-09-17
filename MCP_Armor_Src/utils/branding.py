# -*- coding: utf-8 -*-
"""MCP Shiled output header generation."""


import io
import re
import time
import tokenize
import calendar

from MCP_Armor_Src.core.constants import (
    MCP_SHILED_ART,
    MCP_SHILED_VERSION,
)


def normalize_output_date(value=None):
    """Return a stable ``YYYY-MM-DD HH:MM:SS`` watermark timestamp."""
    text = str(value or '2012-03-15').strip()
    match = re.match(r'^(\d{4})[-/]?(\d{1,2})[-/]?(\d{1,2})(?:[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?$', text)
    if not match:
        raise ValueError('output_date must be YYYY-MM-DD or YYYY-MM-DD HH:MM:SS')
    year, month, day = [int(item) for item in match.group(1, 2, 3)]
    hour = int(match.group(4) or 0)
    minute = int(match.group(5) or 0)
    second = int(match.group(6) or 0)
    # Let time.mktime validate calendar ranges while keeping the emitted text
    # deterministic and independent of the host's current clock.
    calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    return '%04d-%02d-%02d %02d:%02d:%02d' % (
        year, month, day, hour, minute, second)


def output_date_timestamp(value=None):
    text = normalize_output_date(value)
    parts = [int(item) for item in re.split('[-: ]', text)]
    return calendar.timegm((parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], 0, 0, 0))


def mcp_shiled_header(mode='docstring', output_date=None):
    mode = str(mode or 'docstring').strip().lower()
    body = list(MCP_SHILED_ART.splitlines())
    body.append('MCP Shiled V%s OBFED_TIME:%s' % (
        MCP_SHILED_VERSION, normalize_output_date(output_date)))
    if mode == 'comment':
        lines = ['# ' + line for line in body]
    elif mode == 'docstring':
        lines = ["lambda : '''"] + body + ["'''"]
    else:
        raise ValueError('unsupported header mode: %s' % mode)
    return '\n'.join(lines) + '\n'


def _source_prologue_end(data):
    """Return the last protected source line for executable headers."""
    try:
        try:
            unicode_type = unicode
        except NameError:
            unicode_type = str
        token_text = data if isinstance(data, unicode_type) else data.decode(
            'utf-8', 'replace')
        tokens = tokenize.generate_tokens(io.StringIO(token_text).readline)
    except (UnicodeError, ValueError, MemoryError):
        return 0
    # Consume only the leading logical statements.  The previous
    # implementation materialized both a complete AST and a complete token
    # list; multi-megabyte generated loaders could therefore exhaust the
    # Python-2 process merely while inserting the banner.
    statement = []
    protected_end = 0
    first_statement = True
    try:
        for token in tokens:
            token_type, token_text_value, start, end, _line = token
            if token_type in (tokenize.INDENT, tokenize.DEDENT,
                              tokenize.COMMENT, tokenize.NL):
                continue
            if token_type == tokenize.ENDMARKER:
                break
            if token_type != tokenize.NEWLINE:
                statement.append(token)
                continue
            if not statement:
                continue
            significant = [item for item in statement
                           if item[0] not in (tokenize.COMMENT,
                                              tokenize.INDENT,
                                              tokenize.DEDENT)]
            is_doc = bool(first_statement and significant and
                          significant[0][0] == tokenize.STRING)
            is_future = bool(
                len(significant) >= 2 and
                significant[0][0] == tokenize.NAME and
                significant[0][1] == 'from' and
                significant[1][0] == tokenize.NAME and
                significant[1][1] == '__future__')
            if not is_doc and not is_future:
                break
            protected_end = max(protected_end, end[0])
            first_statement = False
            statement = []
    except (tokenize.TokenError, IndentationError, MemoryError):
        return protected_end
    return protected_end


def add_mcp_shiled_header(data, mode='docstring', output_date=None):
    header_marker = "lambda : '''\n" + MCP_SHILED_ART.splitlines()[0]
    comment_marker = '# ' + MCP_SHILED_ART.splitlines()[0]
    if header_marker in data[:4096] or comment_marker in data[:4096]:
        return data
    header = mcp_shiled_header(mode, output_date)
    lines = data.splitlines(True)
    insert_at = 0
    if lines and lines[0].startswith('#!'):
        insert_at = 1
    if len(lines) > insert_at and re.match(r'#.*coding[:=]\s*[-\w.]+', lines[insert_at]):
        insert_at += 1
    if str(mode or 'docstring').strip().lower() == 'docstring':
        insert_at = max(insert_at, _source_prologue_end(data))
    return ''.join(lines[:insert_at]) + header + ''.join(lines[insert_at:])
