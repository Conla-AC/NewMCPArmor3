# -*- coding: utf-8 -*-
"""Random identifiers, payload ciphers and encoded row helpers."""


import base64
from MCP_Armor_Src.core import py27_opcode as opcode
import keyword
import random
import re
import string
import sys
import tokenize
import zlib

try:
    import io
except ImportError:
    import io as StringIO

from MCP_Armor_Src.utils.chacha import chacha8


# Keep generated loader bindings lowercase.  Besides matching the ProGuard
# style audit, this avoids mixed-case names being mistaken for semantic API
# symbols by downstream scanners once a large CodeTuple loader exceeds the
# first 26 short identifiers.
_SHORT_IDENT_ALPHABET = string.ascii_lowercase


def short_ident(index):
    """Return compact case-mixed identifiers.

    The sequence is ``a..z``, ``A..Z``, ``aa..aZ``, ``ba..``.  Keeping the
    first 52 values to one character gives the Rename layer more compact
    output while remaining valid and deterministic on Python 2 and 3.
    """
    value = int(index)
    if value < 0:
        raise ValueError('identifier index must be non-negative')
    if value < len(_SHORT_IDENT_ALPHABET):
        return _SHORT_IDENT_ALPHABET[value]
    value += 1
    chars = []
    while value:
        value, remainder = divmod(value - 1, len(_SHORT_IDENT_ALPHABET))
        chars.append(_SHORT_IDENT_ALPHABET[remainder])
    return ''.join(reversed(chars))


try:
    import builtins as _identifier_builtins
except ImportError:
    import __builtin__ as _identifier_builtins

_SHORT_IDENT_RESERVED = set(keyword.kwlist)
_SHORT_IDENT_RESERVED.update(('print', 'exec', 'raw_input', 'long', 'unicode', 'basestring',
                               'True', 'False', 'None'))
_SHORT_IDENT_RESERVED.update(name for name in dir(_identifier_builtins)
                             if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name))
_SHORT_IDENT_INDEX = 0
_SHORT_IDENT_USED = set()


def random_ident(prefix='_or'):
    """Return the next ProGuard-style short identifier.

    ``prefix`` remains accepted for callers that use semantic labels, but the
    emitted identifier intentionally contains no prefix or hexadecimal marker.
    """
    global _SHORT_IDENT_INDEX
    while True:
        value = short_ident(_SHORT_IDENT_INDEX)
        _SHORT_IDENT_INDEX += 1
        if value in _SHORT_IDENT_RESERVED or value in _SHORT_IDENT_USED:
            continue
        _SHORT_IDENT_USED.add(value)
        return value


def reserve_short_identifiers(names):
    """Prevent generated short names from shadowing input-source symbols."""
    for name in names or ():
        if isinstance(name, str) and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
            _SHORT_IDENT_RESERVED.add(name)


def reserve_source_identifiers(source):
    """Collect NAME tokens without interpreting strings or comments."""
    if isinstance(source, bytes):
        source = source.decode('utf-8', 'replace')
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        reserve_short_identifiers(
            token_text for token_type, token_text, _start, _end, _line in tokens
            if token_type == tokenize.NAME)
    except (tokenize.TokenError, IndentationError, UnicodeError, TypeError):
        return


def visual_int(value):
    """Render an integer through diversified Python protocol noise.

    These expressions are used in generated loaders and unreachable decoys,
    not sprayed over user hot paths.  Keep the result inside Python's integer
    protocol so it remains valid on both Python 2.7 and Python 3 test hosts.
    """
    value = int(value)
    if value == -1:
        # CPython reserves hash(-1) as an error sentinel and returns -2.
        return '((-2 + 0).__hash__().__add__(1))'
    salt = random.randint(3, 0x3ff)
    odd = random.choice((3, 5, 7, 9, 11, 13))
    shift = random.randint(1, 4)
    variants = (
        '((%d + 0)).__hash__()' % value,
        '((%d ^ 0)).__hash__()' % value,
        '((%d - 0)).__hash__()' % value,
        '(((%d ^ 0)).__xor__(%d).__xor__(%d)).__hash__()' % (
            value, salt, salt),
        '((%d + %d).__sub__(%d)).__hash__()' % (
            value, salt, salt),
        '((%d - %d).__add__(%d)).__hash__()' % (
            value, salt, salt),
        '((%d ^ %d).__xor__(%d)).__hash__()' % (
            value, salt, salt),
        '((%d << %d).__rshift__(%d)).__hash__()' % (
            value, shift, shift),
        '((~%d).__invert__()).__hash__()' % value,
        '((%d * %d).__floordiv__(%d)).__hash__()' % (
            value, odd, odd),
    )
    return random.choice(variants)


# Names used by legacy loader templates.  These are implementation locals, not
# Python's CodeType protocol attributes (``co_names``, ``co_consts`` etc.).
# Keep the match bounded so ``co_names`` is never rewritten accidentally.
_RESERVED_GENERATED_IDENTIFIER = re.compile(
    r'(?<![A-Za-z0-9_])('
    r'_mcp_[A-Za-z0-9_]+'
    r'|_(?:names|consts|co|bytes|depth|fake_codes|unused|mirror|'
    r'target_opcode|index_shuffle|code_rows|true_index|notab)'
    r'(?:_[A-Za-z0-9]+)?'
    r')(?![A-Za-z0-9_])')


def obfuscate_reserved_generated_identifiers(source):
    """Rename legacy ``_mcp_*`` output identifiers without AST metadata.

    Some older loader templates emitted their internal helper names directly
    into source (for example ``_mcp_index_shuffle``). The final text pass keeps
    one mapping per build, so code references and exact string-based getattr
    references remain consistent while the output uses the shared short-name
    allocator.
    names. This intentionally runs only on generated output, never on AST
    metadata attributes used by the transformer itself.
    """
    if not source:
        return source
    mapping = {}
    used = set()
    replacements = []
    lines = source.splitlines(True)
    offsets = []
    cursor = 0
    for line in lines:
        offsets.append(cursor)
        cursor += len(line)

    try:
        token_source = source
        if sys.version_info[0] < 3 and isinstance(source, str):
            token_source = source.decode('utf-8')
        tokens = list(tokenize.generate_tokens(io.StringIO(token_source).readline))
        # This pass runs after AST transforms have rendered generated helper
        # names back to source.  A short replacement must not reuse any name
        # already present in the module, especially a function-local binding
        # such as ``i`` used by a later ``for i in ...``.  Otherwise a global
        # decoder alias becomes local at runtime and an earlier branch raises
        # UnboundLocalError before the loop initializes it.
        for token_type, token_text, _start, _end, _line in tokens:
            if token_type == tokenize.NAME:
                used.add(token_text)
        for token_type, token_text, start, end, _line in tokens:
            if token_type != tokenize.NAME:
                continue
            match = _RESERVED_GENERATED_IDENTIFIER.match(token_text)
            if not match or match.group(0) != token_text:
                continue
            if token_text not in mapping:
                value = random_ident()
                while value in used:
                    value = random_ident()
                mapping[token_text] = value
                used.add(value)
            start_offset = offsets[start[0] - 1] + start[1]
            end_offset = offsets[end[0] - 1] + end[1]
            replacements.append((start_offset, end_offset, mapping[token_text]))
    except (tokenize.TokenError, IndentationError, IndexError):
        # Generated loader text is validated later. If tokenization is ever
        # unavailable, preserving a readable helper is safer than mutating an
        # encrypted string literal with a whole-source regex.
        return source

    if not replacements:
        return source
    output = []
    cursor = 0
    for start_offset, end_offset, value in replacements:
        output.append(source[cursor:start_offset])
        output.append(value)
        cursor = end_offset
    output.append(source[cursor:])
    return ''.join(output)


def debug_print_code(enabled, label, indent=0):
    if not enabled:
        return ''
    return '%sprint(%r)' % (' ' * max(0, int(indent)), '[DEBUG] %s Loaded' % label)


def build_loader_debug_parts(enabled, mode):
    prefix = 'MCP %s' % mode
    labels = {
        'debug_loader_init': ('LoaderInit', 0),
        'debug_run_begin': ('RunBegin', 4),
        'debug_imports': ('RuntimeImports', 4),
        'debug_key_mask': ('KeyMaskDecode', 4),
        'debug_key': ('KeyDecode', 4),
        'debug_payload_graph': ('PayloadGraph', 4),
        'debug_payload_b64': ('PayloadBase64', 4),
        'debug_payload_decode': ('PayloadDecryptDecompress', 4),
        'debug_code_object': ('CodeObjectRebuild', 4),
        'debug_opcode_begin': ('OpcodeRestoreBegin', 8),
        'debug_opcode_done': ('OpcodeRestoreComplete', 8),
        'debug_function_type': ('FunctionType', 4),
        'debug_execute_begin': ('ModuleExecuteBegin', 4),
        'debug_execute_done': ('ModuleExecuteComplete', 4),
    }
    return dict((key, debug_print_code(enabled, '%s %s' % (prefix, value[0]), value[1]))
                for key, value in list(labels.items()))


def xor_code_list(codes, key):
    """对 ASCII 码列表进行异或加密，返回可作为 Python 列表字面量的字符串。"""
    encrypted = [(c ^ key) & 0xFF for c in codes]
    # 转为紧凑列表形式，如 "[123, 34, 56]"
    return '[' + ', '.join(str(v) for v in encrypted) + ']'


def random_bytes(size):
    """Return opaque random bytes on the Python 3 host.

    The generated NetEase Python 2 source accepts the resulting ``b''``
    literals, while keeping compression/cipher operations binary-safe on the
    host runtime.
    """
    values = [random.randrange(0, 256) for _ in range(size)]
    if sys.version_info[0] < 3:
        return ''.join(chr(value) for value in values)
    return bytes(values)


def byte_value(value):
    """Return an integer for either a Python 2-style byte or Python 3 byte."""
    return value if isinstance(value, int) else ord(value)


def byte_char(value):
    """Build one binary byte without relying on Python 2 ``chr`` semantics."""
    value = int(value) & 255
    if sys.version_info[0] < 3:
        return chr(value)
    return bytes((value,))


def bytes_from_values(values):
    values = [int(value) & 255 for value in values]
    if sys.version_info[0] < 3:
        return ''.join(chr(value) for value in values)
    return bytes(values)


def chunk_text(text, min_size, max_size):
    chunks = []
    pos = 0
    while pos < len(text):
        step = random.randint(min_size, max_size)
        chunks.append(text[pos:pos + step])
        pos += step
    return chunks or ['']


def make_table_rows(tag, chunks, fake_count):
    rows = []
    for idx, chunk in enumerate(chunks):
        rows.append((tag, idx, chunk))
    for _ in range(fake_count):
        rows.append((random_ident('tag'), random.randint(1000, 999999), base64.b64encode(random_bytes(random.randint(8, 32)))))
    random.shuffle(rows)
    return rows


def rows_repr(rows):
    lines = []
    for tag, idx, value in rows:
        lines.append('    (%r, %d, %r),' % (tag, idx, value))
    # Emit actual source newlines. A literal backslash-n makes the generated
    # loader fail parsing as soon as a table has more than one row.
    return '\n'.join(lines)


def xor_data(data, key):
    data = data if isinstance(data, (bytes, bytearray)) else str(data).encode('latin1')
    key = key if isinstance(key, (bytes, bytearray)) else str(key).encode('latin1')
    return bytes_from_values(byte_value(ch) ^ byte_value(key[idx % len(key)])
                             for idx, ch in enumerate(data))


def add_data(data, key):
    data = data if isinstance(data, (bytes, bytearray)) else str(data).encode('latin1')
    key = key if isinstance(key, (bytes, bytearray)) else str(key).encode('latin1')
    return bytes_from_values((byte_value(ch) + byte_value(key[idx % len(key)])) & 255
                             for idx, ch in enumerate(data))


def roll_data(data, key):
    data = data if isinstance(data, (bytes, bytearray)) else str(data).encode('latin1')
    key = key if isinstance(key, (bytes, bytearray)) else str(key).encode('latin1')
    return bytes_from_values(byte_value(ch) ^ ((byte_value(key[idx % len(key)]) + idx) & 255)
                             for idx, ch in enumerate(data))


def encode_payload(raw, key, level, chacha_key=None):
    if sys.version_info[0] >= 3 and isinstance(raw, str):
        raw = raw.encode('utf-8')
    elif sys.version_info[0] < 3:
        try:
            if isinstance(raw, unicode):
                raw = raw.encode('utf-8')
        except NameError:
            pass
    ops = [4, 0, 1, 2, 3]
    data = zlib.compress(raw, level)
    data = xor_data(data, key)
    data = add_data(data, key)
    data = roll_data(data, key)
    data = data[::-1]
    if chacha_key:
        # ChaCha is the outermost layer, so the generated decoder restores it
        # before reversing the compact legacy pipeline above.
        data = chacha8(data, chacha_key)
        ops.append(5)
    return data, ops


def random_metadata_label(prefix):
    alphabet = string.ascii_letters + string.digits + '_$.-@#'
    return prefix + '_' + ''.join(random.choice(alphabet) for _ in range(random.randint(16, 48))) + '.py'


def random_binary_metadata_label(prefix):
    alphabet = string.ascii_letters + string.digits + '!#$%&()+-.@[]^_{}~'
    raw = ''.join(random.choice(alphabet) for _ in range(random.randint(24, 72)))
    return prefix + '_' + raw + '.py'


def can_poison_real_code_name(co, name):
    return name not in ('<module>',)


def build_fake_mcs_rows(count):
    rows = []
    for version in range(max(0, count)):
        tag = random_ident('mcs')
        salt = random.randint(1, 255)
        for opv in sorted(set(opcode.opmap.values())):
            rows.append((tag, version ^ salt, (opv ^ salt) & 255, random.randint(0, 255), random.randint(0, 255)))
    random.shuffle(rows)
    return rows


def build_payload_split_rows(encoded, options):
    encoded_b64 = base64.b64encode(encoded)
    split_count = max(1, options.payload_splits)
    if split_count <= 1 or len(encoded_b64) < split_count:
        tag = random_ident('ptag')
        rows = make_table_rows(tag, chunk_text(encoded_b64, options.chunk_min, options.chunk_max), options.extra_payload_fakes)
        return encode_multilayer_rows(rows), [tag]
    tags = []
    rows = []
    size = (len(encoded_b64) + split_count - 1) // split_count
    for idx in range(split_count):
        part = encoded_b64[idx * size:(idx + 1) * size]
        if not part:
            continue
        tag = random_ident('ptag')
        tags.append(tag)
        rows.extend(make_table_rows(tag, chunk_text(part, options.chunk_min, options.chunk_max), options.extra_payload_fakes))
    for _mirror in range(max(0, getattr(options, 'fake_payload_mirrors', 0))):
        fake_tag = random_ident('pmir')
        fake_data = base64.b64encode(zlib.compress(random_bytes(random.randint(96, 384)), 9))
        rows.extend(make_table_rows(fake_tag, chunk_text(fake_data, options.chunk_min, options.chunk_max), options.extra_payload_fakes + 3))
    if getattr(options, 'payload_graph_split', False) and len(tags) > 1:
        graph = []
        salt = random.randint(1, 255)
        for idx, tag in enumerate(tags):
            prev_idx = idx - 1 if idx else -1
            graph.append((tag, idx ^ salt, prev_idx ^ salt, salt, random.randint(1000, 999999), 1 ^ salt))
        for idx in range(max(0, getattr(options, 'payload_graph_decoys', 0))):
            graph.append((random_ident('gdec'), random.randint(1000, 999999) ^ salt, random.randint(-8, 999999) ^ salt, salt, random.randint(1000, 999999), 0 ^ salt))
        random.shuffle(graph)
        return encode_multilayer_rows(rows), graph
    return encode_multilayer_rows(rows), tags


def encode_multilayer_rows(rows):
    out = []
    for tag, idx, value in rows:
        for _retry in range(64):
            row_key = random.randint(1, 255)
            encoded = bytes_from_values(
                (byte_value(ch) + ((row_key + pos) & 255)) & 255
                for pos, ch in enumerate(value))[::-1]
            preview = repr((tag, idx ^ row_key, encoded, row_key)).lower()
            if 'exec' not in preview and 'eval' not in preview:
                break
        out.append((tag, idx ^ row_key, encoded, row_key))
    random.shuffle(out)
    return out
