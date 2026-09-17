# -*- coding: utf-8 -*-
"""Optional string-comparison hash guards.

The default guard mode is semantics preserving: a stable hash is used only
as a rejection filter and the original equality operation remains the final
decision.  The hash-only mode is intentionally opt-in and is not equivalent
for arbitrary input because of collisions and non-string operands.
"""

import ast
import fnmatch
import random

from MCP_Armor_Src.ast_obf.literals import source_string_is_safe
from MCP_Armor_Src.utils.encoding import random_ident, reserve_short_identifiers


HASH_MASK = 0xffffffffffffffff
HASH_OFFSET = 1469598103934665603
HASH_PRIME = 1099511628211
TEXT_TYPES_NAME = '_mcp_hash_text_types'
UNICODE_TYPE_NAME = '_mcp_hash_unicode'

try:
    _unicode_type = unicode
    _string_types = (str, unicode)
except NameError:
    _unicode_type = str
    _string_types = (str, bytes)


def _byte_value(value):
    if isinstance(value, int):
        return value
    return ord(value)


def _text_bytes(value):
    if not isinstance(value, _unicode_type):
        return value
    return value.encode('utf-8')


def stable_text_hash(value, seed=HASH_OFFSET, prime=HASH_PRIME,
                     variant=0, step=17, salt=0):
    """Return the host-side value for the generated cross-runtime hash."""
    raw = _text_bytes(value)
    result = int(seed) & HASH_MASK
    if variant == 1:
        for index, char in enumerate(raw):
            result = (result +
                      ((_byte_value(char) ^
                        ((int(salt) + index * int(step)) & 255)) *
                       int(prime))) & HASH_MASK
    elif variant == 2:
        for index, char in enumerate(raw):
            value_byte = (_byte_value(char) + index * int(step)) & 255
            result = (result + value_byte * int(prime)) & HASH_MASK
        return ((result << 7) ^ (result >> 3)) & HASH_MASK
    else:
        for char in raw:
            result = (result + _byte_value(char) * int(prime)) & HASH_MASK
    return result


def _literal_value(node):
    if isinstance(node, ast.Str):
        return node.s
    constant = getattr(ast, 'Constant', None)
    if constant is not None and isinstance(node, constant):
        value = node.value
        if isinstance(value, _string_types):
            return value
    return None


def _is_text_literal(node):
    value = _literal_value(node)
    return isinstance(value, _string_types)


def _opaque_int_text(value):
    left = random.randint(1000, 100000)
    multiplier = random.randint(3, 251)
    offset = (int(value) - left * multiplier) % (HASH_MASK + 1)
    return '((%d * %d + %d) %% %d)' % (
        left, multiplier, offset, HASH_MASK + 1)


class _PlaceholderReplacer(ast.NodeTransformer):
    def __init__(self, value_name, value_node, literal_name, literal_node):
        self.value_name = value_name
        self.value_node = value_node
        self.literal_name = literal_name
        self.literal_node = literal_node

    def visit_Name(self, node):
        if node.id == self.value_name:
            return ast.copy_location(self.value_node, node)
        if node.id == self.literal_name:
            return ast.copy_location(self.literal_node, node)
        return node


def _variant_parameters(variant, varied):
    if not varied:
        return HASH_OFFSET, HASH_PRIME, 17, 0
    return (
        random.randint(1, HASH_MASK),
        random.randint(0x100000001, 0xffffffffffffffc5) | 1,
        random.randint(3, 251),
        random.randint(1, 0x7fffffff),
    )


def _inline_hash_source(value_name, variant, seed, prime, step, salt,
                        obfuscate):
    raw_name = random_ident('raw')
    index_name = random_ident('index')
    char_name = random_ident('char')
    seed_text = _opaque_int_text(seed) if obfuscate else str(seed)
    prime_text = _opaque_int_text(prime) if obfuscate else str(prime)
    step_text = _opaque_int_text(step) if obfuscate else str(step)
    salt_text = _opaque_int_text(salt) if obfuscate else str(salt)
    byte_expr = (
        '(%s if isinstance(%s, int) else ord(%s))' %
        (char_name, char_name, char_name))
    raw_expr = (
        "(%s.encode('utf-8') if type(%s) is %s else %s)" %
        (value_name, value_name, UNICODE_TYPE_NAME, value_name))
    if variant == 1:
        item_expr = (
            '((%s ^ ((%s + %s * %s) & 255)) * %s)' %
            (byte_expr, salt_text, index_name, step_text, prime_text))
        body = 'sum((%s for %s, %s in enumerate(%s)), %s) & %d' % (
            item_expr, index_name, char_name, raw_name, seed_text, HASH_MASK)
    elif variant == 2:
        item_expr = '((%s + %s * %s) & 255) * %s' % (
            byte_expr, index_name, step_text, prime_text)
        body = (
            'sum((%s for %s, %s in enumerate(%s)), %s) & %d' %
            (item_expr, index_name, char_name, raw_name, seed_text, HASH_MASK))
        body = '(((%s) << 7) ^ ((%s) >> 3)) & %d' % (body, body, HASH_MASK)
    else:
        body = (
            'sum((%s * %s for %s in %s), %s) & %d' %
            (byte_expr, prime_text, char_name, raw_name, seed_text,
             HASH_MASK))
    return (
        '(lambda %s: %s)(%s)' %
        (raw_name, body, raw_expr), raw_name)


def _inline_expression(value_node, literal_node, operator, mode, varied,
                       obfuscate):
    value_name = random_ident('hash_value')
    literal_name = random_ident('hash_literal')
    hash_name = random_ident('hash_result')
    variant = random.randint(0, 2) if varied else 0
    seed, prime, step, salt = _variant_parameters(variant, varied)
    target = stable_text_hash(_literal_value(literal_node), seed, prime,
                              variant, step, salt)
    target_text = _opaque_int_text(target) if obfuscate else str(target)
    hash_source, _raw_name = _inline_hash_source(
        value_name, variant, seed, prime, step, salt, obfuscate)
    hash_source = '(%s if type(%s) in %s else None)' % (
        hash_source, value_name, TEXT_TYPES_NAME)
    compare = '%s %s %s' % (
        literal_name if operator == 'reverse_eq' else value_name,
        '!=' if operator in ('ne', 'reverse_ne') else '==',
        value_name if operator == 'reverse_eq' else literal_name)
    if mode == 'hash-only':
        result = '%s %s %s' % (
            hash_name, '!=' if operator in ('ne', 'reverse_ne') else '==',
            target_text)
    else:
        fallback = compare
        mismatch = 'True' if operator in ('ne', 'reverse_ne') else 'False'
        result = '(%s if (%s is None or %s == %s) else %s)' % (
            fallback, hash_name, hash_name, target_text, mismatch)
    source = (
        '(lambda %s: (lambda %s: %s)(%s))(%s)' %
        (value_name, hash_name, result, hash_source, '__MCP_HASH_VALUE__'))
    tree = ast.parse(source, mode='eval').body
    replacement = _PlaceholderReplacer(
        '__MCP_HASH_VALUE__', value_node, literal_name, literal_node).visit(tree)
    ast.fix_missing_locations(replacement)
    return replacement, target


class SourceStringHashCompare(ast.NodeTransformer):
    def __init__(self, mode='guard', inline=False, inline_obfuscate=False,
                 inline_variants=False, min_length=6, ratio=100, limit=128,
                 excludes=None):
        self.mode = mode if mode in ('guard', 'hash-only') else 'guard'
        self.inline = bool(inline)
        self.inline_obfuscate = bool(inline_obfuscate and inline)
        self.inline_variants = bool(inline_variants and inline)
        self.min_length = max(1, int(min_length or 1))
        self.ratio = max(0, min(100, int(ratio or 0)))
        self.limit = max(0, int(limit or 0))
        self.excludes = list(excludes or ())
        self.protected = set()
        self.count = 0
        self.helper_name = random_ident('hash_compare')
        self.helpers = []

    def _eligible(self, literal_node):
        value = _literal_value(literal_node)
        if (not isinstance(value, _string_types) or
                len(value) < self.min_length or
                not source_string_is_safe(value) or
                id(literal_node) in self.protected or
                self.count >= self.limit or
                random.randint(1, 100) > self.ratio):
            return False
        return not any(fnmatch.fnmatch(value, pattern)
                       for pattern in self.excludes)

    def visit_Compare(self, node):
        if len(node.ops) != 1 or len(node.comparators) != 1:
            return self.generic_visit(node)
        op = node.ops[0]
        if not isinstance(op, (ast.Eq, ast.NotEq)):
            return self.generic_visit(node)
        left_literal = _is_text_literal(node.left)
        right_literal = _is_text_literal(node.comparators[0])
        if left_literal == right_literal:
            return self.generic_visit(node)
        literal = node.left if left_literal else node.comparators[0]
        if not self._eligible(literal):
            return self.generic_visit(node)
        node = self.generic_visit(node)
        value_node = node.comparators[0] if left_literal else node.left
        literal_node = node.left if left_literal else node.comparators[0]
        operator = ('reverse_ne' if left_literal else 'ne') if isinstance(op, ast.NotEq) else (
            'reverse_eq' if left_literal else 'eq')
        if self.inline:
            replacement, _target = _inline_expression(
                value_node, literal_node, operator, self.mode,
                self.inline_variants, self.inline_obfuscate)
        else:
            target = stable_text_hash(_literal_value(literal_node))
            replacement = ast.Call(
                func=ast.Name(id=self.helper_name, ctx=ast.Load()),
                args=[value_node, literal_node, ast.Num(n=target),
                      ast.Num(n=1 if isinstance(op, ast.NotEq) else 0),
                      ast.Num(n=1 if left_literal else 0)],
                keywords=[], starargs=None, kwargs=None)
        self.count += 1
        return ast.copy_location(replacement, node)

    def helper_statements(self):
        if not self.count:
            return []
        support = ast.parse('''
try:
    %(unicode)s = unicode
except NameError:
    %(unicode)s = str
%(types)s = (str, %(unicode)s)
''' % {
            'unicode': UNICODE_TYPE_NAME,
            'types': TEXT_TYPES_NAME,
        }).body
        if self.inline:
            return support
        source = '''
def %(helper)s(value, expected, target, invert, reverse):
    if type(value) not in %(types)s:
        if reverse:
            return expected != value if invert else expected == value
        return value != expected if invert else value == expected
    raw = value.encode('utf-8') if type(value) is %(unicode)s else value
    result = %(offset)d
    for char in raw:
        result = (result + (char if isinstance(char, int) else ord(char)) * %(prime)d) & %(mask)d
    if result != target:
        return bool(invert)
    if reverse:
        return expected != value if invert else expected == value
    return value != expected if invert else value == expected
        ''' % {
            'unicode': UNICODE_TYPE_NAME,
            'types': TEXT_TYPES_NAME,
            'helper': self.helper_name,
            'offset': HASH_OFFSET,
            'prime': HASH_PRIME,
            'mask': HASH_MASK,
        }
        statements = support + ast.parse(source).body
        for statement in statements:
            for child in ast.walk(statement):
                if isinstance(child, ast.FunctionDef):
                    child._mcp_source_synthetic = True
        return statements


def obfuscate_source_string_comparisons(
        tree, mode='guard', inline=False, inline_obfuscate=False,
        inline_variants=False, min_length=6, ratio=100, limit=128,
        excludes=None, protected=None):
    source_names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            source_names.append(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            source_names.append(node.name)
        elif hasattr(ast, 'arg') and isinstance(node, ast.arg):
            source_names.append(node.arg)
    reserve_short_identifiers(source_names)
    transformer = SourceStringHashCompare(
        mode, inline, inline_obfuscate, inline_variants, min_length,
        ratio, limit, excludes)
    transformer.protected = set(protected or ())
    tree = transformer.visit(tree)
    ast.fix_missing_locations(tree)
    return tree, transformer.helper_statements(), transformer.count
