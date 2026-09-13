# -*- coding: utf-8 -*-
"""String and constant source-level transformations."""


import ast
import random

from MCP_Armor_Src.utils.encoding import (
    byte_char, byte_value,
    byte_value,
    random_bytes,
    random_ident,
    visual_int,
)
from MCP_Armor_Src.utils.chacha import chacha8

try:
    _text_type = unicode
    _string_types = (str, unicode)
except NameError:
    _text_type = str
    _string_types = (str,)


def source_string_is_safe(value):
    if not isinstance(value, _string_types):
        return False
    if len(value) < 4:
        return False
    if any(marker in value for marker in ('RegisterSystem', 'ListenForEvent', 'UnListenForEvent', 'extraServerApi', 'extraClientApi')):
        return False
    if '/' in value or '\\' in value or value.endswith('.py'):
        return False
    return True


SOURCE_LITERAL_SENSITIVE_CALLS = set([
    'RegisterSystem', 'ListenForEvent', 'UnListenForEvent',
    'getattr', 'setattr', 'hasattr', 'delattr', '__import__', 'import_module',
    'eval', 'execfile',
])


def source_call_leaf_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def source_docstring_node(body):
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Str):
        return body[0].value
    return None


class SourceLiteralProtectionCollector(ast.NodeVisitor):
    """Collect string nodes that must remain literal for Python/NetEase semantics."""
    def __init__(self):
        self.protected = set()
        self.has_global_introspection = False

    def protect_tree_strings(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Str):
                self.protected.add(id(child))

    def protect_docstring(self, body):
        node = source_docstring_node(body)
        if node is not None:
            self.protected.add(id(node))

    def visit_Module(self, node):
        self.protect_docstring(node.body)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.protect_docstring(node.body)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.protect_docstring(node.body)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = source_call_leaf_name(node.func)
        sensitive = (name in SOURCE_LITERAL_SENSITIVE_CALLS or
                     (name and (name.startswith('Register') or name.startswith('Listen') or
                                name.startswith('UnListen') or name in ('GetClsByClsStr', 'GetModuleByName'))))
        if sensitive:
            for arg in node.args:
                self.protect_tree_strings(arg)
            for keyword in node.keywords:
                self.protect_tree_strings(keyword.value)
            if getattr(node, 'starargs', None) is not None:
                self.protect_tree_strings(node.starargs)
            if getattr(node, 'kwargs', None) is not None:
                self.protect_tree_strings(node.kwargs)
        if name in ('globals', 'vars', 'dir', 'eval', 'execfile'):
            self.has_global_introspection = True
        self.generic_visit(node)

    def visit_Exec(self, node):
        self.has_global_introspection = True
        self.generic_visit(node)

    def visit_Compare(self, node):
        if any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
            self.protect_tree_strings(node.left)
            for value in node.comparators:
                self.protect_tree_strings(value)
        self.generic_visit(node)


def collect_source_literal_protection(tree):
    collector = SourceLiteralProtectionCollector()
    collector.visit(tree)
    return collector


class SourceStringSplitter(ast.NodeTransformer):
    def __init__(self, parts=3, protected=None):
        self.parts = max(2, min(8, int(parts or 0)))
        self.protected = protected or set()

    def split_value(self, value):
        count = min(self.parts, len(value))
        if count < 2:
            return [value]
        cuts = sorted(random.sample(list(range(1, len(value))), count - 1))
        chunks = []
        start = 0
        for cut in cuts + [len(value)]:
            chunks.append(value[start:cut])
            start = cut
        return chunks

    def visit_Str(self, node):
        if id(node) in self.protected or not source_string_is_safe(node.s) or len(node.s) < self.parts:
            return node
        chunks = self.split_value(node.s)
        expr = ast.Str(s=chunks[0])
        for chunk in chunks[1:]:
            expr = ast.BinOp(left=expr, op=ast.Add(), right=ast.Str(s=chunk))
        return ast.copy_location(expr, node)


class SourceStringXor(ast.NodeTransformer):
    """Polymorphic source-string encryption with a split runtime decoder pool."""
    def __init__(self, mode='random', text_key='MCP_Shiled', number_key=173,
                 min_length=4, limit=512, protected=None, variants=4, decoys=2,
                 debug=False):
        self.mode = mode if mode in ('random', 'text', 'number', 'chacha') else 'random'
        self.text_key = text_key
        self.number_key = int(number_key or 173) & 255
        if self.number_key == 0:
            self.number_key = 173
        self.min_length = max(1, int(min_length or 1))
        self.limit = max(0, int(limit or 0))
        self.protected = protected or set()
        self.count = 0
        self.requested_variant_count = max(2, min(8, int(variants or 4)))
        self.requested_decoy_count = max(0, min(8, int(decoys or 0)))
        self.debug = bool(debug)
        self.variant_count = self.requested_variant_count
        self.decoy_count = self.requested_decoy_count
        self.pool_name = random_ident('sxp')
        self.string_pool_name = random_ident('sxs')
        self.layout = []
        self.real_pool_indexes = []
        self.entries = []
        self.entry_by_value = {}
        self.used_tokens = set()
        self.chacha_module_name = random_ident('sxc')
        self.module_seed = random.randint(1, 0x7fffffff)

    def fixed_text_bytes(self):
        value = self.text_key
        if isinstance(value, _text_type):
            value = value.encode('utf-8')
        elif not isinstance(value, (bytes, bytearray)):
            value = str(value).encode('utf-8')
        if not value:
            value = 'MCP_Shiled'
        return value

    def make_key(self, raw):
        if self.mode == 'chacha':
            return [byte_value(ch) for ch in random_bytes(32)]
        if self.mode == 'number':
            return [self.number_key]
        if self.mode == 'text':
            return [byte_value(ch) for ch in self.fixed_text_bytes()]
        upper = max(2, min(12, max(2, len(raw))))
        size = random.randint(2, upper)
        return [random.randint(1, 255) for _ in range(size)]

    def make_payload(self, raw, key):
        if self.mode == 'chacha':
            # ``bytes(generator)`` is not a byte conversion on Python 2.7:
            # it stringifies the generator object.  The generated target
            # loader correctly reconstructs the key with chr(), so build the
            # host-side encryption key with the same explicit byte join.
            key_bytes = ''.join(chr(value & 255) for value in key)
            encrypted = [byte_value(ch) for ch in chacha8(raw, key_bytes)]
            return encrypted, key, [0]
        size = len(key)
        rotate = random.randrange(0, size)
        salt = random.randint(1, 255)
        key_step = random.randint(1, 127)
        prefix = [random.randint(0, 255) for _ in range(random.randint(1, 4))]
        suffix = [random.randint(0, 255) for _ in range(random.randint(1, 4))]
        scheduled = []
        for index in range(size):
            scheduled.append((key[(index + rotate) % size] + salt +
                              index * key_step) & 255)
        key_row = prefix + scheduled + suffix
        bias = random.randint(1, 255)
        drift = random.randint(1, 127)
        record_salt = random.randint(1, 0x7fffffff)
        site_tag = random.randint(1, 0x7fffffff)
        encrypted = []
        for index, char in enumerate(raw):
            state = (self.module_seed ^ record_salt ^ site_tag ^
                     (index * 0x45D9F3B)) & 0xffffffff
            state ^= (state >> 16)
            state = (state * 0x7FEB352D) & 0xffffffff
            state ^= (state >> 15)
            stream = ((state ^ (state >> 8) ^
                       key[index % size]) & 255)
            mixed = byte_value(char) ^ stream
            encrypted.append((mixed + bias + index * drift) & 255)
        values = [self.module_seed, record_salt, site_tag, salt, key_step,
                  rotate, bias, drift, size, len(prefix)]
        descriptor_mask = random.randint(0x10001, 0x0fffffff)
        descriptor_step = random.randint(3, 0x1ffff)
        descriptor = [
            (value + descriptor_mask + index * descriptor_step) & 0xffffffff
            for index, value in enumerate(values)
        ]
        descriptor.extend([descriptor_mask, descriptor_step])
        return encrypted, key_row, descriptor

    def tuple_node(self, values):
        return ast.Tuple(elts=[ast.Num(n=value) for value in values], ctx=ast.Load())

    def selector_node(self, target, pool_size):
        left = random.randint(100, 10000)
        multiplier = random.randint(3, 97)
        offset = (target - (left * multiplier)) % pool_size
        return ast.BinOp(
            left=ast.BinOp(
                left=ast.BinOp(left=ast.Num(n=left), op=ast.Mult(), right=ast.Num(n=multiplier)),
                op=ast.Add(), right=ast.Num(n=offset)),
            op=ast.Mod(), right=ast.Num(n=pool_size))

    def opaque_integer_node(self, value):
        modulus = 2147483647
        left = random.randint(1000, 100000)
        multiplier = random.randint(11, 251)
        offset = (value - (left * multiplier)) % modulus
        return ast.BinOp(
            left=ast.BinOp(
                left=ast.BinOp(left=ast.Num(n=left), op=ast.Mult(), right=ast.Num(n=multiplier)),
                op=ast.Add(), right=ast.Num(n=offset)),
            op=ast.Mod(), right=ast.Num(n=modulus))

    def next_token(self):
        token = random.randint(0x10000, 0x7ffffffe)
        while token in self.used_tokens:
            token = random.randint(0x10000, 0x7ffffffe)
        self.used_tokens.add(token)
        return token

    def make_string_pool_reference(self, entry, location):
        expr = ast.Name(id=entry['alias'], ctx=ast.Load())
        return ast.copy_location(expr, location)

    def visit_Str(self, node):
        if (id(node) in self.protected or
                not isinstance(node.s, _string_types) or
                len(node.s) < self.min_length):
            return node
        is_unicode = isinstance(node.s, _text_type)
        raw = node.s.encode('utf-8') if is_unicode else node.s
        if not raw:
            return node
        entry_key = (bool(is_unicode), raw)
        existing = self.entry_by_value.get(entry_key)
        if existing is not None:
            return self.make_string_pool_reference(existing, node)
        if self.count >= self.limit:
            return node
        key = self.make_key(raw)
        encoded, key_row, descriptor = self.make_payload(raw, key)
        decoder_index = ast.Index(value=ast.Num(n=0))
        token = self.next_token()
        self.count += 1
        call = ast.Call(
            func=ast.Subscript(
                value=ast.Name(id=self.pool_name, ctx=ast.Load()),
                slice=decoder_index, ctx=ast.Load()),
            args=[
                self.opaque_integer_node(token),
                self.tuple_node(encoded),
                self.tuple_node(key_row),
                self.tuple_node(descriptor),
                ast.Num(n=1 if is_unicode else 0),
            ],
            keywords=[], starargs=None, kwargs=None)
        entry = {
            'key': entry_key,
            'token': token,
            'alias': random_ident('sxv'),
            'call': call,
            'decoder_index': decoder_index,
        }
        self.entries.append(entry)
        self.entry_by_value[entry_key] = entry
        return self.make_string_pool_reference(entry, node)

    def finalize_layout(self):
        item_count = len(self.entries)
        if item_count <= 8:
            self.variant_count = 2
            self.decoy_count = min(self.requested_decoy_count, 1)
        elif item_count <= 32:
            self.variant_count = min(self.requested_variant_count, 3)
            self.decoy_count = min(self.requested_decoy_count, 2)
        else:
            self.variant_count = self.requested_variant_count
            self.decoy_count = self.requested_decoy_count
        self.variant_count = max(2, self.variant_count)
        layout = [(True, index) for index in range(self.variant_count)]
        layout.extend((False, self.variant_count + index)
                      for index in range(self.decoy_count))
        random.shuffle(layout)
        self.layout = layout
        self.real_pool_indexes = [index for index, item in enumerate(layout) if item[0]]
        decoder_pool_size = len(layout)
        for entry in self.entries:
            target = random.choice(self.real_pool_indexes)
            entry['decoder_index'].value = self.selector_node(target, decoder_pool_size)
        shuffled = list(self.entries)
        random.shuffle(shuffled)
        self.entries = shuffled

    def mix_expression(self, style, value_name, key_name):
        if style == 0:
            return '((%s | %s) - (%s & %s))' % (
                value_name, key_name, value_name, key_name)
        if style == 1:
            return '(%s + %s - ((%s & %s) << 1))' % (
                value_name, key_name, value_name, key_name)
        if style == 2:
            return '(((~%s) & %s) | (%s & (~%s)))' % (
                value_name, key_name, value_name, key_name)
        return '((%s | %s) & (~(%s & %s)))' % (
            value_name, key_name, value_name, key_name)

    def decoder_variant_source(self, slot, real, style):
        key_func = random_ident('sxk')
        mix_func = random_ident('sxm')
        factory_func = random_ident('sxf')
        proxy_func = random_ident('sxc')
        class_var = random_ident('sxt')
        object_var = random_ident('sxo')
        payload_attr = random_ident('sxa')
        decoder_name = random_ident('sxd')
        row_name = random_ident('sxr')
        salt_name = random_ident('sxs')
        step_name = random_ident('sxq')
        rotate_name = random_ident('sxw')
        size_name = random_ident('sxn')
        offset_name = random_ident('sxp')
        index_name = random_ident('sxi')
        pos_name = random_ident('sxj')
        value_name = random_ident('sxv')
        key_name = random_ident('sxy')
        bias_name = random_ident('sxb')
        drift_name = random_ident('sxg')
        base_name = random_ident('sxz')
        cache_name = random_ident('sxc')
        token_name = random_ident('sxtk')
        data_name = random_ident('sxd')
        descriptor_name = random_ident('sxe')
        unicode_name = random_ident('sxu')
        mask_name = random_ident('sxm')
        descriptor_step_name = random_ident('sxds')
        values_name = random_ident('sxl')
        chars_name = random_ident('sxa')
        append_name = random_ident('sxa')
        out_name = random_ident('sxo')
        chr_name = random_ident('sxc')
        enumerate_name = random_ident('sxe')
        len_name = random_ident('sxl')
        codec_name = random_ident('sxco')
        self_name = random_ident('sxs')
        args_name = random_ident('sxa')
        seed_name = random_ident('sxseed')
        record_salt_name = random_ident('sxrs')
        site_tag_name = random_ident('sxsite')
        state_name = random_ident('sxstate')
        if self.mode == 'chacha':
            # Native NetEase ChaCha is deliberately the only runtime cipher
            # implementation.  The generated source carries ciphertext and
            # a per-literal key, never the Python fallback algorithm.
            source = (
                'def %(factory)s():\n'
                '    %(cache)s = {}\n'
                '    def %(decoder)s(%(token)s, %(data)s, %(row)s, %(descriptor)s, %(unicode)s):\n'
                '        if %(token)s in %(cache)s:\n'
                '            return %(cache)s[%(token)s]\n'
                '        %(key_bytes)s = \'\'.join(chr(%(item)s & 255) for %(item)s in %(row)s)\n'
                '        %(owner)s = type(%(owner_label)s, (object,), {})()\n'
                '        %(handle)s = %(module)s.create(%(owner)s, %(level)s, %(key_bytes)s)\n'
                '        try:\n'
                '            %(out)s = %(module)s.get_encrypted_text(%(handle)s, \'\'.join(chr(%(item)s & 255) for %(item)s in %(data)s), len(%(data)s))\n'
                '        finally:\n'
                '            try:\n'
                '                %(module)s.destroy(%(handle)s)\n'
                '            except Exception:\n'
                '                pass\n'
                '        if %(unicode)s:\n'
                '            %(out)s = %(out)s.decode(\'utf-8\')\n'
                '        %(cache)s[%(token)s] = %(out)s\n'
                '        return %(out)s\n'
                '    return %(decoder)s\n'
                'def %(proxy)s(%(self)s, *%(args)s):\n'
                '    return %(self)s.%(payload_attr)s(*%(args)s)\n'
                '%(class_var)s = type(%(class_name_repr)s, (object,), {\'__call__\': %(proxy)s})\n'
                '%(object_var)s = %(class_var)s()\n'
                '%(object_var)s.%(payload_attr)s = %(factory)s()\n'
            ) % {
                'factory': factory_func, 'cache': cache_name,
                'decoder': decoder_name, 'token': token_name,
                'data': data_name, 'row': row_name, 'descriptor': descriptor_name,
                'unicode': unicode_name, 'key_bytes': key_name,
                'item': value_name, 'owner': random_ident('sxo'),
                'owner_label': repr(random_ident('ChaChaOwner')),
                'level': visual_int(8),
                'handle': object_var,
                'module': self.chacha_module_name, 'out': out_name,
                'proxy': proxy_func, 'self': self_name, 'args': args_name,
                'payload_attr': payload_attr, 'class_var': class_var,
                'class_name_repr': repr(random_ident('sxc')),
                'object_var': object_var,
            }
            return source, object_var
        mix_expr = self.mix_expression(style % 4, base_name, key_name)
        if not real:
            mix_expr = '(%s + %s + %d)' % (base_name, key_name, (slot % 17) + 1)
        if style % 2:
            collect_code = (
                '        %s = [None] * %s(%s)\n'
                '        for %s, %s in %s(%s):\n'
                '            %s[%s] = %s(%s(%s, %s(%s, %s, %s, %s, %s, %s, %s), %s, %s, %s, %s, %s, %s))\n'
            ) % (
                chars_name, len_name, data_name,
                index_name, value_name, enumerate_name, data_name,
                chars_name, index_name, chr_name, mix_func,
                value_name, key_func, row_name, salt_name, step_name,
                rotate_name, size_name, offset_name, index_name,
                bias_name, drift_name, index_name,
                seed_name, record_salt_name, site_tag_name)
        else:
            collect_code = (
                '        %s = []\n'
                '        %s = %s.append\n'
                '        for %s, %s in %s(%s):\n'
                '            %s(%s(%s(%s, %s(%s, %s, %s, %s, %s, %s, %s), %s, %s, %s, %s, %s, %s)))\n'
            ) % (
                chars_name, append_name, chars_name,
                index_name, value_name, enumerate_name, data_name,
                append_name, chr_name, mix_func,
                value_name, key_func, row_name, salt_name, step_name,
                rotate_name, size_name, offset_name, index_name,
                bias_name, drift_name, index_name,
                seed_name, record_salt_name, site_tag_name)
        if self.debug:
            debug_begin = "        print('[DEBUG] StringXor %%s DecodeBegin Loaded' %% %s)\n" % token_name
            debug_cache_hit = "            print('[DEBUG] StringXor %%s CacheHit Loaded' %% %s)\n" % token_name
            debug_descriptor = "        print('[DEBUG] StringXor %%s Descriptor Loaded' %% %s)\n" % token_name
            debug_key = "        print('[DEBUG] StringXor %%s KeySchedule Loaded' %% %s)\n" % token_name
            debug_bytes = "        print('[DEBUG] StringXor %%s Bytes Loaded' %% %s)\n" % token_name
            debug_unicode = "            print('[DEBUG] StringXor %%s Unicode Loaded' %% %s)\n" % token_name
            debug_cache_store = "        print('[DEBUG] StringXor %%s CacheStore Loaded' %% %s)\n" % token_name
            debug_variant = "print('[DEBUG] StringXor Decoder[%d] Loaded')\n" % slot
        else:
            debug_begin = ''
            debug_cache_hit = ''
            debug_descriptor = ''
            debug_key = ''
            debug_bytes = ''
            debug_unicode = ''
            debug_cache_store = ''
            debug_variant = ''
        source = (
            'def %(key_func)s(%(row)s, %(salt)s, %(step)s, %(rotate)s, %(size)s, %(offset)s, %(index)s):\n'
            '    %(pos)s = ((%(index)s %% %(size)s) - %(rotate)s) %% %(size)s\n'
            '    return (%(row)s[%(offset)s + %(pos)s] - %(salt)s - (%(pos)s * %(step)s)) & 255\n'
            'def %(mix_func)s(%(value)s, %(key)s, %(bias)s, %(drift)s, %(index)s, %(seed)s, %(record_salt)s, %(site_tag)s):\n'
            '    %(base)s = (%(value)s - %(bias)s - (%(index)s * %(drift)s)) & 255\n'
            '    %(state)s = (%(seed)s ^ %(record_salt)s ^ %(site_tag)s ^ (%(index)s * 0x45D9F3B)) & 0xffffffff\n'
            '    %(state)s = ((%(state)s ^ (%(state)s >> 16)) * 0x7FEB352D) & 0xffffffff\n'
            '    %(state)s = %(state)s ^ (%(state)s >> 15)\n'
            '    return ((%(mix_expr)s) ^ (%(state)s ^ (%(state)s >> 8)) & 255)\n'
            'def %(factory)s(%(chr_name)s=chr, %(enum_name)s=enumerate, %(len_name)s=len):\n'
            '    %(cache)s = {}\n'
            '    %(codec)s = %(chr_name)s(117) + %(chr_name)s(116) + %(chr_name)s(102) + %(chr_name)s(45) + %(chr_name)s(56)\n'
            '    def %(decoder)s(%(token)s, %(data)s, %(row)s, %(descriptor)s, %(unicode)s):\n'
            '%(debug_begin)s'
            '        if %(token)s in %(cache)s:\n'
            '%(debug_cache_hit)s'
            '            return %(cache)s[%(token)s]\n'
            '        %(mask)s = %(descriptor)s[-2]\n'
            '        %(descriptor_step)s = %(descriptor)s[-1]\n'
            '        %(values)s = [(%(item)s - %(mask)s - (%(idx)s * %(descriptor_step)s)) & 0xffffffff for %(idx)s, %(item)s in %(enum_name)s(%(descriptor)s[:-2])]\n'
            '        %(seed)s, %(record_salt)s, %(site_tag)s, %(salt)s, %(step)s, %(rotate)s, %(bias)s, %(drift)s, %(size)s, %(offset)s = %(values)s[:10]\n'
            '%(debug_descriptor)s'
            '%(debug_key)s'
            '%(collect_code)s'
            '%(debug_bytes)s'
            '        %(out)s = \'\'.join(%(chars)s)\n'
            '        if %(unicode)s:\n'
            '            %(out)s = %(out)s.decode(%(codec)s)\n'
            '%(debug_unicode)s'
            '        %(cache)s[%(token)s] = %(out)s\n'
            '%(debug_cache_store)s'
            '        return %(out)s\n'
            '    return %(decoder)s\n'
            'def %(proxy)s(%(self)s, *%(args)s):\n'
            '    return %(self)s.%(payload_attr)s(*%(args)s)\n'
            '%(class_var)s = type(%(class_name_repr)s, (object,), {\'__call__\': %(proxy)s})\n'
            '%(object_var)s = %(class_var)s()\n'
            '%(object_var)s.%(payload_attr)s = %(factory)s()\n'
            '%(debug_variant)s'
        ) % {
            'key_func': key_func, 'mix_func': mix_func, 'factory': factory_func,
            'proxy': proxy_func, 'class_var': class_var, 'object_var': object_var,
            'payload_attr': payload_attr, 'decoder': decoder_name,
            'row': row_name, 'salt': salt_name, 'step': step_name,
            'rotate': rotate_name, 'size': size_name, 'offset': offset_name,
            'index': index_name, 'pos': pos_name, 'value': value_name,
            'key': key_name, 'bias': bias_name, 'drift': drift_name,
            'base': base_name, 'mix_expr': mix_expr, 'cache': cache_name,
            'seed': seed_name, 'record_salt': record_salt_name,
            'site_tag': site_tag_name, 'state': state_name,
            'token': token_name, 'data': data_name,
            'descriptor': descriptor_name, 'unicode': unicode_name,
            'mask': mask_name, 'descriptor_step': descriptor_step_name,
            'values': values_name, 'item': value_name, 'idx': index_name,
            'chars': chars_name, 'out': out_name, 'chr_name': chr_name,
            'enum_name': enumerate_name, 'len_name': len_name,
            'codec': codec_name, 'collect_code': collect_code,
            'self': self_name, 'args': args_name,
            'class_name_repr': repr(random_ident('sxc')),
            'debug_begin': debug_begin, 'debug_cache_hit': debug_cache_hit,
            'debug_descriptor': debug_descriptor, 'debug_key': debug_key,
            'debug_bytes': debug_bytes, 'debug_unicode': debug_unicode,
            'debug_cache_store': debug_cache_store,
            'debug_variant': debug_variant,
        }
        return source, object_var

    def decoder_statements(self):
        self.finalize_layout()
        sources = []
        object_names = []
        for slot, item in enumerate(self.layout):
            real, style = item
            source, object_name = self.decoder_variant_source(slot, real, style)
            sources.append(source)
            object_names.append(object_name)
        sources.append('%s = (%s,)\n' % (self.pool_name, ', '.join(object_names)))
        if self.debug:
            sources.append("print('[DEBUG] StringXor DecoderPool real=%d decoy=%d Loaded')\n" % (
                self.variant_count, self.decoy_count))
        statements = ast.parse('\n'.join(sources)).body
        if self.mode == 'chacha':
            statements.insert(0, ast.parse(
                'import _chacha as %s' % self.chacha_module_name).body[0])
        statements.append(ast.Assign(
            targets=[ast.Name(id=self.string_pool_name, ctx=ast.Store())],
            value=ast.Tuple(elts=[entry['call'] for entry in self.entries], ctx=ast.Load())))
        alias_rows = list(enumerate(self.entries))
        random.shuffle(alias_rows)
        for index, entry in alias_rows:
            statements.append(ast.Assign(
                targets=[ast.Name(id=entry['alias'], ctx=ast.Store())],
                value=ast.Subscript(
                    value=ast.Name(id=self.string_pool_name, ctx=ast.Load()),
                    slice=ast.Index(value=self.selector_node(index, len(self.entries))),
                    ctx=ast.Load())))
        if self.debug:
            statements.extend(ast.parse(
                "print('[DEBUG] StringXor StringPool count=%d Loaded')\n" % len(self.entries)).body)
        for statement in statements:
            for child in ast.walk(statement):
                if isinstance(child, ast.FunctionDef):
                    child._mcp_source_synthetic = True
        return statements


def obfuscate_source_strings_xor(tree, mode='random', text_key='MCP_Shiled',
                                 number_key=173, min_length=4, limit=512,
                                 protected=None, variants=4, decoys=2,
                                 debug=False):
    transformer = SourceStringXor(
        mode, text_key, number_key, min_length, limit, protected,
        variants, decoys, debug)
    tree = transformer.visit(tree)
    ast.fix_missing_locations(tree)
    helpers = transformer.decoder_statements() if transformer.count else []
    return tree, helpers


def insert_source_string_xor_helpers(tree, helpers):
    if not helpers:
        return tree
    insert_at = 0
    if (tree.body and isinstance(tree.body[0], ast.Expr) and
            isinstance(tree.body[0].value, ast.Str)):
        insert_at = 1
    while insert_at < len(tree.body):
        stmt = tree.body[insert_at]
        if not (isinstance(stmt, ast.ImportFrom) and stmt.module == '__future__'):
            break
        insert_at += 1
    tree.body[insert_at:insert_at] = helpers
    ast.fix_missing_locations(tree)
    return tree


class SourceConstantPool(ast.NodeTransformer):
    def __init__(self, min_length=4, max_items=128, protected=None):
        self.min_length = max(2, int(min_length or 0))
        self.max_items = max(0, int(max_items or 0))
        self.pool = {}
        self.used = set()
        self.protected = protected or set()
        self.counts = {}

    def value_key(self, value):
        return ('u' if isinstance(value, _text_type) else 's', value)

    def collect_used(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                self.used.add(node.id)

    def collect_values(self, tree):
        for node in ast.walk(tree):
            if (isinstance(node, ast.Str) and id(node) not in self.protected and
                    source_string_is_safe(node.s) and len(node.s) >= self.min_length):
                key = self.value_key(node.s)
                self.counts[key] = self.counts.get(key, 0) + 1

    def visit_Str(self, node):
        value = node.s
        key = self.value_key(value)
        if (id(node) in self.protected or not source_string_is_safe(value) or
                len(value) < self.min_length or self.counts.get(key, 0) < 2):
            return node
        if key not in self.pool and len(self.pool) < self.max_items:
            name = random_ident('cp')
            while name in self.used:
                name = random_ident('cp')
            self.used.add(name)
            self.pool[key] = name
        if key in self.pool:
            return ast.copy_location(ast.Name(id=self.pool[key], ctx=ast.Load()), node)
        return node

    def visit_Module(self, node):
        self.collect_used(node)
        self.collect_values(node)
        body = list(node.body)
        node.body = [self.visit(stmt) for stmt in body]
        assignments = []
        for value_key, name in sorted(list(self.pool.items()), key=lambda item: item[1]):
            assignments.append(ast.Assign(
                targets=[ast.Name(id=name, ctx=ast.Store())],
                value=ast.Str(s=value_key[1])))
        insert_at = 0
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Str):
            insert_at = 1
        while insert_at < len(node.body):
            stmt = node.body[insert_at]
            if not (isinstance(stmt, ast.ImportFrom) and stmt.module == '__future__'):
                break
            insert_at += 1
        node.body[insert_at:insert_at] = assignments
        ast.fix_missing_locations(node)
        return node


class SourceLocalConstantRewrite(ast.NodeTransformer):
    def __init__(self, limit=8):
        self.limit = max(0, int(limit or 0))
        self.depth = 0
        self.counts = []
        self.skip_number = 0

    def visit_FunctionDef(self, node):
        self.depth += 1
        self.counts.append(0)
        node.body = [self.visit(stmt) for stmt in node.body]
        self.counts.pop()
        self.depth -= 1
        return node

    def visit_Lambda(self, node):
        return node

    def visit_ClassDef(self, node):
        body = []
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.ClassDef)):
                stmt = self.visit(stmt)
            body.append(stmt)
        node.body = body
        return node

    def visit_Compare(self, node):
        if any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
            self.skip_number += 1
            self.generic_visit(node)
            self.skip_number -= 1
            return node
        return self.generic_visit(node)

    def visit_Num(self, node):
        if (self.depth <= 0 or not self.counts or self.counts[-1] >= self.limit or
                self.skip_number or isinstance(node.n, bool) or type(node.n) is not int):
            return node
        value = int(node.n)
        if value in (-1, 0, 1) or abs(value) > 1000000:
            return node
        self.counts[-1] += 1
        if value > 1:
            mode = random.randint(0, 2)
            if mode == 0:
                left = random.randint(1, value - 1)
                expr = ast.BinOp(left=ast.Num(n=left), op=ast.Add(), right=ast.Num(n=value - left))
            elif mode == 1:
                salt = random.randint(1, 255)
                expr = ast.BinOp(left=ast.Num(n=value ^ salt), op=ast.BitXor(), right=ast.Num(n=salt))
            else:
                salt = random.randint(1, 255)
                expr = ast.BinOp(left=ast.Num(n=value + salt), op=ast.Sub(), right=ast.Num(n=salt))
        else:
            magnitude = abs(value)
            salt = random.randint(1, 255)
            positive = ast.BinOp(left=ast.Num(n=magnitude + salt), op=ast.Sub(), right=ast.Num(n=salt))
            expr = ast.UnaryOp(op=ast.USub(), operand=positive)
        return ast.copy_location(expr, node)


class SourceExceptionShell(ast.NodeTransformer):
    """Reshape existing exception blocks without creating try blocks in every function."""
    def visit_TryExcept(self, node):
        self.generic_visit(node)
        if not node.orelse:
            node.orelse = [ast.Pass()]
        ast.fix_missing_locations(node)
        return node

    def visit_TryFinally(self, node):
        self.generic_visit(node)
        if not node.finalbody:
            node.finalbody = [ast.Pass()]
        elif not isinstance(node.finalbody[-1], ast.Pass):
            node.finalbody.append(ast.Pass())
        ast.fix_missing_locations(node)
        return node\n