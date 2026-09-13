# -*- coding: utf-8 -*-
"""Function identity weaving and decompiler carrier transforms."""


import ast
import copy
import fnmatch
import random

from MCP_Armor_Src.ast_obf.literals import (
    insert_source_string_xor_helpers,
    source_docstring_node,
)

from MCP_Armor_Src.utils.encoding import (
    byte_char, byte_value,
    random_ident,
)


def _ensure_locations(node, lineno=1, col_offset=0):
    """Fill source coordinates missed by Python 2's AST helper.

    CPython 2.7 ``ast.fix_missing_locations`` does not reliably propagate
    coordinates through every manually-created expression nested below
    ``Index``/``Attribute`` containers.  Identity weaving creates exactly
    those shapes.  Seed only absent fields and retain every real source
    position already present on copied user nodes.
    """
    if not isinstance(node, ast.AST):
        return
    current_line = getattr(node, 'lineno', None)
    current_col = getattr(node, 'col_offset', None)
    if not isinstance(current_line, int) or current_line < 1:
        current_line = lineno
        try:
            node.lineno = int(current_line)
        except Exception:
            pass
    if not isinstance(current_col, int) or current_col < 0:
        current_col = col_offset
        try:
            node.col_offset = int(current_col)
        except Exception:
            pass
    for child in ast.iter_child_nodes(node):
        _ensure_locations(child, current_line, current_col)


class SourceIdentityWeaver(object):
    """Split a public function into a decoy definition and a real code twin.

    The public function object is created with a harmless, misleading body and
    receives the real ``func_code``/``func_defaults`` immediately afterwards.
    This uses only documented Python 2 function-object fields, costs work only
    during module initialization, and adds no call-site trampoline.
    """

    def __init__(self, ratio=45, max_functions=12, default_capsule=False,
                 role_variation=False):
        self.ratio = max(0, min(100, int(ratio or 0)))
        self.max_functions = max(0, int(max_functions or 0))
        self.default_capsule = bool(default_capsule)
        self.role_variation = bool(role_variation)
        self.count = 0

    def _eligible(self, node):
        if getattr(node, '_mcp_source_synthetic', False):
            return False
        if node.decorator_list or node.name.startswith('__'):
            return False
        if self.max_functions and self.count >= self.max_functions:
            return False
        for pattern in ('On*', '*Tick*', '*Update*', '*Timer*',
                        '*Frame*', '*Render*', 'Listen*', 'Notify*',
                        'NeteaseMod*'):
            if fnmatch.fnmatch(node.name, pattern):
                return False
        # A generator's execution identity is part of its public protocol;
        # leave generators untouched and use ordinary functions as carriers.
        if any(isinstance(item, ast.Yield) for item in ast.walk(node)):
            return False
        descendants = list(ast.iter_child_nodes(node))
        while descendants:
            item = descendants.pop()
            if isinstance(item, (ast.FunctionDef, ast.ClassDef, ast.Lambda)):
                return False
            descendants.extend(ast.iter_child_nodes(item))
        return self.ratio >= 100 or random.randint(1, 100) <= self.ratio

    def _decoy_body(self, node):
        doc = source_docstring_node(node.body)
        doc_statement = node.body[0] if doc is not None else None
        body = [doc_statement] if doc_statement is not None else []
        phantom = random_ident('phantom')
        variant = random.randint(0, 2) if self.role_variation else 0
        if variant == 0:
            source = (
                'try:\n'
                '    if 0:\n'
                '        return None\n'
                '    %(phantom)s = tuple((%(phantom)s for %(item)s in ()))\n'
                '    return None\n'
                'finally:\n'
                '    pass\n')
        elif variant == 1:
            source = (
                'try:\n'
                '    %(phantom)s = next((%(item)s for %(item)s in ()), None)\n'
                'except (TypeError, StopIteration):\n'
                '    %(phantom)s = None\n'
                'return %(phantom)s\n')
        else:
            source = (
                '%(phantom)s = ()\n'
                'for %(item)s in %(phantom)s:\n'
                '    if %(item)s is %(phantom)s:\n'
                '        return %(item)s\n'
                'else:\n'
                '    return None\n')
        body.extend(ast.parse(source % {
            'phantom': phantom, 'item': random_ident('item')}).body)
        return body

    def _transplant(self, public_name, hidden_name):
        if self.default_capsule:
            capsule_name = random_ident('capsule')
            carrier_name = random_ident('capsule_value')
            fields = [
                ('code', '%(hidden)s.func_code'),
                ('defaults', '%(hidden)s.func_defaults'),
                ('doc', '%(public)s.func_doc'),
            ]
            if self.role_variation:
                random.shuffle(fields)
            params = []
            returns = []
            indexes = {}
            field_names = {}
            for index, (role, expression) in enumerate(fields):
                field_name = random_ident(role)
                field_names[role] = field_name
                indexes[role] = index
                expression = expression % {
                    'hidden': hidden_name, 'public': public_name}
                params.append('%s=%s' % (field_name, expression))
                returns.append(field_name)
            capsule_source = (
                'def %(capsule)s(%(params)s):\n'
                '    return (%(returns)s)\n'
                '%(carrier)s = %(capsule)s()\n'
            ) % {
                'capsule': capsule_name, 'carrier': carrier_name,
                'params': ', '.join(params),
                'returns': ', '.join(returns) + ',',
                'hidden': hidden_name, 'public': public_name,
            }
            capsule_nodes = ast.parse(capsule_source).body
            for item in capsule_nodes:
                if isinstance(item, ast.FunctionDef):
                    item._mcp_source_synthetic = True
            tail_source = (
                '%(public)s.func_code = %(carrier)s[%(code_index)d]\n'
                '%(public)s.func_defaults = %(carrier)s[%(defaults_index)d]\n'
                'try:\n'
                '    %(public)s.func_doc = %(carrier)s[%(doc_index)d]\n'
                'except Exception:\n'
                '    pass\n'
                '%(carrier)s = None\n'
                'del %(capsule)s\n'
                'del %(hidden)s\n'
            ) % {'public': public_name, 'carrier': carrier_name,
                 'capsule': capsule_name, 'hidden': hidden_name,
                 'code_index': indexes['code'],
                 'defaults_index': indexes['defaults'],
                 'doc_index': indexes['doc']}
            return capsule_nodes + ast.parse(tail_source).body
        carrier = random_ident('carrier')
        left = random.randint(1, 255)
        right = random.randint(1, 255)
        code_slot = left ^ right
        defaults_slot = (left + right) & 255
        field_nodes = [
            ('code', ast.Attribute(value=ast.Name(id=hidden_name, ctx=ast.Load()),
                                   attr='func_code', ctx=ast.Load())),
            ('defaults', ast.Attribute(value=ast.Name(id=hidden_name, ctx=ast.Load()),
                                       attr='func_defaults', ctx=ast.Load())),
            ('doc', ast.Attribute(value=ast.Name(id=public_name, ctx=ast.Load()),
                                  attr='func_doc', ctx=ast.Load())),
        ]
        if self.role_variation:
            random.shuffle(field_nodes)
        field_indexes = dict((role, index) for index, (role, value) in enumerate(field_nodes))
        row = ast.Tuple(elts=[value for role, value in field_nodes], ctx=ast.Load())
        assign_carrier = ast.Assign(
            targets=[ast.Name(id=carrier, ctx=ast.Store())], value=row)
        set_code = ast.Assign(
            targets=[ast.Attribute(value=ast.Name(id=public_name, ctx=ast.Load()),
                                   attr='func_code', ctx=ast.Store())],
            value=ast.Subscript(value=ast.Name(id=carrier, ctx=ast.Load()),
                                slice=ast.Index(ast.Num(n=code_slot)),
                                ctx=ast.Load()))
        set_defaults = ast.Assign(
            targets=[ast.Attribute(value=ast.Name(id=public_name, ctx=ast.Load()),
                                   attr='func_defaults', ctx=ast.Store())],
            value=ast.Subscript(value=ast.Name(id=carrier, ctx=ast.Load()),
                                slice=ast.Index(ast.Num(n=defaults_slot)),
                                ctx=ast.Load()))
        # The two encoded indexes above are deliberately different expressions
        # but must address the two fixed carrier fields.  Normalize them in a
        # small tuple selector so the generated source stays valid for every
        # random pair.
        set_code.value.slice = ast.Index(ast.Num(n=field_indexes['code']))
        set_defaults.value.slice = ast.Index(ast.Num(n=field_indexes['defaults']))
        set_doc = ast.TryExcept(
            body=[ast.Assign(
                targets=[ast.Attribute(value=ast.Name(id=public_name, ctx=ast.Load()),
                                       attr='func_doc', ctx=ast.Store())],
                value=ast.Subscript(value=ast.Name(id=carrier, ctx=ast.Load()),
                                    slice=ast.Index(ast.Num(n=field_indexes['doc'])), ctx=ast.Load()))],
            handlers=[ast.ExceptHandler(type=None, name=None, body=[ast.Pass()])],
            orelse=[])
        clear_carrier = ast.Assign(
            targets=[ast.Name(id=carrier, ctx=ast.Store())],
            value=ast.Name(id='None', ctx=ast.Load()))
        return [assign_carrier, set_code, set_defaults, set_doc, clear_carrier,
                ast.Delete(targets=[ast.Name(id=hidden_name, ctx=ast.Del())])]

    def _body(self, body):
        out = []
        for node in body:
            if isinstance(node, ast.ClassDef):
                node.body = self._body(node.body)
                out.append(node)
                continue
            if not isinstance(node, ast.FunctionDef) or not self._eligible(node):
                out.append(node)
                continue
            hidden = copy.deepcopy(node)
            hidden.name = random_ident('code')
            hidden.decorator_list = []
            hidden._mcp_source_synthetic = True
            public = node
            public.decorator_list = []
            public.body = self._decoy_body(public)
            out.append(hidden)
            out.append(public)
            out.extend(self._transplant(public.name, hidden.name))
            self.count += 1
        return out

    def apply(self, tree):
        tree.body = self._body(tree.body)
        _ensure_locations(tree)
        ast.fix_missing_locations(tree)
        # ``fix_missing_locations`` in Python 2.7 does not descend through
        # every legacy ``Index``/``Subscript`` expression.  Run the explicit
        # pass again after fixing parents so all expression leaves carry
        # concrete coordinates before the target compiler validates the tree.
        _ensure_locations(tree)
        return tree, self.count


def weave_source_function_identities(tree, ratio=45, max_functions=12,
                                     default_capsule=False,
                                     role_variation=False):
    return SourceIdentityWeaver(
        ratio, max_functions, default_capsule, role_variation).apply(tree)


def inject_tuple_argument_decoys(tree, count=0):
    """Add dead Python-2 tuple-argument functions.

    Python 2's compiler lowers tuple argument unpacking into a hidden ``.0``
    local slot.  The decoys are defined and immediately deleted, so they add
    no call-path work and do not alter the public signatures of real APIs.
    """
    count = max(0, min(8, int(count or 0)))
    if count <= 0:
        return tree, 0
    statements = []
    for _ in range(count):
        fn = random_ident('tuple_shadow')
        left = random_ident('left')
        right = random_ident('right')
        seq = random_ident('seq')
        item = random_ident('item')
        mask = random.randint(1, 255)
        source = (
            'def %(fn)s((%(left)s, %(right)s), %(seq)s=None):\n'
            '    if %(seq)s is None:\n'
            '        %(seq)s = ()\n'
            '    try:\n'
            '        return tuple(((%(item)s ^ %(mask)d) for %(item)s in %(seq)s '\
            'if %(item)s != %(left)s and %(item)s != %(right)s))\n'
            '    finally:\n'
            '        pass\n'
        ) % {'fn': fn, 'left': left, 'right': right, 'seq': seq,
             'item': item, 'mask': mask}
        nodes = ast.parse(source).body
        for node in nodes:
            if isinstance(node, ast.FunctionDef):
                node._mcp_source_synthetic = True
        statements.extend(nodes)
        statements.append(ast.Delete(targets=[ast.Name(id=fn, ctx=ast.Del())]))
    insert_source_string_xor_helpers(tree, statements)
    ast.fix_missing_locations(tree)
    return tree, count


def make_source_decompiler_carrier(index=0, exception_lattice=True,
                                   class_body_trap=True,
                                   docstring_bytes=0):
    """Build one legal Python-2 carrier containing recursively nested traps.

    Only the outer carrier function object is created during module startup.
    Its nested tuple-argument, generator, exception and class-body code objects
    remain in ``co_consts`` for recursive decompilers, but are never executed.
    """
    carrier = random_ident('carrier_%d' % index)
    outer_left = random_ident('outer_left')
    outer_mid = random_ident('outer_mid')
    outer_right = random_ident('outer_right')
    seed = random_ident('seed')
    tuple_trap = random_ident('tuple_gate')
    tuple_left = random_ident('tuple_left')
    tuple_mid = random_ident('tuple_mid')
    tuple_right = random_ident('tuple_right')
    values = random_ident('values')
    item = random_ident('item')
    error = random_ident('error')
    generator_trap = random_ident('generator_gate')
    generator_values = random_ident('generator_values')
    generator_item = random_ident('generator_item')
    docstring_bytes = max(0, min(16384, int(docstring_bytes or 0)))
    blob = ''.join(byte_char(random.randrange(0, 256))
                   for _ in range(docstring_bytes))
    parts = [
        'def %(carrier)s((%(outer_left)s, (%(outer_mid)s, %(outer_right)s)), %(seed)s=None):',
    ]
    if blob:
        parts.append('    %(carrier_docstring)s')
    parts.extend([
        '    def %(tuple_trap)s((%(tuple_left)s, (%(tuple_mid)s, %(tuple_right)s)), %(values)s=()):',
        '        try:',
        '            try:',
        '                return tuple((`%(item)s`, %(item)s, %(tuple_left)s, %(tuple_mid)s, %(tuple_right)s) for %(item)s in %(values)s if %(item)s is not %(seed)s)',
        '            except (TypeError, ValueError), %(error)s:',
        '                return (`%(error)s`,)',
        '            else:',
        '                return ()',
        '        finally:',
        '            %(values)s = ()',
        '',
        '    def %(generator_trap)s(%(generator_values)s):',
        '        try:',
        '            for %(generator_item)s in %(generator_values)s:',
        '                yield (`%(generator_item)s`, %(generator_item)s)',
        '        finally:',
        '            %(generator_values)s = ()',
        '',
    ])
    names = {
        'carrier': carrier, 'outer_left': outer_left, 'outer_mid': outer_mid,
        'outer_right': outer_right, 'seed': seed, 'tuple_trap': tuple_trap,
        'tuple_left': tuple_left, 'tuple_mid': tuple_mid,
        'tuple_right': tuple_right, 'values': values, 'item': item,
        'error': error, 'generator_trap': generator_trap,
        'generator_values': generator_values,
        'generator_item': generator_item,
        'carrier_docstring': repr(blob),
    }
    retained = [tuple_trap, generator_trap]
    if exception_lattice:
        lattice = random_ident('exception_lattice')
        flag = random_ident('flag')
        state = random_ident('state')
        lattice_error = random_ident('lattice_error')
        names.update({'lattice': lattice, 'flag': flag, 'state': state,
                      'lattice_error': lattice_error})
        parts.extend([
            '    def %(lattice)s(%(flag)s):',
            '        %(state)s = 0',
            '        while %(state)s < 3:',
            '            try:',
            '                try:',
            '                    if %(flag)s is None:',
            '                        break',
            '                    if %(state)s:',
            '                        return `%(flag)s`',
            '                    %(state)s += 1',
            '                    continue',
            '                except (TypeError, ValueError), %(lattice_error)s:',
            '                    %(flag)s = %(lattice_error)s',
            '                else:',
            '                    %(flag)s = %(state)s',
            '                finally:',
            '                    %(state)s ^= 1',
            '            finally:',
            '                %(flag)s = %(flag)s',
            '        return %(flag)s',
            '',
        ])
        retained.append(lattice)
    if class_body_trap:
        shell = random_ident('shell')
        shell_method = random_ident('relay')
        shell_alias = random_ident('relay_alias')
        shell_self = random_ident('shell_self')
        shell_left = random_ident('shell_left')
        shell_right = random_ident('shell_right')
        shell_values = random_ident('shell_values')
        shell_item = random_ident('shell_item')
        inner = random_ident('inner_shell')
        inner_method = random_ident('inner_relay')
        names.update({
            'shell': shell, 'shell_method': shell_method,
            'shell_alias': shell_alias, 'shell_self': shell_self,
            'shell_left': shell_left, 'shell_right': shell_right,
            'shell_values': shell_values, 'shell_item': shell_item,
            'inner': inner, 'inner_method': inner_method,
        })
        parts.extend([
            '    class %(shell)s(object):',
            '        def %(shell_method)s(%(shell_self)s, (%(shell_left)s, %(shell_right)s), %(shell_values)s=()):',
            '            return tuple((%(shell_item)s for %(shell_item)s in %(shell_values)s if %(shell_item)s != %(shell_left)s and %(shell_item)s != %(shell_right)s))',
            '        %(shell_alias)s = %(shell_method)s',
            '        del %(shell_method)s',
            '        class %(inner)s:',
            '            def %(inner_method)s(%(shell_self)s, (%(shell_left)s, (%(outer_mid)s, %(shell_right)s))):',
            '                return (`%(shell_left)s`, `%(outer_mid)s`, `%(shell_right)s`)',
            '',
        ])
        retained.append(shell)
    names['retained'] = ', '.join(retained) + ','
    parts.append('    return (%(retained)s %(outer_left)s, %(outer_mid)s, %(outer_right)s, %(seed)s)')
    parts.append('del %(carrier)s')
    source = '\n'.join(parts) % names
    nodes = ast.parse(source).body
    for node in nodes:
        if isinstance(node, ast.FunctionDef):
            node._mcp_source_synthetic = True
    return nodes


def make_runtime_type_table_carrier(index=0):
    """Build a cold Python-2 runtime-type table carrier.

    The sample's useful idea is deriving implementation types from ordinary
    objects instead of importing their names.  Keep it in an uncalled nested
    function: it contributes descriptor, code and generator-frame shapes to
    the emitted module without probing the game runtime at import time.
    """
    carrier = random_ident('type_table_%d' % index)
    none_type = random_ident('none_type')
    meta_type = random_ident('meta_type')
    hash_type = random_ident('hash_type')
    new_type = random_ident('new_type')
    hash_owner_type = random_ident('hash_owner_type')
    new_owner_type = random_ident('new_owner_type')
    code_type = random_ident('code_type')
    generator_type = random_ident('generator_type')
    frame_type = random_ident('frame_type')
    generator_fn = random_ident('generator_fn')
    generator = random_ident('generator')
    descriptor_class = random_ident('descriptor_class')
    descriptor_method = random_ident('descriptor_method')
    rows = random_ident('type_rows')
    seed_name = random_ident('type_seed')
    blob_name = random_ident('type_blob')
    seed = random.randint(0x10000, 0x7fffffff)
    blob = ''.join(byte_char(random.randrange(0, 256))
                   for _ in range(random.randint(20, 56)))
    source = (
        'def %(carrier)s(%(seed_name)s=%(seed)d, %(blob_name)s=%(blob)r):\n'
        '    %(none_type)s = None.__new__.__self__\n'
        '    %(meta_type)s = None.__hash__.__objclass__.__class__\n'
        '    %(hash_type)s = type(None.__hash__)\n'
        '    %(new_type)s = type(None.__new__)\n'
        '    %(hash_owner_type)s = None.__hash__.__class__\n'
        '    %(new_owner_type)s = None.__new__.__class__\n'
        '    def %(generator_fn)s():\n'
        '        yield %(seed)d\n'
        '    %(generator)s = %(generator_fn)s()\n'
        '    %(generator_type)s = type(%(generator)s)\n'
        '    %(frame_type)s = type(%(generator)s.gi_frame)\n'
        '    %(code_type)s = type(%(generator_fn)s.func_code)\n'
        '    %(generator)s.close()\n'
        '    class %(descriptor_class)s(object):\n'
        '        %(rows)s = (%(none_type)s, %(meta_type)s, %(hash_type)s, %(new_type)s, %(hash_owner_type)s, %(new_owner_type)s, %(code_type)s, %(generator_type)s, %(frame_type)s)\n'
        '        def %(descriptor_method)s(self, %(blob_name)s=None):\n'
        '            return self.%(rows)s if %(blob_name)s is None else (%(blob_name)s, self.%(rows)s)\n'
        '    return (%(descriptor_class)s, %(generator_fn)s, %(seed)d)\n'
        'del %(carrier)s'
    ) % {
        'carrier': carrier, 'none_type': none_type, 'meta_type': meta_type,
        'hash_type': hash_type, 'new_type': new_type,
        'hash_owner_type': hash_owner_type, 'new_owner_type': new_owner_type,
        'code_type': code_type,
        'generator_type': generator_type, 'frame_type': frame_type,
        'generator_fn': generator_fn, 'generator': generator,
        'descriptor_class': descriptor_class,
        'descriptor_method': descriptor_method, 'rows': rows,
        'seed': seed, 'seed_name': seed_name, 'blob': blob,
        'blob_name': blob_name,
    }
    nodes = ast.parse(source).body
    for node in nodes:
        if isinstance(node, ast.FunctionDef):
            node._mcp_source_synthetic = True
    return nodes


def inject_source_decompiler_carriers(tree, count=0, exception_lattice=True,
                                      class_body_trap=True,
                                      docstrings=False,
                                      docstring_min=1024,
                                      docstring_max=4096):
    count = max(0, min(4, int(count or 0)))
    if count <= 0:
        return tree, 0
    statements = []
    docstring_min = max(64, min(16384, int(docstring_min or 64)))
    docstring_max = max(
        docstring_min, min(16384, int(docstring_max or docstring_min)))
    for index in range(count):
        size = (random.randint(docstring_min, docstring_max)
                if docstrings else 0)
        statements.extend(make_source_decompiler_carrier(
            index, exception_lattice, class_body_trap, size))
        statements.extend(make_runtime_type_table_carrier(index))
    insert_source_string_xor_helpers(tree, statements)
    ast.fix_missing_locations(tree)
    return tree, count\n