# -*- coding: utf-8 -*-
"""Import facades, code capsules and loader cleanup components."""


import base64
import pickle
import random

from MCP_Armor_Src.core.constants import (
    CODE_TUPLE_MAGIC,
)

from MCP_Armor_Src.loaders.code_tuple import (
    pack_code_tuple,
)

from MCP_Armor_Src.utils.encoding import (
    random_bytes,
    debug_print_code,
    random_ident,
)


def build_outer_decompiler_bait_code(count, taunt_text, budget_bytes=8192):
    """Build bounded cold code-object baits for Python-2 decompilers.

    The generated functions are only defined and referenced by a holder tuple;
    none of their bodies run while the protected module is imported.  Several
    source shapes are rotated so one fixed template is not emitted in every
    artifact.  ``budget_bytes`` is a hard cap on the generated source text,
    including the final holder.
    """
    count = max(0, min(4, int(count or 0)))
    budget_bytes = max(0, min(65536, int(budget_bytes or 0)))
    if count <= 0 or budget_bytes <= 0:
        return ''
    lines = []
    refs = []
    marker = taunt_text or 'ShitArmor_DEOBF'
    # Leave enough room for the randomized holder assignment.  This makes the
    # configured limit deterministic even though repr(binary_blob) expands by
    # a variable amount.
    holder_reserve = 192
    for bait_index in range(count):
        fn = random_ident('odb')
        left = random_ident('odl')
        middle = random_ident('odm')
        right = random_ident('odr')
        seed = random_ident('ods')
        nested = random_ident('odn')
        pair_left = random_ident('opl')
        pair_right = random_ident('opr')
        rows = random_ident('odw')
        item = random_ident('odi')
        state = random_ident('odt')
        error = random_ident('ode')
        shell = random_ident('odc')
        relay = random_ident('odq')
        self_name = random_ident('odo')
        values = random_ident('odv')
        value = random_ident('odx')
        guard = random.randint(0x10000, 0x7fffffff)
        impossible = guard ^ 0x5A5A5A5A
        blob = random_bytes(random.randint(32, 80))
        fields = {
            'fn': fn, 'left': left, 'middle': middle, 'right': right,
            'seed': seed, 'guard': guard, 'nested': nested,
            'pair_left': pair_left, 'pair_right': pair_right, 'rows': rows,
            'item': item, 'state': state, 'error': error, 'shell': shell,
            'relay': relay, 'self_name': self_name, 'values': values,
            'value': value, 'impossible': impossible, 'marker': marker,
            'blob': blob,
        }
        variant = random.randrange(3)
        if variant == 0:
            source = (
                'def %(fn)s((%(left)s, (%(middle)s, %(right)s)), %(seed)s=%(guard)d):\n'
                '    def %(nested)s((%(pair_left)s, %(pair_right)s), %(rows)s=()):\n'
                '        %(state)s = %(seed)s ^ %(guard)d\n'
                '        try:\n'
                '            for %(item)s in %(rows)s:\n'
                '                %(state)s = ((%(state)s << 5) ^ %(item)s ^ (%(state)s >> 2)) & 0x7fffffff\n'
                '            return (%(state)s, %(pair_left)s, %(pair_right)s)\n'
                '        except (TypeError, ValueError), %(error)s:\n'
                '            return (%(error)s, %(state)s)\n'
                '        finally:\n'
                '            %(rows)s = ()\n'
                '    class %(shell)s(object):\n'
                '        def %(relay)s(%(self_name)s, (%(pair_left)s, %(pair_right)s), %(values)s=()):\n'
                '            return tuple((%(value)s for %(value)s in %(values)s if %(value)s != %(pair_left)s and %(value)s != %(pair_right)s))\n'
                '    if %(seed)s == %(impossible)d:\n'
                '        return %(nested)s((%(left)s, %(right)s), (%(middle)s,))\n'
                '    return (%(nested)s, %(shell)s, %(marker)r, %(blob)r)\n'
            ) % fields
        elif variant == 1:
            source = (
                'def %(fn)s((%(left)s, (%(middle)s, %(right)s)), %(seed)s=%(guard)d):\n'
                '    def %(nested)s((%(pair_left)s, %(pair_right)s), %(rows)s=()):\n'
                '        try:\n'
                '            return tuple((`%(item)s`, %(item)s ^ %(seed)s) for %(item)s in %(rows)s if %(item)s not in (%(pair_left)s, %(pair_right)s))\n'
                '        except (IndexError, TypeError), %(error)s:\n'
                '            return (%(error)s, %(pair_left)s, %(pair_right)s)\n'
                '        finally:\n'
                '            %(rows)s = ()\n'
                '    def %(relay)s(%(values)s=()):\n'
                '        return ((%(value)s, %(value)s ^ %(guard)d) for %(value)s in %(values)s)\n'
                '    if %(seed)s == %(impossible)d:\n'
                '        return list(%(relay)s(%(nested)s((%(left)s, %(right)s), (%(middle)s,))))\n'
                '    return (%(nested)s, %(relay)s, %(marker)r, %(blob)r)\n'
            ) % fields
        else:
            source = (
                'def %(fn)s((%(left)s, (%(middle)s, %(right)s)), %(seed)s=%(guard)d):\n'
                '    class %(shell)s(object):\n'
                '        def %(relay)s(%(self_name)s, (%(pair_left)s, %(pair_right)s), %(values)s=()):\n'
                '            try:\n'
                '                return dict((%(value)s, (%(value)s ^ %(seed)s)) for %(value)s in %(values)s)\n'
                '            except (TypeError, ValueError), %(error)s:\n'
                '                return {%(pair_left)s: %(error)s, %(pair_right)s: %(values)s}\n'
                '            finally:\n'
                '                %(values)s = ()\n'
                '    def %(nested)s(%(rows)s=()):\n'
                '        return tuple((lambda %(item)s: %(item)s ^ %(guard)d)(%(item)s) for %(item)s in %(rows)s)\n'
                '    if %(seed)s == %(impossible)d:\n'
                '        return %(shell)s().%(relay)s((%(left)s, %(right)s), (%(middle)s,))\n'
                '    return (%(shell)s, %(nested)s, %(marker)r, %(blob)r)\n'
            ) % fields
        candidate = '\n'.join(lines + [source])
        if len(candidate) + holder_reserve > budget_bytes:
            break
        lines.append(source)
        refs.append(fn)
    if not refs:
        return ''
    holder = random_ident('odh')
    holder_source = '%s = (%s)\n' % (
        holder, ', '.join(refs) + (',' if len(refs) == 1 else ''))
    result = '\n'.join(lines + [holder_source])
    # The reserve above is deliberately conservative; retain a final hard
    # assertion so future template edits cannot silently defeat the governor.
    if len(result) > budget_bytes:
        return ''
    return result


def build_loader_decoy_tuple_code(count, taunt_text, names, import_codes):
    count = max(0, min(12, count))
    if count <= 0:
        return ''
    lines = []
    refs = []
    for idx in range(count):
        func_name = random_ident('ldt')
        raw_name = random_ident('ldr')
        guard_name = random_ident('ldg')
        b64_name = random_ident('ldb')
        pickle_name = random_ident('ldp')
        types_name = random_ident('ldt')
        tuple_name = random_ident('ldt')
        marker = taunt_text or 'loader-decoy-tuple'
        fake_arg_name = random_ident('fda')
        fake_marker_name = random_ident('fdm')
        fake_value_name = random_ident('fdv')
        fake_source = (
            'def %s(%s=None):\n'
            '    %s = %r\n'
            '    %s = %d\n'
            '    if %s < 0:\n'
            '        return %s\n'
            '    return %s\n'
        ) % (random_ident('fd'), fake_arg_name, fake_marker_name, marker,
             fake_value_name, random.randint(10000, 999999),
             fake_value_name, fake_marker_name, fake_arg_name)
        fake_code = compile(fake_source, '<loader-decoy>', 'exec', 0, True)
        fake_blob = base64.b64encode(CODE_TUPLE_MAGIC + pickle.dumps(pack_code_tuple(fake_code), 2))
        guard = random.randint(10000, 999999)
        lines.append('def %s(%s=%r):\n    %s = %d\n    if %s == -1:\n        %s = %s(%s)\n        %s = %s(%s)\n        %s = %s(%s)\n        %s = getattr(%s, %s(%s))(%s)\n        if isinstance(%s, str) and getattr(%s, %s(%s))(%r):\n            %s = getattr(%s, %s(%s))(%s[%d:])\n            return getattr(%s, %s(%s))(*%s)\n    return %s\n' % (
            func_name, raw_name, fake_blob,
            guard_name, guard, guard_name,
            b64_name, names['import_name'], import_codes['b64_code'],
            pickle_name, names['import_name'], import_codes['pickle_code'],
            types_name, names['import_name'], import_codes['types_code'],
            tuple_name, b64_name, names['str_name'],
            import_codes['b64decode_code'], raw_name,
            tuple_name, tuple_name, names['str_name'],
            import_codes['startswith_code'], CODE_TUPLE_MAGIC,
            tuple_name, pickle_name, names['str_name'],
            import_codes['loads_code'], tuple_name, len(CODE_TUPLE_MAGIC),
            types_name, names['str_name'], import_codes['codetype_code'],
            tuple_name,
            raw_name,
        ))
        refs.append(func_name)
    holder = random_ident('ldh')
    lines.append('%s = (%s)\n' % (holder, ', '.join(refs) + (',' if len(refs) == 1 else '')))
    return '\n'.join(lines)


def build_import_facade_parts(names, enabled, registry_protection,
                              fake_module_code, random_code):
    if not enabled:
        return {
            'facade_top_code': '',
            'facade_cached_code': '',
            'facade_exec_pre_code': '',
            'exec_globals_expr': 'globals()',
            'facade_exec_post_code': '',
        }
    fake_module_name = random_ident('ifm')
    module_name = names['facade_module_name']
    flag_name = names['facade_flag_name']
    seed_name = names['facade_seed_name']
    sys_name = names['facade_sys_name']
    dict_name = names['facade_dict_name']
    key_name = names['facade_key_name']
    value_name = names['facade_value_name']
    top_code = (
        'try:\n'
        '    %s = %s(%s)\n'
        '    %s = True\n'
        'except ImportError:\n'
        '    %s = %s(%s)\n'
        '    %s = %s.__class__(%r)\n'
        '    %s.__dict__.update(globals())\n'
        '    %s.__builtins__ = __builtins__\n'
        '    %s.__name__ = globals().get(\'__name__\', %r)\n'
        '    %s.__package__ = globals().get(\'__package__\', None)\n'
        '    %s = False\n'
    ) % (
        module_name, names['import_name'], fake_module_code,
        flag_name,
        seed_name, names['import_name'], random_code,
        module_name, seed_name, fake_module_name,
        module_name,
        module_name,
        module_name, fake_module_name,
        module_name,
        flag_name,
    )
    registry_top_code = ''
    registry_pre_code = ''
    if registry_protection:
        registry_class_name = names['facade_registry_class_name']
        registry_name = names['facade_registry_name']
        registry_map_name = names['facade_registry_map_name']
        registry_key_name = names['facade_registry_key_name']
        registry_value_name = names['facade_registry_value_name']
        registry_self_name = random_ident('frs')
        registry_storage_name = random_ident('frm')
        registry_init_name = random_ident('fri')
        registry_get_name = random_ident('frg')
        registry_item_name = random_ident('frx')
        registry_contains_name = random_ident('frc')
        registry_class_label = random_ident('frl')
        registry_top_code = (
            '\ndef %s(%s, %s):\n'
            '    %s.%s = %s\n'
            'def %s(%s, %s, %s=None):\n'
            '    return %s.%s.get(%s, %s)\n'
            'def %s(%s, %s):\n'
            '    return %s.%s[%s]\n'
            'def %s(%s, %s):\n'
            '    return %s in %s.%s\n'
            '%s = type(%r, (object,), {\n'
            "    '__init__': %s, 'get': %s,\n"
            "    '__getitem__': %s, '__contains__': %s})\n"
        ) % (registry_init_name, registry_self_name, registry_map_name,
             registry_self_name, registry_storage_name, registry_map_name,
             registry_get_name, registry_self_name,
             registry_key_name, registry_value_name,
             registry_self_name, registry_storage_name,
             registry_key_name, registry_value_name,
             registry_item_name, registry_self_name, registry_key_name,
             registry_self_name, registry_storage_name, registry_key_name,
             registry_contains_name, registry_self_name, registry_key_name,
             registry_key_name, registry_self_name, registry_storage_name,
             registry_class_name, registry_class_label,
             registry_init_name, registry_get_name,
             registry_item_name, registry_contains_name)
        top_code += registry_top_code
    def export_loop(indent):
        pad = ' ' * indent
        return (
            '%sfor %s, %s in %s.__dict__.items():\n'
            '%s    if %s not in (\'__builtins__\', \'__name__\', \'__package__\', \'__loader__\', \'__spec__\'):\n'
            '%s        globals()[%s] = %s'
        ) % (pad, key_name, value_name, module_name, pad, key_name, pad, key_name, value_name)
    cached_code = (
        '    if %s:\n'
        '%s\n'
        '        return %s'
    ) % (flag_name, export_loop(8), module_name)
    if registry_protection:
        pre_code = (
            '    %s = %s(%s)\n'
            '    %s = %s({%r: %s})\n'
            '    getattr(%s, %s(%s))[%r] = %s.get(%r)\n'
            '    %s = %s.__dict__\n'
            '    %s.update(globals())\n'
            '    %s[\'__builtins__\'] = __builtins__\n'
            '    %s[\'__name__\'] = globals().get(\'__name__\', %r)\n'
            '    %s[\'__package__\'] = globals().get(\'__package__\', None)'
        ) % (
            sys_name, names['import_name'], names['sys_code'],
            names['facade_registry_name'], names['facade_registry_class_name'],
            fake_module_name, module_name,
            sys_name, names['str_name'], names['modules_code'],
            fake_module_name, names['facade_registry_name'], fake_module_name,
            dict_name, module_name,
            dict_name,
            dict_name,
            dict_name, fake_module_name,
            dict_name,
        )
    else:
        pre_code = (
            '    %s = %s(%s)\n'
            '    getattr(%s, %s(%s))[%r] = %s\n'
            '    %s = %s.__dict__\n'
            '    %s.update(globals())\n'
            '    %s[\'__builtins__\'] = __builtins__\n'
            '    %s[\'__name__\'] = globals().get(\'__name__\', %r)\n'
            '    %s[\'__package__\'] = globals().get(\'__package__\', None)'
        ) % (
            sys_name, names['import_name'], names['sys_code'],
            sys_name, names['str_name'], names['modules_code'],
            fake_module_name, module_name,
            dict_name, module_name,
            dict_name,
            dict_name,
            dict_name, fake_module_name,
            dict_name,
        )
    post_code = export_loop(4)
    return {
        'facade_top_code': top_code,
        'facade_cached_code': cached_code,
        'facade_exec_pre_code': pre_code,
        'exec_globals_expr': dict_name,
        'facade_exec_post_code': post_code,
    }


def build_code_capsule_parts(names, enabled=False, protocol_guard=False, debug=False):
    if not enabled:
        return {
            'capsule_top_code': '',
            'capsule_invoke_code': '    %s = %s()' % (
                names['func_result_name'], names['module_func_name']),
        }

    class_name = random_ident('ccp')
    factory_name = random_ident('ccf')
    invoke_name = random_ident('cci')
    getattr_name = random_ident('ccg')
    reduce_name = random_ident('ccr')
    reduce_ex_name = random_ident('ccx')
    copy_name = random_ident('ccc')
    deepcopy_name = random_ident('ccd')
    repr_name = random_ident('ccp')
    args_name = random_ident('cca')
    kwargs_name = random_ident('ccw')
    self_name = random_ident('cco')
    attr_name = random_ident('ccn')
    memo_name = random_ident('ccm')
    proto_name = random_ident('ccv')
    target_name = random_ident('ccu')
    class_label = random_ident('CodeCapsule')
    repr_label = '<%s sealed>' % random_ident('capsule')
    decoy_key = random_ident('sealed')
    decoy_value = random.randint(0x10000, 0x7fffffff)

    debug_call = ''
    if debug:
        debug_call = "    print('[DEBUG] MCP CodeCapsule Invoke Loaded')\n"

    lines = [
        'def %s(%s):' % (factory_name, target_name),
        '    def %s(%s, *%s, **%s):' % (invoke_name, self_name, args_name, kwargs_name),
        ('    ' + debug_call.rstrip('\n')) if debug_call else '',
        '        return %s(*%s, **%s)' % (target_name, args_name, kwargs_name),
    ]
    if not debug_call:
        del lines[2]

    if protocol_guard:
        lines.extend([
            '    def %s(%s, %s):' % (getattr_name, self_name, attr_name),
            '        if %s == %r:' % (attr_name, '__dict__'),
            '            return {%r: %d}' % (decoy_key, decoy_value),
            '        return object.__getattribute__(%s, %s)' % (self_name, attr_name),
            '    def %s(%s):' % (reduce_name, self_name),
            '        return (%s, (None,))' % factory_name,
            '    def %s(%s, %s):' % (reduce_ex_name, self_name, proto_name),
            '        return %s(%s)' % (reduce_name, self_name),
            '    def %s(%s):' % (copy_name, self_name),
            '        return %s' % self_name,
            '    def %s(%s, %s):' % (deepcopy_name, self_name, memo_name),
            '        try:',
            '            %s[id(%s)] = %s' % (memo_name, self_name, self_name),
            '        except Exception:',
            '            pass',
            '        return %s' % self_name,
            '    def %s(%s):' % (repr_name, self_name),
            '        return %r' % repr_label,
        ])

    fields = ["'__call__': %s" % invoke_name]
    if protocol_guard:
        fields.extend([
            "'__getattribute__': %s" % getattr_name,
            "'__reduce__': %s" % reduce_name,
            "'__reduce_ex__': %s" % reduce_ex_name,
            "'__copy__': %s" % copy_name,
            "'__deepcopy__': %s" % deepcopy_name,
            "'__repr__': %s" % repr_name,
        ])
    lines.extend([
        '    %s = type(%r, (object,), {%s})' % (class_name, class_label, ', '.join(fields)),
        '    return %s()' % class_name,
    ])

    capsule_name = random_ident('cco')
    invoke_lines = [
        '    %s = %s(%s)' % (
            capsule_name, factory_name, names['module_func_name']),
        '    %s = %s()' % (names['func_result_name'], capsule_name),
    ]
    if debug:
        invoke_lines.insert(1, debug_print_code(True, 'MCP CodeCapsule Sealed', 4))
    return {
        'capsule_top_code': '\n'.join(lines),
        'capsule_invoke_code': '\n'.join(invoke_lines),
    }


def build_loader_cleanup_code(names, enabled=False, debug=False):
    if not enabled:
        return ''
    lines = []
    if debug:
        lines.append(debug_print_code(True, 'MCP Loader ReferenceCleanupBegin', 4))
    for table_name in (
            'payload_name', 'key_name', 'decoy_table_name',
            'opcode_table_name', 'fake_mcs_table_name'):
        lines.extend([
            '    try:',
            '        %s[:] = []' % names[table_name],
            '    except Exception:',
            '        pass',
        ])
    for local_name in (
            'raw_name', 'data_arg', 'payload_join_name', 'key_arg', 'mask_name',
            'code_arg', 'func_type_name', 'pickle_name', 'types_name',
            'opcode_map_name', 'counter_name'):
        lines.append('    %s = None' % names[local_name])
    if debug:
        lines.append(debug_print_code(True, 'MCP Loader ReferenceCleanupComplete', 4))
    return '\n'.join(lines)
