# -*- coding: utf-8 -*-
"""Small generated-loader source builders and decoy tables."""


import random

from MCP_Armor_Src.utils.encoding import (
    random_ident,
    visual_int,
)


def build_loader_noise(count):
    parts = []
    for _ in range(max(0, count)):
        fn = random_ident('lj')
        arg = random_ident('la')
        a = random_ident('lv')
        b = random_ident('lv')
        c = random_ident('lv')
        seed = random.randint(1000, 999999)
        seed_expr = visual_int(seed)
        byte_mask_expr = visual_int(255)
        word_mask_expr = visual_int(65535)
        negative_expr = visual_int(-1)
        parts.append('def %s(%s=None):\n'
                     '    try:\n'
                     '        %s = %s\n'
                     '        %s = (%s ^ (%s & %s)) & %s\n'
                     '        if %s == %s:\n'
                     '            return %r\n'
                     '        else:\n'
                     '            %s = (%s, %s, %r)\n'
                     '    except Exception:\n'
                     '        %s = None\n'
                     '    return %s\n' % (
                         fn, arg, a, seed_expr, b, a, a,
                         byte_mask_expr, word_mask_expr, b, negative_expr,
                         '???????????', c, a, b, 'not-called', c, c))
    return '\n'.join(parts)


def rows_repr_any(rows):
    lines = []
    for row in rows:
        lines.append('    %r,' % (row,))
    return '\n'.join(lines)


def py_string_literal(value):
    if value is None:
        value = ''
    if isinstance(value, str):
        raw = value.encode('utf-8')
    else:
        raw = str(value)
    return repr(raw)


def build_taunt_reference_chain(text, count):
    count = max(0, min(128, count))
    if not text or count <= 0:
        return ''
    lines = []
    previous = py_string_literal(text)
    for idx in range(count):
        name = random_ident('tf')
        local = random_ident('tm')
        guard_name = random_ident('guard')
        guard = random.randint(10000, 999999)
        if idx % 3 == 0:
            lines.append('def %s(%s=%s):\n    %s = %d\n    if %s < 0:\n        return %s\n    return %s\n' % (name, local, previous, guard_name, guard, guard_name, local, local))
        elif idx % 3 == 1:
            lines.append('def %s(%s=%s):\n    try:\n        %s = (%d & 7)\n    except Exception:\n        return %s\n    return %s\n' % (name, local, previous, guard_name, guard, local, local))
        else:
            lines.append('def %s(%s=%s):\n    if (%d ^ %d):\n        return %s\n    return %s\n' % (name, local, previous, guard, guard, local, local))
        previous = name + '()'
    holder = random_ident('th')
    lines.append('%s = (%s,)\n' % (holder, previous))
    return '\n'.join(lines)


def build_fake_reference_chain(count, taunt_text=None, taunt_outer_refs=0):
    count = max(0, min(24, count))
    if count <= 0:
        return build_taunt_reference_chain(taunt_text, taunt_outer_refs)
    names = [random_ident('rf') for _ in range(count)]
    lines = []
    prev = 'None'
    for name in names:
        val = random.randint(1000, 999999)
        arg_name = random_ident('arg')
        value_name = random_ident('value')
        lines.append('def %s(%s=None):\n    %s = %d\n    if %s == -1:\n        return %s\n    return %s\n' % (name, arg_name, value_name, val, value_name, prev, prev))
        prev = name
    root = random_ident('rr')
    refs = ', '.join(names)
    lines.append('%s = (%s)\n' % (root, refs + (',' if len(names) == 1 else '')))
    taunt_code = build_taunt_reference_chain(taunt_text, taunt_outer_refs)
    if taunt_code:
        lines.append(taunt_code)
    return '\n'.join(lines)


def build_api_decoy_chain(count, taunt_text=None):
    count = max(0, min(256, count))
    if count <= 0:
        return ''
    apis = ['extraServerApi', 'extraClientApi', 'RegisterSystem', 'ListenForEvent', 'UnListenForEvent', 'NotifyToServer', 'NotifyToClient', 'CreateEngineEntity', 'GetLocalPlayerId', 'GetEngineCompFactory']
    lines = []
    for idx in range(count):
        name = random_ident('api')
        arg_name = random_ident('arg')
        api_var = random_ident('api')
        marker_var = random_ident('mark')
        guard_var = random_ident('guard')
        api_name = random.choice(apis)
        marker = taunt_text or 'api-decoy'
        guard = random.randint(10000, 999999)
        lines.append('def %s(%s=None):\n    %s = %r\n    %s = %r\n    %s = %d\n    if %s == -1:\n        return getattr(%s, %s, %s)\n    return %s\n' % (
            name, arg_name, api_var, api_name, marker_var, marker,
            guard_var, guard, guard_var, arg_name, api_var, marker_var,
            api_var))
    holder = random_ident('ah')
    lines.append('%s = (%s)\n' % (holder, ', '.join([random.choice(apis).__repr__() for _ in range(min(count, 32))]) + ','))
    return '\n'.join(lines)


def build_restore_noise(level):
    level = max(0, min(32, level))
    if level <= 0:
        return 'pass'
    parts = []
    for idx in range(level):
        var = random_ident('rn')
        val = random.randint(10000, 999999)
        if idx % 3 == 0:
            parts.append('%s = %d\n    if %s == -1:\n        return None' % (var, val, var))
        elif idx % 3 == 1:
            parts.append('try:\n        %s = (%d & 255)\n    except Exception:\n        %s = 0' % (var, val, var))
        else:
            parts.append('%s = (%d ^ %d)' % (var, val, val))
    return '\n    '.join(parts)


def build_trampoline_layers(count):
    count = max(0, min(8, count))
    entry = random_ident('tr')
    funcs = []
    leaf = random_ident('tr')
    arg_ft = random_ident('ft')
    arg_co = random_ident('co')
    arg_gl = random_ident('gl')
    local_v = random_ident('value')
    funcs.append('def %s(%s, %s, %s):\n    return %s(%s, %s)\n' % (
        leaf, arg_ft, arg_co, arg_gl, arg_ft, arg_co, arg_gl))
    prev = leaf
    for _ in range(count):
        name = random_ident('tr')
        guard = random.randint(1000, 999999)
        # opaque always-true predicate: v*v+v is always even
        funcs.append('def %s(%s, %s, %s):\n    %s = %d\n    if (%s * %s + %s) %% 2 == 0:\n        return %s(%s, %s, %s)\n    return None\n' % (
            name, arg_ft, arg_co, arg_gl, local_v, guard, local_v, local_v,
            local_v, prev, arg_ft, arg_co, arg_gl))
        prev = name
    funcs.append('%s = %s\n' % (entry, prev))
    return '\n'.join(funcs), entry


def build_executable_decoys(count):
    """Decoy functions that are actually invoked by the flattened run().

    Unlike the cold baits, these are called (their results fold into a junk
    accumulator), and their branches use opaque always-true predicates rather
    than an obvious ``if x == -1`` guard.
    """
    count = max(0, min(16, count))
    if count <= 0:
        return '', None
    lines = []
    names = []
    for _ in range(count):
        fn = random_ident('xd')
        arg = random_ident('xa')
        a = random_ident('xv')
        b = random_ident('xv')
        c = random_ident('xv')
        seed = random.randint(0x10000, 0x7fffffff)
        mul = random.choice((1103515245, 214013, 1664525, 22695477))
        inc = random.choice((12345, 2531011, 1013904223, 1))
        variant = random.randrange(3)
        if variant == 0:
            body = ('def %s(%s=None):\n'
                    '    %s = %d\n'
                    '    %s = (%s * %d + %d) & 0x7fffffff\n'
                    '    if (%s * %s + %s) %% 2 == 0:\n'
                    '        return (%s ^ (%s & 255)) & 0x7fffffff\n'
                    '    return %s\n') % (
                        fn, arg, a, seed, b, a, mul, inc, a, a, a,
                        b, arg, b)
        elif variant == 1:
            body = ('def %s(%s=None):\n'
                    '    %s = (%d ^ %d)\n'
                    '    %s = (%s << 1) & 0x7ffffffe\n'
                    '    if ((%s * %s - %s) & 1) == 0:\n'
                    '        return (%s + %s + (%s & 255)) & 0x7fffffff\n'
                    '    return %s\n') % (
                        fn, arg, a, seed, mul, b, a, a, a, a,
                        b, arg, a, b)
        else:
            body = ('def %s(%s=None):\n'
                    '    %s = %d\n'
                    '    %s = (%s >> 3) ^ (%s << 5) ^ %s\n'
                    '    if (%s * %s + %s) %% 2 == 0:\n'
                    '        return %s & 0x7fffffff\n'
                    '    return %s ^ %d\n') % (
                        fn, arg, a, seed, b, a, a, arg, a, a, a,
                        b, a, seed)
        lines.append(body)
        names.append(fn)
    holder = random_ident('xdh')
    lines.append('%s = (%s)\n' % (holder, ', '.join(names) + (',' if len(names) == 1 else '')))
    return '\n'.join(lines), holder


def build_decoy_opcode_rows(count):
    rows = []
    for _ in range(max(0, count)):
        rows.append((random_ident('op'), random.randint(0, 999999), (random.randint(0, 255), random.randint(0, 255), random.randint(0, 999999))))
    random.shuffle(rows)
    return rows
