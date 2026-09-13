# -*- coding: utf-8 -*-
"""Fake code objects, constants and invalid dead-bytecode payloads."""


from MCP_Armor_Src.core import py27_opcode as opcode
import random
import types

from MCP_Armor_Src.bytecode_obf.instructions import (
    write_oparg,
)

from MCP_Armor_Src.bytecode_obf.model import (
    rebuild_code,
)

from MCP_Armor_Src.core.constants import (
    CODE_TUPLE_MAGIC,
    JUMP_ABSOLUTE,
    JUMP_FORWARD,
    LOAD_CONST,
    NOP,
    RETURN_VALUE,
)

from MCP_Armor_Src.utils.encoding import (
    byte_char, byte_value,
    random_binary_metadata_label,
    random_bytes,
    random_ident,
)


def make_taunt_const(text, depth, idx):
    salt = random.randint(10000, 999999)
    mode = idx % 5
    if mode == 0:
        return text
    if mode == 1:
        return (text, 'lambda', depth, idx, salt)
    if mode == 2:
        return {'msg': text, 'mark': salt ^ 0x334455, 'dead': False}
    if mode == 3:
        return (text, ('try', 'except', 'finally'), ('opcode', salt & 255))
    return '%s#%08x#%d#%d' % (text, salt, depth, idx)


def make_fake_code_object(depth, idx, taunt_text=None, fake_depth=0, nop_bloat=0, stop_bloat=0):
    fname = random_ident('fc')
    marker = taunt_text or 'dead-code-object'
    source = (
        'def %s(_x=None):\n'
        '    _m = %r\n'
        '    _v = %d\n'
        '    if _v < 0:\n'
        '        return _m\n'
        '    return None\n'
    ) % (fname, marker, random.randint(10000, 999999))
    compiled = compile(source, '<fake_%d_%d>' % (depth, idx), 'exec', 0, True)
    base = compiled
    for const in compiled.co_consts:
        if isinstance(const, types.CodeType):
            base = const
            break

    stop_code = opcode.opmap.get('STOP_CODE', 0)
    arg_names = [
        'LOAD_CONST', 'LOAD_FAST', 'STORE_FAST', 'DELETE_FAST',
        'LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_ATTR',
        'LOAD_DEREF', 'STORE_DEREF',
        'IMPORT_FROM', 'UNPACK_SEQUENCE',
        'BUILD_MAP', 'BUILD_LIST',
        'MAKE_FUNCTION', 'MAKE_CLOSURE',
    ]
    exc_arg_names = ['SETUP_FINALLY', 'SETUP_EXCEPT', 'SETUP_WITH']
    exc_noarg_names = ['WITH_CLEANUP', 'END_FINALLY', 'POP_BLOCK']
    poison = []

    def add_arg_op(name, arg):
        opv = opcode.opmap.get(name)
        if opv is not None:
            poison.append(byte_char(opv))
            poison.append(write_oparg(arg))

    extra_nops = max(0, int(nop_bloat)) // (fake_depth + 1)
    extra_stops = max(0, int(stop_bloat)) // (fake_depth + 1)
    for _n in range(random.randint(1, 4) + extra_nops):
        poison.append(byte_char(NOP))
    for _s in range(random.randint(1, 3) + extra_stops):
        poison.append(byte_char(stop_code))
    for _j in range(random.randint(1, 3)):
        poison.append(byte_char(JUMP_ABSOLUTE))
        poison.append(write_oparg(random.choice([0, 1, 2, random.randint(30000, 65535)])))
    for _a in range(random.randint(8, 16)):
        add_arg_op(random.choice(arg_names), random.randint(30000, 65535))
    for _e in range(random.randint(2, 5)):
        add_arg_op(random.choice(exc_arg_names), random.randint(0, 65535))
        noarg = opcode.opmap.get(random.choice(exc_noarg_names))
        if noarg is not None:
            poison.append(byte_char(noarg))
    for _b in range(random.randint(2, 5)):
        poison.append(byte_char(random.choice([255, 254, 251, 250, 249, 248, 247])))
        poison.append(byte_char(random.randint(0, 255)))
        poison.append(byte_char(random.randint(0, 255)))

    poison = b''.join(poison)
    if len(poison) > 65535:
        poison = poison[:65535]
    code_bytes = byte_char(JUMP_FORWARD) + write_oparg(len(poison)) + poison
    code_bytes += byte_char(LOAD_CONST) + write_oparg(0) + byte_char(RETURN_VALUE)

    consts = [
        None,
        marker,
        make_taunt_const(marker, depth, idx),
        ('fake-code-object', depth, idx, random.randint(10000, 999999)),
        random_bytes(random.randint(8, 24)),
        float('inf'),
        -float('inf'),
    ]
    for noise_idx in range(random.randint(4, 10)):
        consts.append(make_fake_const(depth + 1, noise_idx, taunt_text, 0))
    if fake_depth < 2:
        child_count = 1 + ((depth + idx + fake_depth) & 1)
        for child_idx in range(child_count):
            child_seed = (idx * 17) + child_idx + 1
            consts.append(make_fake_code_object(depth + 1, child_seed, taunt_text, fake_depth + 1, nop_bloat, stop_bloat))
    names = list(base.co_names) + make_ghost_names(random.randint(6, 14), taunt_text)
    return rebuild_code(
        base,
        consts=consts,
        code_bytes=code_bytes,
        filename=random_binary_metadata_label('fake_file'),
        name=random_binary_metadata_label('fake_code'),
        firstlineno=-1,
        names=names,
        varnames=base.co_varnames,
        nlocals=base.co_nlocals,
    )


def make_ghost_names(count, taunt_text=None):
    names = []
    bases = ['RegisterSystem', 'ListenForEvent', 'NotifyToServer', 'NotifyToClient', 'CreateComponent', 'GetEngineCompFactory', 'extraServerApi', 'extraClientApi', 'Minecraft', 'NeteaseSystem']
    for idx in range(max(0, count)):
        if taunt_text and idx % 7 == 0:
            names.append(('ghost_%s_%d' % (taunt_text, idx)).replace(' ', '_'))
        else:
            names.append('_ghost_%s_%08x' % (random.choice(bases), random.randint(0, 0xffffffff)))
    return names


def make_fake_const(depth, idx, taunt_text=None, taunt_inner_consts=0):
    if taunt_text and taunt_inner_consts > 0 and idx < taunt_inner_consts:
        return make_taunt_const(taunt_text, depth, idx)
    salt = random.randint(10000, 999999)
    mode = idx % 8
    if mode == 0:
        return '???????????#%d:%d:%d' % (depth, idx, salt)
    if mode == 1:
        return ('_noise_', depth, idx, salt, ('path', '<mem>', random.randint(1, 999)))
    if mode == 2:
        return random.randint(0x1000, 0x7fffffff)
    if mode == 3:
        return None
    if mode == 4:
        return ('lambda', ('if', 'try', 'except'), ('fake', depth, idx), salt ^ 0x5A5A)
    if mode == 5:
        return 'deobf_%08x_%08x' % (salt, random.randint(0, 0xffffffff))
    if mode == 6:
        return (float((salt % 997) + depth) / 7.0, int(salt) << (idx % 5))
    return ('opcode', (salt & 255, (salt >> 3) & 255), 'not-used')


def make_const_swamp(count, taunt_text=None):
    swamp = []
    for idx in range(max(0, count)):
        salt = random.randint(10000, 999999)
        if idx % 4 == 0:
            swamp.append((taunt_text or 'const-swamp', salt, random_bytes(random.randint(8, 24))))
        elif idx % 4 == 1:
            swamp.append({'k': '_swamp_%08x' % salt, 'v': salt ^ 0x55AA, 'm': taunt_text})
        elif idx % 4 == 2:
            swamp.append([salt, salt & 255, (salt >> 8) & 255, None])
        else:
            swamp.append('swamp_%08x_%s' % (salt, taunt_text or 'dead'))
    return swamp


def make_const_reference_chain(count, taunt_text=None):
    refs = []
    apis = [
        'mod.server.extraServerApi', 'mod.client.extraClientApi', 'RegisterSystem',
        'ListenForEvent', 'UnListenForEvent', 'NotifyToServer', 'NotifyToClient',
        'GetEngineCompFactory', 'CreateCommand', 'CreateTag', 'AddEntityTag',
        'CustomCommandTriggerServerEvent', 'PlayerJoinMessageEvent', 'ServerChatEvent',
    ]
    opnames = [
        'LOAD_CONST', 'LOAD_GLOBAL', 'LOAD_ATTR', 'CALL_FUNCTION', 'MAKE_FUNCTION',
        'JUMP_FORWARD', 'JUMP_ABSOLUTE', 'SETUP_FINALLY', 'WITH_CLEANUP',
        'EXTENDED_ARG', 'IMPORT_NAME', 'IMPORT_FROM',
    ]
    for idx in range(max(0, count)):
        salt = random.randint(10000, 999999)
        fake_ops = []
        for pos in range(random.randint(4, 10)):
            fake_ops.append((random.choice(opnames), random.randint(0, 65535), (salt ^ (pos * 131)) & 255))
        api_path = random.choice(apis)
        event_name = random.choice(apis[-3:])
        marker = taunt_text or 'const-ref-chain'
        if idx % 4 == 0:
            refs.append((marker, ('api', api_path, event_name), ('opmap', tuple(fake_ops)), ('payload', CODE_TUPLE_MAGIC, salt)))
        elif idx % 4 == 1:
            refs.append({
                'api': api_path,
                'event': event_name,
                'opcode': fake_ops,
                'magic': CODE_TUPLE_MAGIC,
                'salt': salt,
                'dead': True,
            })
        elif idx % 4 == 2:
            refs.append([api_path, event_name, tuple(fake_ops), [CODE_TUPLE_MAGIC, marker, salt ^ 0x55AA]])
        else:
            refs.append('%s|%s|%s|%08x|%s' % (api_path, event_name, random.choice(opnames), salt, marker))
    return refs


def build_dead_bad_bytecode(count, bad_units=3, nop_bloat=0, stop_bloat=0, arg_poison=0, exception_poison=0, call_poison=0):
    chunks = []
    bad_ops = [255, 254, 251, 250, 249, 248, 247]
    stop_code = opcode.opmap.get('STOP_CODE', 0)
    arg_ops = [opcode.opmap[name] for name in (
        'LOAD_CONST', 'LOAD_FAST', 'STORE_FAST', 'DELETE_FAST', 'LOAD_GLOBAL', 'STORE_GLOBAL', 'DELETE_GLOBAL',
        'LOAD_NAME', 'STORE_NAME', 'DELETE_NAME', 'LOAD_ATTR', 'STORE_ATTR', 'DELETE_ATTR',
        'LOAD_DEREF', 'STORE_DEREF', 'LOAD_CLOSURE', 'IMPORT_FROM')
        if name in opcode.opmap]
    shape_arg_ops = [opcode.opmap[name] for name in (
        'UNPACK_SEQUENCE', 'BUILD_TUPLE', 'BUILD_LIST', 'BUILD_SET', 'BUILD_MAP', 'BUILD_SLICE',
        'LIST_APPEND', 'SET_ADD', 'MAP_ADD', 'DUP_TOPX', 'MAKE_FUNCTION', 'MAKE_CLOSURE')
        if name in opcode.opmap]
    exc_arg_ops = [opcode.opmap[name] for name in ('SETUP_FINALLY', 'SETUP_EXCEPT', 'SETUP_WITH') if name in opcode.opmap]
    exc_noarg_ops = [opcode.opmap[name] for name in ('WITH_CLEANUP', 'POP_BLOCK', 'END_FINALLY') if name in opcode.opmap]
    call_ops = [opcode.opmap[name] for name in ('MAKE_FUNCTION', 'CALL_FUNCTION', 'CALL_FUNCTION_VAR', 'CALL_FUNCTION_KW', 'CALL_FUNCTION_VAR_KW') if name in opcode.opmap]
    jump_ops = [op for op in (JUMP_ABSOLUTE, JUMP_FORWARD) if op is not None]
    stack_noarg_ops = [opcode.opmap[name] for name in (
        'ROT_TWO', 'ROT_THREE', 'ROT_FOUR', 'DUP_TOP', 'POP_TOP', 'STORE_MAP',
        'WITH_CLEANUP', 'END_FINALLY', 'POP_BLOCK', 'NOP', 'STOP_CODE')
        if name in opcode.opmap]
    legacy_noarg_ops = [opcode.opmap[name] for name in (
        'SLICE+0', 'SLICE+1', 'SLICE+2', 'SLICE+3',
        'STORE_SLICE+0', 'STORE_SLICE+1', 'STORE_SLICE+2', 'STORE_SLICE+3',
        'DELETE_SLICE+0', 'DELETE_SLICE+1', 'DELETE_SLICE+2', 'DELETE_SLICE+3',
        'PRINT_NEWLINE_TO')
        if name in opcode.opmap]

    def add_oparg(buf, opv, arg):
        buf.append(byte_char(opv))
        buf.append(byte_char(arg & 255))
        buf.append(byte_char((arg >> 8) & 255))

    def add_combo(buf, mode):
        if mode == 0 and jump_ops:
            add_oparg(buf, random.choice(jump_ops), random.choice([0, 1, 2, random.randint(30000, 65535)]))
        elif mode == 1 and shape_arg_ops:
            add_oparg(buf, random.choice(shape_arg_ops), random.randint(30000, 65535))
        elif mode == 2 and arg_ops:
            add_oparg(buf, random.choice(arg_ops), random.randint(30000, 65535))
        elif mode == 3 and exc_arg_ops:
            add_oparg(buf, random.choice(exc_arg_ops), random.randint(0, 65535))
            if exc_noarg_ops:
                buf.append(byte_char(random.choice(exc_noarg_ops)))
        elif mode == 4 and call_ops:
            add_oparg(buf, random.choice(call_ops), random.randint(30000, 65535))
        elif mode == 5 and stack_noarg_ops:
            for _x in range(random.randint(1, 3)):
                buf.append(byte_char(random.choice(stack_noarg_ops)))
        elif mode == 6 and legacy_noarg_ops:
            for _x in range(random.randint(2, 5)):
                buf.append(byte_char(random.choice(legacy_noarg_ops)))
        else:
            buf.append(byte_char(random.choice(bad_ops)))
            buf.append(byte_char(random.randint(0, 255)))
            buf.append(byte_char(random.randint(0, 255)))

    for _ in range(max(0, count)):
        poison = []
        for _n in range(max(0, nop_bloat)):
            poison.append(byte_char(NOP))
        for _s in range(max(0, stop_bloat)):
            poison.append(byte_char(stop_code))
        for _a in range(max(0, arg_poison)):
            if arg_ops:
                add_oparg(poison, random.choice(arg_ops), random.randint(30000, 65535))
        for _e in range(max(0, exception_poison)):
            if exc_arg_ops:
                add_oparg(poison, random.choice(exc_arg_ops), random.randint(0, 65535))
            if exc_noarg_ops:
                poison.append(byte_char(random.choice(exc_noarg_ops)))
        for _c in range(max(0, call_poison)):
            if call_ops:
                add_oparg(poison, random.choice(call_ops), random.randint(30000, 65535))
        combo_rounds = max(1, bad_units + arg_poison + exception_poison + call_poison)
        for _combo in range(combo_rounds):
            add_combo(poison, random.randint(0, 7))
        for _j in range(max(0, bad_units)):
            poison.append(byte_char(random.choice(bad_ops)))
            poison.append(byte_char(random.randint(0, 255)))
            poison.append(byte_char(random.randint(0, 255)))
        random_noise = random.randint(0, max(0, bad_units))
        for _r in range(random_noise):
            poison.append(byte_char(random.randint(240, 255)))
        poison = b''.join(poison)
        if JUMP_FORWARD is not None and len(poison) <= 65535:
            chunks.append(byte_char(JUMP_FORWARD))
            chunks.append(byte_char(len(poison) & 255))
            chunks.append(byte_char((len(poison) >> 8) & 255))
            chunks.append(poison)
            chunks.append(byte_char(NOP))
        else:
            chunks.append(poison)
    return b''.join(chunks)\n