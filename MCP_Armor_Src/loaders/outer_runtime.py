# -*- coding: utf-8 -*-
"""Generated outer runtime protection layers."""
from __future__ import absolute_import, print_function

import random

from MCP_Armor_Src.utils.encoding import (
    debug_print_code,
    random_bytes,
    random_ident,
)


def build_outer_runtime_parts(names, options):
    variadic_args = random_ident('ova')
    variadic_kwargs = random_ident('ovk')
    tuple_gateway_enabled = bool(getattr(options, 'outer_tuple_gateway', False))
    closure_mirage_enabled = bool(getattr(
        options, 'outer_closure_index_mirage', False))
    generator_mirage_enabled = bool(getattr(
        options, 'outer_generator_frame_mirage', False))
    descriptor_mirage_enabled = bool(getattr(
        options, 'outer_method_descriptor_mirage', False))
    defaults_dict_enabled = bool(getattr(
        options, 'outer_defaults_dict_doppelganger', False))
    generator_enabled = bool(options.outer_generator_stages or
                             generator_mirage_enabled)
    method_enabled = bool(options.outer_dynamic_method or
                          descriptor_mirage_enabled)
    closure_enabled = bool(options.outer_closure_vault or
                           closure_mirage_enabled)
    closure_factory = random_ident('ocf')
    closure_getter = random_ident('ocg')
    closure_secret = random_ident('ocs')
    if closure_enabled:
        if closure_mirage_enabled:
            # Keep no complete runtime key in any closure cell.  Two encrypted
            # fragments, two mask shares, a route/check pair and a plausible
            # decoy become genuine co_freevars/func_closure entries.
            left_name = random_ident('ocl')
            right_name = random_ident('ocr')
            left_buf = random_ident('oclb')
            right_buf = random_ident('ocrb')
            char_name = random_ident('occ')
            mask_left = random_ident('ocml')
            mask_right = random_ident('ocmr')
            mask_name = random_ident('ocm')
            guard_name = random_ident('ocgd')
            route_name = random_ident('ocrt')
            decoy_name = random_ident('ocdy')
            decoded_left = random_ident('ocdl')
            decoded_right = random_ident('ocdr')
            output_name = random_ident('oco')
            pos_name = random_ident('ocp')
            mask_value = random.randint(1, 255)
            mask_share = random.randint(1, 255)
            mask_other = mask_value ^ mask_share
            guard_value = random.randint(257, 65535)
            decoy_value = random_bytes(max(8, int(options.key_len or 16)))
            scheme = random.randint(0, 2)
            setup_lines = [
                '    def %s(%s):' % (closure_factory, closure_secret),
                '        %s = %d' % (mask_left, mask_share),
                '        %s = %d' % (mask_right, mask_other),
                '        %s = []' % left_buf,
                '        %s = []' % right_buf,
            ]
            if scheme == 0:
                setup_lines.extend([
                    '        for %s in %s[::2]:' % (
                        char_name, closure_secret),
                    '            %s.append(chr(ord(%s) ^ (%s ^ %s)))' % (
                        left_buf, char_name, mask_left, mask_right),
                    '        for %s in %s[1::2]:' % (
                        char_name, closure_secret),
                    '            %s.append(chr(ord(%s) ^ (%s ^ %s)))' % (
                        right_buf, char_name, mask_left, mask_right),
                ])
            else:
                cut_name = random_ident('ocut')
                source_expr = closure_secret if scheme == 1 else '%s[::-1]' % closure_secret
                setup_lines.extend([
                    '        %s = (len(%s) + 1) // 2' % (
                        cut_name, closure_secret),
                    '        for %s in %s[:%s]:' % (
                        char_name, source_expr, cut_name),
                    '            %s.append(chr(ord(%s) ^ (%s ^ %s)))' % (
                        left_buf, char_name, mask_left, mask_right),
                    '        for %s in %s[%s:]:' % (
                        char_name, source_expr, cut_name),
                    '            %s.append(chr(ord(%s) ^ (%s ^ %s)))' % (
                        right_buf, char_name, mask_left, mask_right),
                ])
            setup_lines.extend([
                "        %s = ''.join(%s)" % (left_name, left_buf),
                "        %s = ''.join(%s)" % (right_name, right_buf),
                '        %s = %r' % (decoy_name, decoy_value),
                '        %s = %d' % (guard_name, guard_value),
                '        %s = (len(%s) + len(%s)) ^ %s' % (
                    route_name, left_name, right_name, guard_name),
                '        %s = None' % closure_secret,
                '        def %s():' % closure_getter,
                '            if (%s ^ %s) != (len(%s) + len(%s)):' % (
                    route_name, guard_name, left_name, right_name),
                '                return %s[:len(%s) + len(%s)]' % (
                    decoy_name, left_name, right_name),
                '            %s = %s ^ %s' % (
                    mask_name, mask_left, mask_right),
                '            %s = []' % decoded_left,
                '            for %s in %s:' % (char_name, left_name),
                '                %s.append(chr(ord(%s) ^ %s))' % (
                    decoded_left, char_name, mask_name),
                '            %s = []' % decoded_right,
                '            for %s in %s:' % (char_name, right_name),
                '                %s.append(chr(ord(%s) ^ %s))' % (
                    decoded_right, char_name, mask_name),
                "            %s = ''.join(%s)" % (
                    decoded_left, decoded_left),
                "            %s = ''.join(%s)" % (
                    decoded_right, decoded_right),
            ])
            if scheme == 0:
                setup_lines.extend([
                    '            %s = []' % output_name,
                    '            %s = 0' % pos_name,
                    '            while %s < len(%s) or %s < len(%s):' % (
                        pos_name, decoded_left, pos_name, decoded_right),
                    '                if %s < len(%s):' % (
                        pos_name, decoded_left),
                    '                    %s.append(%s[%s])' % (
                        output_name, decoded_left, pos_name),
                    '                if %s < len(%s):' % (
                        pos_name, decoded_right),
                    '                    %s.append(%s[%s])' % (
                        output_name, decoded_right, pos_name),
                    '                %s += 1' % pos_name,
                    "            return ''.join(%s)" % output_name,
                ])
            elif scheme == 1:
                setup_lines.append(
                    '            return %s + %s' % (
                        decoded_left, decoded_right))
            else:
                setup_lines.append(
                    '            return (%s + %s)[::-1]' % (
                        decoded_left, decoded_right))
            setup_lines.extend([
                '        return %s' % closure_getter,
                '    %s = %s(%s)' % (
                    closure_getter, closure_factory, names['key_arg']),
                '    del %s' % closure_factory,
                '    %s = None' % names['key_arg'],
            ])
            closure_setup = '\n'.join(setup_lines)
        else:
            closure_setup = (
                '    def %s(%s):\n'
                '        def %s():\n'
                '            return %s\n'
                '        return %s\n'
                '    %s = %s(%s)\n'
                '    del %s'
            ) % (closure_factory, closure_secret, closure_getter,
                 closure_secret, closure_getter, closure_getter,
                 closure_factory, names['key_arg'], closure_factory)
        if options.debug:
            label = ('MCP FunctionLoader ClosureIndexMirage' if
                     closure_mirage_enabled else
                     'MCP FunctionLoader RuntimeKeyClosure')
            closure_setup += '\n' + debug_print_code(True, label, 4)
        runtime_key_expr = '%s()' % closure_getter
    else:
        closure_setup = ''
        runtime_key_expr = names['key_arg']

    active = any((
        closure_enabled,
        tuple_gateway_enabled,
        method_enabled,
        generator_mirage_enabled,
        descriptor_mirage_enabled,
        defaults_dict_enabled,
        options.outer_dynamic_class,
        options.outer_callable_proxy,
        options.outer_frame_namespace,
        generator_enabled,
        options.outer_exception_state,
    ))
    if not active:
        dispatch = []
        if options.debug:
            dispatch.append(debug_print_code(True, 'MCP OuterDispatchBegin'))
        dispatch.append('%s()' % names['run_name'])
        if options.debug:
            dispatch.append(debug_print_code(True, 'MCP OuterDispatchComplete'))
        return {
            'closure_vault_setup_code': closure_setup,
            'runtime_key_expr': runtime_key_expr,
            'outer_dispatch_code': '\n'.join(dispatch),
        }

    probe_func = random_ident('ofp')
    probe_obj = random_ident('ofo')
    namespace_name = random_ident('ofn')
    target_name = random_ident('oft')
    entry_factory = random_ident('oef')
    entry_getter = random_ident('oeg')
    entry_secret = random_ident('oes')
    invoke_name = random_ident('oim')
    engine_name = random_ident('oec')
    engine_obj = random_ident('oeo')
    method_name = random_ident('obm')
    target_attr = random_ident('ota')
    pipeline_name = random_ident('ogp')
    pipeline_obj = random_ident('ogo')
    pipeline_arg = random_ident('oga')
    staged_name = random_ident('ost')
    result_name = random_ident('ors')
    boot_exc = random_ident('oeb')
    run_exc = random_ident('oer')
    state_name = random_ident('oes')

    lines = []
    if options.debug:
        lines.append(debug_print_code(True, 'MCP OuterDispatchBegin'))
    if options.outer_frame_namespace:
        lines.extend([
            'def %s():' % probe_func,
            '    yield None',
            '%s = %s()' % (probe_obj, probe_func),
            '%s = %s.gi_frame.f_globals' % (namespace_name, probe_obj),
            '%s = %s[%r]' % (target_name, namespace_name, names['run_name']),
            '%s.close()' % probe_obj,
            'del %s' % probe_obj,
        ])
        if options.debug:
            lines.append(debug_print_code(True, 'MCP Outer FrameNamespace'))
    else:
        lines.append('%s = %s' % (target_name, names['run_name']))

    if closure_enabled:
        if closure_mirage_enabled:
            entry_decoy_a = random_ident('oeda')
            entry_decoy_b = random_ident('oedb')
            entry_slots = random_ident('oeis')
            entry_ghost = random_ident('oeig')
            entry_route = random_ident('oeir')
            entry_route_left = random_ident('oeil')
            entry_guard = random_ident('oeid')
            entry_index = random_ident('oeii')
            entry_left_arg = random_ident('oela')
            entry_right_arg = random_ident('oera')
            real_index = random.randint(0, 2)
            route_left_value = random.randint(257, 65535)
            route_value = route_left_value ^ real_index
            entry_guard_value = random.randint(257, 65535)
            slots = [entry_left_arg, entry_right_arg]
            slots.insert(real_index, entry_secret)
            lines.extend([
                'def %s(*%s, **%s):' % (
                    entry_decoy_a, variadic_args, variadic_kwargs),
                '    return None',
                'def %s(*%s, **%s):' % (
                    entry_decoy_b, variadic_args, variadic_kwargs),
                '    return None',
                'def %s(%s, %s, %s):' % (
                    entry_factory, entry_secret, entry_left_arg,
                    entry_right_arg),
                '    %s = (%s,)' % (entry_slots, ', '.join(slots)),
                '    %s = (%s, %s, %s)' % (
                    entry_ghost, entry_right_arg, entry_left_arg,
                    entry_right_arg),
                '    %s = %d' % (entry_route_left, route_left_value),
                '    %s = %d' % (entry_route, route_value),
                '    %s = %d' % (entry_guard, entry_guard_value),
                '    def %s():' % entry_getter,
                '        %s = (%s ^ %s) %% len(%s)' % (
                    entry_index, entry_route_left, entry_route, entry_slots),
                '        if (len(%s) ^ %s) == %d:' % (
                    entry_ghost, entry_guard,
                    3 ^ entry_guard_value),
                '            return %s[%s]' % (entry_slots, entry_index),
                '        return %s[0]' % entry_ghost,
                '    return %s' % entry_getter,
                '%s = %s(%s, %s, %s)' % (
                    entry_getter, entry_factory, target_name,
                    entry_decoy_a, entry_decoy_b),
                'del %s' % target_name,
                '%s = %s()' % (target_name, entry_getter),
                'del %s' % entry_factory,
            ])
        else:
            lines.extend([
                'def %s(%s):' % (entry_factory, entry_secret),
                '    def %s():' % entry_getter,
                '        return %s' % entry_secret,
                '    return %s' % entry_getter,
                '%s = %s(%s)' % (entry_getter, entry_factory, target_name),
                'del %s' % target_name,
                '%s = %s()' % (target_name, entry_getter),
            ])
        if options.debug:
            label = ('MCP Outer ClosureIndexMirage' if
                     closure_mirage_enabled else 'MCP Outer ClosureVault')
            lines.append(debug_print_code(True, label))

    if tuple_gateway_enabled:
        tuple_gate = random_ident('otg')
        tuple_decoy = random_ident('otd')
        tuple_left_a = random_ident('otla')
        tuple_left_b = random_ident('otlb')
        tuple_right_a = random_ident('otra')
        tuple_right_b = random_ident('otrb')
        tuple_real = random_ident('otrr')
        tuple_false = random_ident('otrf')
        tuple_state = random_ident('ots')
        left_a_value = random.randint(0, 255)
        left_b_value = random.randint(0, 255)
        right_a_value = random.randint(0, 255)
        right_b_value = random.randint(0, 255)
        expected_value = ((left_a_value ^ right_a_value) +
                          (left_b_value ^ right_b_value)) & 255
        lines.extend([
            'def %s(*%s, **%s):' % (
                tuple_decoy, variadic_args, variadic_kwargs),
            '    return None',
            'def %s((%s, %s), (%s, %s), %s, %s):' % (
                tuple_gate, tuple_left_a, tuple_left_b,
                tuple_right_a, tuple_right_b, tuple_real, tuple_false),
            '    %s = ((%s ^ %s) + (%s ^ %s)) & 255' % (
                tuple_state, tuple_left_a, tuple_right_a,
                tuple_left_b, tuple_right_b),
            '    if %s == %d:' % (tuple_state, expected_value),
            '        return %s' % tuple_real,
            '    return %s' % tuple_false,
            '%s = %s((%d, %d), (%d, %d), %s, %s)' % (
                target_name, tuple_gate, left_a_value, left_b_value,
                right_a_value, right_b_value, target_name, tuple_decoy),
            'del %s' % tuple_gate,
            'del %s' % tuple_decoy,
        ])
        if options.debug:
            lines.append(debug_print_code(True, 'MCP Outer RealTupleGateway'))

    if defaults_dict_enabled:
        defaults_factory = random_ident('oddf')
        defaults_capsule = random_ident('oddc')
        defaults_holder = random_ident('oddh')
        defaults_secret = random_ident('odds')
        defaults_decoy_a = random_ident('odda')
        defaults_decoy_b = random_ident('oddb')
        defaults_left_arg = random_ident('oddla')
        defaults_right_arg = random_ident('oddra')
        defaults_slots = random_ident('oddsl')
        defaults_closure_share = random_ident('oddcs')
        defaults_route_arg = random_ident('oddrr')
        defaults_proof_arg = random_ident('oddpr')
        defaults_index = random_ident('oddix')
        defaults_saved = random_ident('odddf')
        defaults_real_index = random.randint(0, 2)
        defaults_share_value = random.randint(257, 65535)
        defaults_route_value = defaults_share_value ^ defaults_real_index
        proof_left = random.randint(257, 65535)
        proof_right = random.randint(257, 65535)
        proof_value = proof_left ^ proof_right
        bad_route = defaults_share_value ^ ((defaults_real_index + 1) % 3)
        bad_proof = (proof_left, proof_right, proof_value ^ 1)
        real_proof = (proof_left, proof_right, proof_value)
        defaults_items = [defaults_left_arg, defaults_right_arg]
        defaults_items.insert(defaults_real_index, defaults_secret)
        dict_key_a = random_ident('odka')
        dict_key_b = random_ident('odkb')
        dict_key_c = random_ident('odkc')
        lines.extend([
            'def %s(*%s, **%s):' % (
                defaults_decoy_a, variadic_args, variadic_kwargs),
            '    return None',
            'def %s(*%s, **%s):' % (
                defaults_decoy_b, variadic_args, variadic_kwargs),
            '    return None',
            'def %s(%s, %s, %s):' % (
                defaults_factory, defaults_secret,
                defaults_left_arg, defaults_right_arg),
            '    %s = [[%s]]' % (
                defaults_holder, ', '.join(defaults_items)),
            '    %s = %d' % (
                defaults_closure_share, defaults_share_value),
            '    def %s(%s=%d, %s=%r):' % (
                defaults_capsule, defaults_route_arg, bad_route,
                defaults_proof_arg, bad_proof),
            '        %s = (%s ^ %s) %% len(%s[0])' % (
                defaults_index, defaults_closure_share,
                defaults_route_arg, defaults_holder),
            '        if (%s[0] ^ %s[1]) == %s[2]:' % (
                defaults_proof_arg, defaults_proof_arg,
                defaults_proof_arg),
            '            return %s[0][%s]' % (
                defaults_holder, defaults_index),
            '        return %s[0][(%s + 1) %% len(%s[0])]' % (
                defaults_holder, defaults_index, defaults_holder),
            '    return %s, %s' % (
                defaults_capsule, defaults_holder),
            '%s, %s = %s(%s, %s, %s)' % (
                defaults_capsule, defaults_holder, defaults_factory,
                target_name, defaults_decoy_a, defaults_decoy_b),
            'del %s' % defaults_factory,
            '%s = %s.func_defaults' % (
                defaults_saved, defaults_capsule),
            '%s.func_dict[%r] = (%d, %d, %d)' % (
                defaults_capsule, dict_key_a,
                bad_route, proof_left, proof_value ^ 1),
            '%s.func_dict[%r] = {%r: %r, %r: %d}' % (
                defaults_capsule, dict_key_b,
                dict_key_a, random_ident('odmeta'),
                dict_key_c, random.randint(257, 65535)),
            '%s.func_dict[%r] = %s' % (
                defaults_capsule, dict_key_c, defaults_saved),
            '%s.func_defaults = (%d, %r)' % (
                defaults_capsule, defaults_route_value, real_proof),
            '%s = %s()' % (target_name, defaults_capsule),
            '%s.func_defaults = %s' % (
                defaults_capsule, defaults_saved),
            '%s[0] = (%s, %s, %s)' % (
                defaults_holder, defaults_decoy_a, defaults_decoy_b,
                defaults_decoy_a),
            '%s = None' % defaults_holder,
            '%s = None' % defaults_saved,
        ])
        if options.debug:
            lines.append(debug_print_code(
                True, 'MCP Outer DefaultsDictDoppelganger'))

    method_cleanup = []
    if (method_enabled or options.outer_dynamic_class or
            options.outer_callable_proxy):
        method_self = random_ident('omsf')
        if descriptor_mirage_enabled:
            method_decoy_a = random_ident('omda')
            method_decoy_b = random_ident('omdb')
            method_name_a = random_ident('omna')
            method_name_b = random_ident('omnb')
            method_name_c = random_ident('omnc')
            method_shadow_a = random_ident('omsa')
            method_shadow_b = random_ident('omsb')
            method_bound_a = random_ident('omba')
            method_bound_b = random_ident('ombb')
            method_bound_c = random_ident('ombc')
            method_slots = random_ident('omsl')
            method_index = random_ident('omix')
            method_route_a = random_ident('omra')
            method_route_b = random_ident('omrb')
            method_real_index = random.randint(0, 2)
            method_route_a_value = random.randint(257, 65535)
            method_route_b_value = method_route_a_value ^ method_real_index
            method_functions = [method_decoy_a, method_decoy_b]
            method_functions.insert(method_real_index, invoke_name)
            method_names = [method_name_a, method_name_b, method_name_c]
            lines.extend([
                'def %s(%s):' % (invoke_name, method_self),
                '    return getattr(%s, %r)()' % (method_self, target_attr),
                'def %s(%s):' % (method_decoy_a, method_self),
                '    return getattr(%s, %r)' % (
                    method_self, method_shadow_a),
                'def %s(%s):' % (method_decoy_b, method_self),
                '    return getattr(%s, %r)' % (
                    method_self, method_shadow_b),
                '%s = type(%r, (object,), {})' % (
                    engine_name, random_ident('DescriptorStage')),
            ])
            for attr_name, func_name in zip(method_names, method_functions):
                lines.append('setattr(%s, %r, %s)' % (
                    engine_name, attr_name, func_name))
            lines.extend([
                '%s = %s()' % (engine_obj, engine_name),
                'setattr(%s, %r, %s)' % (
                    engine_obj, target_attr, target_name),
                'setattr(%s, %r, (%s, %d))' % (
                    engine_obj, method_shadow_a, target_name,
                    random.randint(257, 65535)),
                'setattr(%s, %r, None)' % (
                    engine_obj, method_shadow_b),
                '%s = %s.__dict__[%r].__get__(%s, %s)' % (
                    method_bound_a, engine_name, method_name_a,
                    engine_obj, engine_name),
                '%s = getattr(%s, %r)' % (
                    method_bound_b, engine_obj, method_name_b),
                '%s = %s.__dict__[%r].__get__(%s, %s)' % (
                    method_bound_c, engine_name, method_name_c,
                    engine_obj, engine_name),
                '%s = (%s, %s, %s)' % (
                    method_slots, method_bound_a, method_bound_b,
                    method_bound_c),
                '%s = %d' % (method_route_a, method_route_a_value),
                '%s = %d' % (method_route_b, method_route_b_value),
                '%s = (%s ^ %s) %% len(%s)' % (
                    method_index, method_route_a, method_route_b,
                    method_slots),
                '%s = %s[%s]' % (
                    target_name, method_slots, method_index),
            ])
            method_cleanup.extend([
                'setattr(%s, %r, None)' % (engine_obj, target_attr),
                '%s = None' % method_bound_a,
                '%s = None' % method_bound_b,
                '%s = None' % method_bound_c,
                '%s = None' % method_slots,
                '%s = None' % engine_obj,
            ])
            if options.outer_callable_proxy:
                proxy_invoke = random_ident('ompi')
                proxy_name = random_ident('ompc')
                proxy_obj = random_ident('ompo')
                proxy_attr = random_ident('ompa')
                lines.extend([
                    'def %s(%s):' % (proxy_invoke, method_self),
                    '    return getattr(%s, %r)()' % (
                        method_self, proxy_attr),
                    '%s = type(%r, (object,), {%r: %s})' % (
                        proxy_name, random_ident('MethodProxy'),
                        '__call__', proxy_invoke),
                    '%s = %s()' % (proxy_obj, proxy_name),
                    'setattr(%s, %r, %s)' % (
                        proxy_obj, proxy_attr, target_name),
                    '%s = %s' % (target_name, proxy_obj),
                ])
                method_cleanup.extend([
                    'setattr(%s, %r, None)' % (proxy_obj, proxy_attr),
                    '%s = None' % proxy_obj,
                ])
            method_cleanup.append('%s = None' % target_name)
            if options.debug:
                lines.append(debug_print_code(
                    True, 'MCP Outer MethodDescriptorTripleMirage'))
        else:
            lines.extend([
                'def %s(%s):' % (invoke_name, method_self),
                '    return getattr(%s, %r)()' % (method_self, target_attr),
            ])
            class_fields = '{}'
            if options.outer_dynamic_class:
                lines.append('%s = type(%r, (object,), %s)' % (
                    engine_name, random_ident('RuntimeStage'), class_fields))
            else:
                lines.extend(['class %s(object):' % engine_name, '    pass'])
            if options.outer_dynamic_method or not options.outer_callable_proxy:
                lines.append('setattr(%s, %r, %s)' % (
                    engine_name, method_name, invoke_name))
            if options.outer_callable_proxy:
                lines.append('setattr(%s, %r, %s)' % (
                    engine_name, '__call__', invoke_name))
            lines.extend([
                '%s = %s()' % (engine_obj, engine_name),
                'setattr(%s, %r, %s)' % (engine_obj, target_attr, target_name),
            ])
            if options.outer_callable_proxy:
                lines.append('%s = %s' % (target_name, engine_obj))
            else:
                lines.append('%s = getattr(%s, %r)' % (
                    target_name, engine_obj, method_name))
            if options.debug:
                lines.append(debug_print_code(
                    True, 'MCP Outer DynamicCallableProxy'))

    generator_cleanup = []
    if generator_enabled:
        if generator_mirage_enabled:
            gen_decoy_a = random_ident('ogda')
            gen_decoy_b = random_ident('ogdb')
            gen_stage_arg = random_ident('ogsa')
            gen_target_arg = random_ident('ogta')
            gen_shadow_arg = random_ident('ogha')
            gen_local_target = random_ident('oglt')
            gen_local_shadow = random_ident('ogls')
            gen_local_route = random_ident('oglr')
            gen_a = random_ident('ogoa')
            gen_b = random_ident('ogob')
            gen_c = random_ident('ogoc')
            gen_prime_a = random_ident('ogpa')
            gen_prime_b = random_ident('ogpb')
            gen_prime_c = random_ident('ogpc')
            gen_slots = random_ident('ogsl')
            gen_prime_slots = random_ident('ogps')
            gen_index = random_ident('ogix')
            gen_route_a = random_ident('ogra')
            gen_route_b = random_ident('ogrb')
            gen_real_index = random.randint(0, 2)
            gen_route_a_value = random.randint(257, 65535)
            gen_route_b_value = gen_route_a_value ^ gen_real_index
            generator_targets = [gen_decoy_a, gen_decoy_b]
            generator_targets.insert(gen_real_index, target_name)
            generator_shadows = [target_name, gen_decoy_a, gen_decoy_b]
            random.shuffle(generator_shadows)
            stage_values = []
            for _unused in range(3):
                stage_left = random.randint(257, 65535)
                stage_right = random.randint(257, 65535)
                stage_values.append((stage_left, stage_right))
            lines.extend([
                'def %s(*%s, **%s):' % (
                    gen_decoy_a, variadic_args, variadic_kwargs),
                '    return None',
                'def %s(*%s, **%s):' % (
                    gen_decoy_b, variadic_args, variadic_kwargs),
                '    return None',
                'def %s(%s, %s, %s):' % (
                    pipeline_name, gen_stage_arg, gen_target_arg,
                    gen_shadow_arg),
                '    %s = %s' % (gen_local_target, gen_target_arg),
                '    %s = %s' % (gen_local_shadow, gen_shadow_arg),
                '    %s = %s[0] ^ %s[1]' % (
                    gen_local_route, gen_stage_arg, gen_stage_arg),
                '    yield %s' % gen_local_target,
                '    yield %s()' % gen_local_target,
                '%s = %s((%d, %d), %s, %s)' % (
                    gen_a, pipeline_name, stage_values[0][0],
                    stage_values[0][1], generator_targets[0],
                    generator_shadows[0]),
                '%s = %s((%d, %d), %s, %s)' % (
                    gen_b, pipeline_name, stage_values[1][0],
                    stage_values[1][1], generator_targets[1],
                    generator_shadows[1]),
                '%s = %s((%d, %d), %s, %s)' % (
                    gen_c, pipeline_name, stage_values[2][0],
                    stage_values[2][1], generator_targets[2],
                    generator_shadows[2]),
                '%s = %s.next()' % (gen_prime_a, gen_a),
                '%s = %s.next()' % (gen_prime_b, gen_b),
                '%s = %s.next()' % (gen_prime_c, gen_c),
                '%s = (%s, %s, %s)' % (
                    gen_slots, gen_a, gen_b, gen_c),
                '%s = (%s, %s, %s)' % (
                    gen_prime_slots, gen_prime_a, gen_prime_b,
                    gen_prime_c),
                '%s = %d' % (gen_route_a, gen_route_a_value),
                '%s = %d' % (gen_route_b, gen_route_b_value),
                '%s = (%s ^ %s) %% len(%s)' % (
                    gen_index, gen_route_a, gen_route_b, gen_slots),
                '%s = %s[%s]' % (
                    pipeline_obj, gen_slots, gen_index),
                '%s = %s[%s]' % (
                    staged_name, gen_prime_slots, gen_index),
            ])
            generator_cleanup.extend([
                '%s.close()' % gen_a,
                '%s.close()' % gen_b,
                '%s.close()' % gen_c,
                '%s = None' % gen_a,
                '%s = None' % gen_b,
                '%s = None' % gen_c,
                '%s = None' % gen_prime_a,
                '%s = None' % gen_prime_b,
                '%s = None' % gen_prime_c,
                '%s = None' % gen_slots,
                '%s = None' % gen_prime_slots,
                '%s = None' % pipeline_obj,
                '%s = None' % staged_name,
            ])
            if options.debug:
                lines.append(debug_print_code(
                    True, 'MCP Outer GeneratorFrameMirrors'))
        else:
            lines.extend([
                'def %s(%s):' % (pipeline_name, pipeline_arg),
                '    yield %s' % pipeline_arg,
                '    yield %s()' % pipeline_arg,
                '%s = %s(%s)' % (
                    pipeline_obj, pipeline_name, target_name),
            ])
            if options.debug:
                lines.append(debug_print_code(
                    True, 'MCP Outer GeneratorStages'))

    if options.outer_exception_state:
        lines.extend([
            '%s = type(%r, (Exception,), {})' % (
                boot_exc, random_ident('StageBoot')),
            '%s = type(%r, (Exception,), {})' % (
                run_exc, random_ident('StageRun')),
            '%s = 0' % state_name,
            '%s = None' % result_name,
            'while True:',
            '    try:',
            '        if %s == 0:' % state_name,
            '            raise %s()' % boot_exc,
            '        raise %s()' % run_exc,
            '    except %s:' % boot_exc,
        ])
        if generator_enabled and not generator_mirage_enabled:
            lines.append('        %s = %s.next()' % (staged_name, pipeline_obj))
        elif generator_mirage_enabled:
            lines.append('        %s = %s' % (staged_name, staged_name))
        else:
            lines.append('        %s = %s' % (staged_name, target_name))
        if options.debug:
            lines.append(debug_print_code(True, 'MCP Outer ExceptionBootState', 8))
        lines.extend([
            '        %s = 1' % state_name,
            '    except %s:' % run_exc,
        ])
        if generator_enabled:
            lines.append('        %s = %s.next()' % (result_name, pipeline_obj))
        else:
            lines.append('        %s = %s()' % (result_name, staged_name))
        if options.debug:
            lines.append(debug_print_code(True, 'MCP Outer ExceptionRunState', 8))
        lines.append('        break')
    elif generator_enabled:
        if not generator_mirage_enabled:
            lines.append('%s = %s.next()' % (staged_name, pipeline_obj))
        lines.append('%s = %s.next()' % (result_name, pipeline_obj))
    else:
        lines.append('%s = %s()' % (result_name, target_name))

    lines.extend(generator_cleanup)
    lines.extend(method_cleanup)

    if options.debug:
        lines.append(debug_print_code(True, 'MCP OuterDispatchComplete'))

    return {
        'closure_vault_setup_code': closure_setup,
        'runtime_key_expr': runtime_key_expr,
        'outer_dispatch_code': '\n'.join(lines),
    }
