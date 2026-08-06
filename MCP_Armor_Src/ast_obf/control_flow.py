# -*- coding: utf-8 -*-
"""AST pipeline composition, validation and source compilation."""
from __future__ import absolute_import, print_function

import ast
import os
import random

from MCP_Armor_Src.ast_obf.dead_flow import (
    add_source_comment_noise,
    inject_source_dead_flow,
)

from MCP_Armor_Src.ast_obf.analysis import (
    analyze_source_tree,
    annotate_source_tree,
)

from MCP_Armor_Src.ast_obf.predicates import (
    inject_internal_predicates,
)

from MCP_Armor_Src.ast_obf.identity import (
    inject_source_decompiler_carriers,
    inject_tuple_argument_decoys,
    weave_source_function_identities,
)

from MCP_Armor_Src.ast_obf.literals import (
    SourceConstantPool,
    SourceExceptionShell,
    SourceLocalConstantRewrite,
    SourceStringSplitter,
    collect_source_literal_protection,
    insert_source_string_xor_helpers,
    obfuscate_source_strings_xor,
    source_docstring_node,
)

from MCP_Armor_Src.ast_obf.names import (
    obfuscate_source_definition_names,
    rename_source_locals,
)

from MCP_Armor_Src.ast_obf.references import (
    obfuscate_source_references,
)

from MCP_Armor_Src.ast_obf.structure import (
    linearize_source_calls,
    render_source_tree,
    schedule_source_execution,
)

from MCP_Armor_Src.ast_obf.VM.vm import (
    virtualize_source_functions,
)

from MCP_Armor_Src.utils.encoding import (
    obfuscate_reserved_generated_identifiers,
    random_ident,
)

from MCP_Armor_Src.utils.filesystem import (
    python_compile_filename,
    read_file,
)


def has_unsafe_flatten_node(node):
    unsafe = (ast.TryExcept, ast.TryFinally, ast.With, ast.Yield, ast.Lambda, ast.Global, ast.Nonlocal if hasattr(ast, 'Nonlocal') else ast.Global)
    for child in ast.walk(node):
        if isinstance(child, unsafe):
            return True
    return False


def is_flattenable_stmt(stmt):
    return isinstance(stmt, (ast.Assign, ast.AugAssign, ast.Expr, ast.If, ast.Return))


def make_name(name, ctx):
    return ast.Name(id=name, ctx=ctx)


def make_num(value):
    return ast.Num(n=value)


def assign_name(name, value):
    return ast.Assign(targets=[make_name(name, ast.Store())], value=value)


def state_assign(state_name, value):
    return assign_name(state_name, make_num(value))


def state_test(state_name, value):
    return ast.Compare(left=make_name(state_name, ast.Load()), ops=[ast.Eq()], comparators=[make_num(value)])


def is_return_stmt(stmt):
    return isinstance(stmt, ast.Return)


def flatten_function_body(body, state_name, ret_name, max_blocks):
    if not body or len(body) < 3 or len(body) > max_blocks:
        return None
    if any(not is_flattenable_stmt(stmt) for stmt in body):
        return None
    if any(has_unsafe_flatten_node(stmt) for stmt in body):
        return None
    blocks = []
    for idx, stmt in enumerate(body):
        next_state = idx + 1 if idx + 1 < len(body) else -1
        block_body = []
        if isinstance(stmt, ast.Return):
            block_body.append(assign_name(ret_name, stmt.value or ast.Name(id='None', ctx=ast.Load())))
            block_body.append(state_assign(state_name, -1))
        elif isinstance(stmt, ast.If):
            true_state = next_state
            false_state = next_state
            true_body = list(stmt.body)
            false_body = list(stmt.orelse)
            if len(true_body) == 1 and isinstance(true_body[0], ast.Return):
                true_state = -1
                true_body = [assign_name(ret_name, true_body[0].value or ast.Name(id='None', ctx=ast.Load()))]
            if len(false_body) == 1 and isinstance(false_body[0], ast.Return):
                false_state = -1
                false_body = [assign_name(ret_name, false_body[0].value or ast.Name(id='None', ctx=ast.Load()))]
            if not true_body:
                true_body = [ast.Pass()]
            if not false_body:
                false_body = [ast.Pass()]
            true_body.append(state_assign(state_name, true_state))
            false_body.append(state_assign(state_name, false_state))
            block_body.append(ast.If(test=stmt.test, body=true_body, orelse=false_body))
        else:
            block_body.append(stmt)
            block_body.append(state_assign(state_name, next_state))
        blocks.append((idx, block_body))
    random.shuffle(blocks)
    dispatch_body = []
    for state, block_body in blocks:
        dispatch_body.append(ast.If(test=state_test(state_name, state), body=block_body, orelse=[]))
    dispatch_body.append(ast.If(test=state_test(state_name, -1), body=[ast.Break()], orelse=[]))
    return [assign_name(state_name, make_num(0)), assign_name(ret_name, ast.Name(id='None', ctx=ast.Load())), ast.While(test=ast.Name(id='True', ctx=ast.Load()), body=dispatch_body, orelse=[]), ast.Return(value=make_name(ret_name, ast.Load()))]


class ControlFlowFlattener(ast.NodeTransformer):
    def __init__(self, max_blocks):
        self.max_blocks = max_blocks

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if has_unsafe_flatten_node(node):
            return node
        state_name = random_ident()
        ret_name = random_ident()
        new_body = flatten_function_body(node.body, state_name, ret_name, self.max_blocks)
        if new_body:
            node.body = new_body
        return node


def flatten_source_control_flow(source, max_blocks):
    tree = ast.parse(source)
    tree = ControlFlowFlattener(max_blocks).visit(tree)
    ast.fix_missing_locations(tree)
    return tree


def make_function_name_restore_stmt(func_name, attr_name):
    return ast.Assign(
        targets=[ast.Attribute(value=ast.Name(id=func_name, ctx=ast.Load()), attr=attr_name, ctx=ast.Store())],
        value=ast.Str(s=func_name)
    )


def make_function_name_restore_guard(func_name):
    return ast.TryExcept(
        body=[
            make_function_name_restore_stmt(func_name, '__name__'),
            make_function_name_restore_stmt(func_name, 'func_name'),
        ],
        handlers=[
            ast.ExceptHandler(type=None, name=None, body=[ast.Pass()])
        ],
        orelse=[]
    )


class FunctionNameRestoreInjector(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        return [node, make_function_name_restore_guard(node.name)]


def restore_function_object_names(tree):
    tree = FunctionNameRestoreInjector().visit(tree)
    ast.fix_missing_locations(tree)
    return tree


class SourceASTSmokeCollector(ast.NodeVisitor):
    def __init__(self):
        self.arguments = []
        self.docstrings = []

    def arg_layout(self, args, hidden=0):
        names = []
        visible = list(getattr(args, 'args', []) or [])
        if hidden:
            visible = visible[:-hidden]
        for arg in visible:
            names.append(arg.id if isinstance(arg, ast.Name) else str(arg))
        return (tuple(names), getattr(args, 'vararg', None), getattr(args, 'kwarg', None))

    def visit_Module(self, node):
        doc = source_docstring_node(node.body)
        self.docstrings.append(('module', doc.s if doc is not None else None))
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if getattr(node, '_mcp_source_synthetic', False):
            return
        self.arguments.append(('def', self.arg_layout(
            node.args, getattr(node, '_mcp_source_hidden_args', 0))))
        doc = source_docstring_node(node.body)
        self.docstrings.append(('def', doc.s if doc is not None else None))
        self.generic_visit(node)

    def visit_Lambda(self, node):
        self.arguments.append(('lambda', self.arg_layout(node.args)))
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        if getattr(node, '_mcp_source_synthetic', False):
            return
        doc = source_docstring_node(node.body)
        self.docstrings.append(('class', doc.s if doc is not None else None))
        self.generic_visit(node)


def source_ast_smoke_snapshot(tree):
    collector = SourceASTSmokeCollector()
    collector.visit(tree)
    return (tuple(collector.arguments), tuple(collector.docstrings))


def source_ast_smoke_validate(tree, baseline, stage):
    ast.fix_missing_locations(tree)
    current = source_ast_smoke_snapshot(tree)
    if current[0] != baseline[0]:
        raise ValueError('AST smoke failed at %s: function parameter layout changed' % stage)
    if current[1] != baseline[1]:
        raise ValueError('AST smoke failed at %s: module/function/class docstring changed' % stage)
    try:
        compile(tree, '<ast-smoke-%s>' % stage, 'exec', 0, True)
    except Exception as exc:
        raise ValueError('AST smoke failed at %s: %s' % (stage, exc))
    return tree


def build_source_tree(source, control_flow_flatten=False, control_flow_max_blocks=18,
                      source_linearize_calls=False,
                      source_schedule=False, source_schedule_max_exprs=4, source_schedule_window=8,
                      source_local_rename=False, source_local_rename_max=48,
                      source_dead_flow=False, source_dead_flow_blocks=1,
                      restore_function_names=False,
                      source_name_obfuscation=False, source_name_obfuscation_max=64,
                      source_string_split=False, source_string_split_parts=3,
                      source_string_xor=False, source_string_xor_mode='random',
                      source_string_xor_text='MCP_Shiled', source_string_xor_number=173,
                      source_string_xor_min_length=4, source_string_xor_limit=512,
                      source_string_xor_variants=4, source_string_xor_decoys=2,
                      source_string_xor_debug=False,
                      source_constant_pool=False, source_constant_pool_min=4, source_constant_pool_max=128,
                      source_constant_rewrite=False, source_constant_rewrite_limit=8,
                      source_exception_shell=False,
                      source_vm=False, source_vm_ratio=15, source_vm_min_ops=8,
                      source_vm_max_ops=160, source_vm_max_functions=8, source_vm_include=None,
                      source_vm_exclude=None, source_vm_allow_loops=False,
                      source_vm_debug=False, source_tuple_arg_decoys=0,
                      source_dotzero_relay=False, source_default_capsule=False,
                      source_identity_weave=False, source_identity_ratio=45,
                      source_identity_max=12, source_identity_variation=False,
                      source_decompiler_carriers=0,
                      source_exception_lattice=False,
                      source_class_body_trap=False,
                      source_vm_binary_payload=False,
                      source_reference_obf=False,
                      source_reference_obf_ratio=35,
                      source_reference_obf_exclude=None,
                      source_decoy_docstrings=False,
                      source_decoy_docstring_min=1024,
                      source_decoy_docstring_max=4096,
                      source_analysis=None,
                      source_flow_hardening=False,
                      source_internal_predicates=False,
                      source_internal_predicate_ratio=70,
                      source_hot_patterns=None,
                      source_vm_dialects=1,
                      source_vm_flow_constants=False,
                      source_vm_exception_trap_ratio=0):
    tree = ast.parse(source)
    source_string_xor_helpers = []
    smoke_baseline = source_ast_smoke_snapshot(tree)
    source_ast_smoke_validate(tree, smoke_baseline, 'parse')
    if source_flow_hardening or source_analysis is not None:
        if source_analysis is None:
            source_analysis = analyze_source_tree(
                tree, None, source_hot_patterns,
                source_internal_predicate_ratio)
        annotate_source_tree(tree, source_analysis)
    if source_name_obfuscation:
        protected_names = getattr(source_analysis, 'external_names', ())
        tree = obfuscate_source_definition_names(
            tree, source_name_obfuscation_max, protected_names)
        source_ast_smoke_validate(tree, smoke_baseline, 'name-obfuscation')
    # Hidden predicate parameters and every direct caller must be rewritten
    # while calls still have their original ``name(...)`` / ``self.name(...)``
    # shape.  Linearization turns those calls into temporary-bound callables,
    # after which the interprocedural matcher can no longer identify the
    # target and would leave a required hidden argument missing.
    if source_internal_predicates:
        tree, predicate_count = inject_internal_predicates(tree)
        if predicate_count:
            source_ast_smoke_validate(
                tree, smoke_baseline, 'internal-predicates')
    if source_constant_pool:
        literal_info = collect_source_literal_protection(tree)
        if not literal_info.has_global_introspection:
            tree = SourceConstantPool(source_constant_pool_min, source_constant_pool_max,
                                      literal_info.protected).visit(tree)
            source_ast_smoke_validate(tree, smoke_baseline, 'constant-pool')
    if source_string_split:
        literal_info = collect_source_literal_protection(tree)
        tree = SourceStringSplitter(source_string_split_parts, literal_info.protected).visit(tree)
        source_ast_smoke_validate(tree, smoke_baseline, 'string-split')
    if source_string_xor:
        literal_info = collect_source_literal_protection(tree)
        if not literal_info.has_global_introspection:
            tree, source_string_xor_helpers = obfuscate_source_strings_xor(
                tree, source_string_xor_mode, source_string_xor_text,
                source_string_xor_number, source_string_xor_min_length,
                source_string_xor_limit, literal_info.protected,
                source_string_xor_variants, source_string_xor_decoys,
                source_string_xor_debug)
            source_ast_smoke_validate(tree, smoke_baseline, 'string-xor')
    if source_constant_rewrite:
        tree = SourceLocalConstantRewrite(source_constant_rewrite_limit).visit(tree)
        source_ast_smoke_validate(tree, smoke_baseline, 'constant-rewrite')
    if source_exception_shell:
        tree = SourceExceptionShell().visit(tree)
        source_ast_smoke_validate(tree, smoke_baseline, 'exception-rewrite')
    if source_dead_flow:
        tree = inject_source_dead_flow(tree, source_dead_flow_blocks)
        source_ast_smoke_validate(tree, smoke_baseline, 'dead-flow')
    if source_local_rename:
        tree = rename_source_locals(tree, source_local_rename_max)
        source_ast_smoke_validate(tree, smoke_baseline, 'local-rename')
    if source_linearize_calls:
        tree = linearize_source_calls(tree)
        source_ast_smoke_validate(tree, smoke_baseline, 'linearize-calls')
    if source_schedule:
        tree = schedule_source_execution(tree, source_schedule_max_exprs, source_schedule_window)
        source_ast_smoke_validate(tree, smoke_baseline, 'schedule')
    if control_flow_flatten:
        tree = ControlFlowFlattener(control_flow_max_blocks).visit(tree)
        ast.fix_missing_locations(tree)
        source_ast_smoke_validate(tree, smoke_baseline, 'control-flow-flatten')
    if source_vm:
        tree, vm_count = virtualize_source_functions(
            tree, source_vm_ratio, source_vm_min_ops, source_vm_max_ops,
            source_vm_max_functions,
            source_vm_include, source_vm_exclude, source_vm_allow_loops,
            source_vm_debug, source_dotzero_relay,
            source_vm_binary_payload, source_reference_obf,
            source_vm_dialects, source_vm_flow_constants,
            source_vm_exception_trap_ratio)
        if vm_count:
            source_ast_smoke_validate(tree, smoke_baseline, 'source-vm')
    if source_reference_obf:
        tree, reference_count = obfuscate_source_references(
            tree, source_reference_obf_ratio,
            source_reference_obf_exclude,
            source_flow_hardening)
        if reference_count:
            source_ast_smoke_validate(
                tree, smoke_baseline, 'source-reference-obf')
    if source_identity_weave:
        tree, weave_count = weave_source_function_identities(
            tree, source_identity_ratio, source_identity_max,
            source_default_capsule,
            source_identity_variation)
        if weave_count:
            source_ast_smoke_validate(tree, smoke_baseline, 'source-identity-weave')
    if source_tuple_arg_decoys:
        tree, tuple_count = inject_tuple_argument_decoys(
            tree, source_tuple_arg_decoys)
        if tuple_count:
            source_ast_smoke_validate(tree, smoke_baseline, 'source-tuple-arg-decoys')
    if source_decompiler_carriers:
        tree, carrier_count = inject_source_decompiler_carriers(
            tree, source_decompiler_carriers,
            source_exception_lattice, source_class_body_trap,
            source_decoy_docstrings, source_decoy_docstring_min,
            source_decoy_docstring_max)
        if carrier_count:
            source_ast_smoke_validate(
                tree, smoke_baseline, 'source-decompiler-carriers')
    if restore_function_names:
        tree = restore_function_object_names(tree)
        source_ast_smoke_validate(tree, smoke_baseline, 'restore-function-names')
    if source_string_xor_helpers:
        tree = insert_source_string_xor_helpers(tree, source_string_xor_helpers)
        source_ast_smoke_validate(tree, smoke_baseline, 'string-xor-helpers')
    ast.fix_missing_locations(tree)
    return tree


def make_source_only_output(path, opts, source_linearize_calls=None, source_schedule=None, source_local_rename=None, source_dead_flow=None, control_flow_flatten=None,
                            source_name_obfuscation=None, source_string_split=None, source_string_xor=None, source_constant_pool=None,
                            source_constant_rewrite=None, source_exception_shell=None, source_parenthesis_noise=None,
                            source_comment_noise=None, source_vm=None,
                            source_tuple_arg_decoys=None, source_dotzero_relay=None,
                            source_default_capsule=None, source_identity_weave=None,
                            source_decompiler_carriers=None,
                            source_exception_lattice=None,
                            source_class_body_trap=None,
                            source_identity_variation=None,
                            source_reference_obf=None,
                            source_analysis=None,
                            source_flow_hardening=None,
                            source_internal_predicates=None):
    source = read_file(path)
    if source_linearize_calls is None:
        source_linearize_calls = opts.source_linearize_calls
    if source_schedule is None:
        source_schedule = opts.source_schedule
    if source_local_rename is None:
        source_local_rename = opts.source_local_rename
    if source_dead_flow is None:
        source_dead_flow = opts.source_dead_flow
    if control_flow_flatten is None:
        control_flow_flatten = opts.control_flow_flatten
    if source_name_obfuscation is None:
        source_name_obfuscation = opts.source_name_obfuscation
    if source_string_split is None:
        source_string_split = opts.source_string_split
    if source_string_xor is None:
        source_string_xor = opts.source_string_xor
    if source_constant_pool is None:
        source_constant_pool = opts.source_constant_pool
    if source_constant_rewrite is None:
        source_constant_rewrite = opts.source_constant_rewrite
    if source_exception_shell is None:
        source_exception_shell = opts.source_exception_shell
    if source_parenthesis_noise is None:
        source_parenthesis_noise = opts.source_parenthesis_noise
    if source_comment_noise is None:
        source_comment_noise = opts.source_comment_noise
    if source_vm is None:
        source_vm = opts.source_vm
    if source_tuple_arg_decoys is None:
        source_tuple_arg_decoys = opts.source_tuple_arg_decoys
    if source_dotzero_relay is None:
        source_dotzero_relay = opts.source_dotzero_relay
    if source_default_capsule is None:
        source_default_capsule = opts.source_default_capsule
    if source_identity_weave is None:
        source_identity_weave = opts.source_identity_weave
    if source_decompiler_carriers is None:
        source_decompiler_carriers = opts.source_decompiler_carriers
    if source_exception_lattice is None:
        source_exception_lattice = opts.source_exception_lattice
    if source_class_body_trap is None:
        source_class_body_trap = opts.source_class_body_trap
    if source_identity_variation is None:
        source_identity_variation = opts.source_identity_variation
    if source_reference_obf is None:
        source_reference_obf = opts.source_reference_obf
    if source_flow_hardening is None:
        source_flow_hardening = opts.source_flow_hardening
    if source_internal_predicates is None:
        source_internal_predicates = opts.source_internal_predicates
    if not (source_linearize_calls or source_schedule or control_flow_flatten or source_local_rename or source_dead_flow or
            source_name_obfuscation or source_string_split or source_constant_pool or
            source_string_xor or
            source_constant_rewrite or source_exception_shell or source_vm or
            source_reference_obf or
            source_flow_hardening or source_internal_predicates or
            source_tuple_arg_decoys or source_identity_weave or
            source_decompiler_carriers):
        return source
    tree = build_source_tree(source, control_flow_flatten, opts.control_flow_max_blocks,
                             source_linearize_calls,
                             source_schedule, opts.source_schedule_max_exprs, opts.source_schedule_window,
                             source_local_rename, opts.source_local_rename_max,
                             source_dead_flow, opts.source_dead_flow_blocks,
                             False, source_name_obfuscation, opts.source_name_obfuscation_max,
                             source_string_split, opts.source_string_split_parts,
                             source_string_xor, opts.source_string_xor_mode,
                             opts.source_string_xor_text, opts.source_string_xor_number,
                             opts.source_string_xor_min_length, opts.source_string_xor_limit,
                             opts.source_string_xor_variants, opts.source_string_xor_decoys,
                             opts.source_string_xor_debug,
                             source_constant_pool, opts.source_constant_pool_min, opts.source_constant_pool_max,
                             source_constant_rewrite, opts.source_constant_rewrite_limit,
                             source_exception_shell,
                             source_vm, opts.source_vm_ratio, opts.source_vm_min_ops,
                             opts.source_vm_max_ops, opts.source_vm_max_functions, opts.source_vm_include,
                             opts.source_vm_exclude, opts.source_vm_allow_loops,
                             opts.source_vm_debug, source_tuple_arg_decoys,
                             source_dotzero_relay, source_default_capsule,
                             source_identity_weave, opts.source_identity_ratio,
                             opts.source_identity_max, source_identity_variation,
                             source_decompiler_carriers,
                             source_exception_lattice,
                             source_class_body_trap,
                             False,
                             source_reference_obf,
                             opts.source_reference_obf_ratio,
                             opts.source_reference_obf_exclude,
                             opts.source_decoy_docstrings,
                             opts.source_decoy_docstring_min,
                             opts.source_decoy_docstring_max,
                             source_analysis,
                             source_flow_hardening,
                             source_internal_predicates,
                             opts.source_internal_predicate_ratio,
                             opts.source_hot_patterns,
                             opts.source_vm_dialects,
                             opts.source_vm_flow_constants,
                             opts.source_vm_exception_trap_ratio)
    rendered = render_source_tree(tree, source_parenthesis_noise)
    if source_comment_noise:
        rendered = add_source_comment_noise(rendered, opts.source_comment_noise_count)
    return obfuscate_reserved_generated_identifiers(rendered)


def compile_source(path, filename_mode, control_flow_flatten=False, control_flow_max_blocks=18,
                   source_linearize_calls=False,
                   source_schedule=False, source_schedule_max_exprs=4, source_schedule_window=8,
                   source_local_rename=False, source_local_rename_max=48,
                   source_dead_flow=False, source_dead_flow_blocks=1,
                   restore_function_names=False,
                   source_name_obfuscation=False, source_name_obfuscation_max=64,
                   source_string_split=False, source_string_split_parts=3,
                   source_string_xor=False, source_string_xor_mode='random',
                   source_string_xor_text='MCP_Shiled', source_string_xor_number=173,
                   source_string_xor_min_length=4, source_string_xor_limit=512,
                   source_string_xor_variants=4, source_string_xor_decoys=2,
                   source_string_xor_debug=False,
                   source_constant_pool=False, source_constant_pool_min=4, source_constant_pool_max=128,
                   source_constant_rewrite=False, source_constant_rewrite_limit=8,
                   source_exception_shell=False,
                   source_vm=False, source_vm_ratio=15, source_vm_min_ops=8,
                   source_vm_max_ops=160, source_vm_max_functions=8, source_vm_include=None,
                   source_vm_exclude=None, source_vm_allow_loops=False,
                   source_vm_debug=False, source_tuple_arg_decoys=0,
                   source_dotzero_relay=False, source_default_capsule=False,
                   source_identity_weave=False, source_identity_ratio=45,
                   source_identity_max=12, source_identity_variation=False,
                   source_decompiler_carriers=0,
                   source_exception_lattice=False,
                   source_class_body_trap=False,
                   source_reference_obf=False,
                   source_reference_obf_ratio=35,
                   source_reference_obf_exclude=None,
                   source_decoy_docstrings=False,
                   source_decoy_docstring_min=1024,
                   source_decoy_docstring_max=4096,
                   source_analysis=None,
                   source_flow_hardening=False,
                   source_internal_predicates=False,
                   source_internal_predicate_ratio=70,
                   source_hot_patterns=None,
                   source_vm_dialects=1,
                   source_vm_flow_constants=False,
                   source_vm_exception_trap_ratio=0):
    source = read_file(path)
    filename = path
    if filename_mode == 'mem':
        filename = '<mem>'
    elif filename_mode == 'module':
        filename = '<%s>' % os.path.basename(path).replace(' ', '_')
    filename = python_compile_filename(filename)
    if source_linearize_calls or source_schedule or control_flow_flatten or source_local_rename or source_dead_flow or restore_function_names or source_name_obfuscation or source_string_split or source_string_xor or source_constant_pool or source_constant_rewrite or source_exception_shell or source_vm or source_reference_obf or source_tuple_arg_decoys or source_identity_weave or source_decompiler_carriers or source_flow_hardening or source_internal_predicates:
        tree = build_source_tree(source, control_flow_flatten, control_flow_max_blocks,
                                 source_linearize_calls,
                                 source_schedule, source_schedule_max_exprs, source_schedule_window,
                                 source_local_rename, source_local_rename_max,
                                 source_dead_flow, source_dead_flow_blocks,
                                 restore_function_names,
                                 source_name_obfuscation, source_name_obfuscation_max,
                                 source_string_split, source_string_split_parts,
                                 source_string_xor, source_string_xor_mode,
                                 source_string_xor_text, source_string_xor_number,
                                 source_string_xor_min_length, source_string_xor_limit,
                                 source_string_xor_variants, source_string_xor_decoys,
                                 source_string_xor_debug,
                                 source_constant_pool, source_constant_pool_min, source_constant_pool_max,
                                 source_constant_rewrite, source_constant_rewrite_limit,
                                 source_exception_shell,
                                 source_vm, source_vm_ratio, source_vm_min_ops,
                                 source_vm_max_ops, source_vm_max_functions, source_vm_include,
                                 source_vm_exclude, source_vm_allow_loops,
                                 source_vm_debug, source_tuple_arg_decoys,
                                 source_dotzero_relay, source_default_capsule,
                                 source_identity_weave, source_identity_ratio,
                                 source_identity_max, source_identity_variation,
                                 source_decompiler_carriers,
                                 source_exception_lattice,
                                 source_class_body_trap,
                                 True,
                                 source_reference_obf,
                                 source_reference_obf_ratio,
                                 source_reference_obf_exclude,
                                 source_decoy_docstrings,
                                 source_decoy_docstring_min,
                                 source_decoy_docstring_max,
                                 source_analysis,
                                 source_flow_hardening,
                                 source_internal_predicates,
                                 source_internal_predicate_ratio,
                                 source_hot_patterns,
                                 source_vm_dialects,
                                 source_vm_flow_constants,
                                 source_vm_exception_trap_ratio)
        rendered = render_source_tree(tree, False)
        if '_mcp_' in rendered:
            rendered = obfuscate_reserved_generated_identifiers(rendered)
            return compile(rendered, filename, 'exec', 0, True)
        return compile(tree, filename, 'exec', 0, True)
    return compile(source, filename, 'exec', 0, True)
