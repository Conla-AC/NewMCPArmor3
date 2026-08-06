#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import ast
import os
import re
import shutil
import stat
import sys

from MCP_Armor_Src.netease import modmain_fuser as netease_modmain_fuser


DEFAULT_CONFIG_TEXT = '''# NetEase folder fuser config
# Run: py -2 netease_folder_fuser.py --config config.yml
# Or put this file as config.yml and run: py -2 netease_folder_fuser.py

# =========================
# 1. Folder / output
# =========================
input_dir: ./ScriptMod
output_dir: ./ScriptMod_obf_config
include_ui: true
keep_sources: true
full_integrate_py: false
target_side: both

# =========================
# 2. Recognition / binding
# Leave empty to auto-detect from modMain.py and RegisterSystem.
# server_systems/client_systems format: SystemName=Package.module.Class
# =========================
mod_name:
binding_name:
version:
namespace:
binding_class:
server_systems: []
client_systems: []

# =========================
# 3. Preset
# low / medium / high / experimental
# Manual values below override preset values.
# =========================
intensity: high
mcs_opmap_version: 1
server_mcs_opmap: false
client_mcs_opmap: false
mcs_op_override: []

# =========================
# 4. Basic payload / literals
# =========================
key_len: 64
split_literals: true
mask_key: true
noise_chunks: 48
bloat_lines: 0
bloat_kb: 0
bloat_style: strings
obfuscate_binding: true

# =========================
# 5. Inner layer: string encryption
# =========================
string_encrypt_modules: true
string_encrypt_payload: true
string_enc_zlib: true
string_enc_xor: true
string_enc_add: true
string_enc_reverse: true

# =========================
# 6. Inner layer: source/AST semantic obfuscation
# =========================
fold_string_consts: true
fold_number_consts: false
rewrite_boolops: true
flatten_control_flow: false
return_gate: false
exception_gate: false
call_perturb: false
exception_gate_rate: 0
call_perturb_rate: 0
statement_reorder: false
statement_reorder_rate: 30
statement_reorder_window: 4
inner_dataflow_noise: false
inner_dataflow_rate: 30
inner_dataflow_min: 1
inner_dataflow_max: 4
const_pool_strings: false
const_pool_numbers: false
call_dispatcher: false
call_dispatcher_rate: 8
fake_function_count: 0
flatten_control_flow_v2: false

# =========================
# 7. Inner layer: bytecode obfuscation
# Safer defaults are tuned for NetEase V1 opcode map.
# =========================
const_poison_payload:
const_poison_per_module:
const_poison_jitter:
dead_stop_tail:
jump_garbage_min:
jump_garbage_max:
fake_code_count:
bait_code_count:
metadata_poison:
aggressive_poison_stream:
cf_gate_min:
cf_gate_max:
cf_gate_count:
bytecode_trampoline: false
bytecode_trampoline_rate: 35
anti_decompile_traps: 0
jump_poison_blocks: 0
jump_poison_min: 8
jump_poison_max: 32
obf2_fake_layers: 0
obf2_fake_count: 0
obf2_fake_min: 120
obf2_fake_max: 900
inner_taunt_repeat: 1
inner_opcode_tunnel: false
inner_opcode_table:
double_code_wrap:
taunt_text:

# =========================
# 8. Outer layer: modMain noise
# =========================
outer_lambda_noise: true
outer_lambda_count: 1
outer_taunt_repeat: 3
outer_taunt_text: ShitArmor_DEOBF
outer_control_noise: true
outer_control_count: 2
outer_doc_lines: 8
outer_doc_min_bytes: 48
outer_doc_max_bytes: 112

# =========================
# 9. Debug / policy
# =========================
dump_payload_source: false
dump_obf_pyc: false
check_policy: true

# =========================
# 10. Quick risky switches
# These only force-enable selected features above.
# =========================
enable_fake_code: false
enable_flatten: false
enable_double_wrap: false
enable_aggressive_poison: false
'''


def read_file(path):
    with open(path, 'rb') as handle:
        return handle.read()


def write_file(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, 'wb') as handle:
        handle.write(data)


def parse_scalar(value):
    value = value.strip()
    if not value:
        return ''
    lower = value.lower()
    if lower in ('true', 'yes', 'y', 'on'):
        return True
    if lower in ('false', 'no', 'n', 'off'):
        return False
    if lower in ('null', 'none', '~'):
        return None
    if value in ('[]', ''):
        return []
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.startswith('[') and value.endswith(']'):
        body = value[1:-1].strip()
        if not body:
            return []
        return [parse_scalar(item.strip()) for item in body.split(',') if item.strip()]
    try:
        if value.startswith('0x') or value.startswith('0X'):
            return int(value, 16)
        return int(value)
    except Exception:
        return value


def read_simple_yaml(path):
    data = {}
    current_key = None
    for raw_line in read_file(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('-') and current_key:
            if not isinstance(data.get(current_key), list):
                data[current_key] = []
            data.setdefault(current_key, []).append(parse_scalar(line[1:].strip()))
            continue
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if not value:
            data[key] = None
            current_key = key
        else:
            data[key] = parse_scalar(value)
            current_key = key if isinstance(data[key], list) else None
    return data


def is_empty_config(value):
    return value is None or value == ''


def list_config(value):
    if is_empty_config(value):
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if not is_empty_config(item)]
    if isinstance(value, basestring):
        return [item.strip() for item in value.replace(',', ';').split(';') if item.strip()]
    return [str(value)]


def bool_config(config, key, default=False):
    value = config.get(key, default)
    if isinstance(value, basestring):
        return value.strip().lower() in ('1', 'true', 'yes', 'y', 'on')
    return bool(value)


def config_to_argv(config):
    input_dir = config.get('input_dir') or config.get('input')
    output_dir = config.get('output_dir') or config.get('output')
    if not input_dir or not output_dir:
        raise SystemExit('error: config.yml requires input_dir and output_dir')
    argv = [str(input_dir), str(output_dir)]
    target_side = config.get('target_side') or config.get('target') or config.get('side')
    if target_side:
        argv.extend(['--target-side', str(target_side)])
    if not bool_config(config, 'include_ui', True):
        argv.append('--no-ui')
    if bool_config(config, 'full_integrate_py', False):
        argv.append('--full-integrate-py')
    if not bool_config(config, 'keep_sources', True):
        argv.append('--strip-sources')
    if bool_config(config, 'dump_payload_source', False):
        argv.append('--dump-payload-source')
    if bool_config(config, 'dump_obf_pyc', False):
        argv.append('--dump-obf-pyc')
    argv.extend(['--intensity', str(config.get('intensity', 'medium'))])
    argv.extend(['--mcs-opmap-version', str(config.get('mcs_opmap_version', 1))])
    if bool_config(config, 'server_mcs_opmap', False):
        argv.append('--server-mcs-opmap')
    else:
        argv.append('--no-server-mcs-opmap')
    if bool_config(config, 'client_mcs_opmap', False):
        argv.append('--client-mcs-opmap')
    else:
        argv.append('--no-client-mcs-opmap')
    overrides = config.get('mcs_op_override', [])
    if isinstance(overrides, basestring):
        overrides = [item.strip() for item in overrides.replace(',', ';').split(';') if item.strip()]
    for item in overrides or []:
        argv.extend(['--mcs-op-override', str(item)])
    if bool_config(config, 'enable_double_wrap', False):
        argv.append('--enable-double-wrap')
    if bool_config(config, 'enable_flatten', False):
        argv.append('--enable-flatten')
    if bool_config(config, 'enable_aggressive_poison', False):
        argv.append('--enable-aggressive-poison')
    if bool_config(config, 'enable_fake_code', False):
        argv.append('--enable-fake-code')
    inner_opcode_table = config.get('inner_opcode_table')
    if inner_opcode_table:
        argv.extend(['--inner-opcode-table', str(inner_opcode_table)])
    if bool_config(config, 'shuffle_consts', False):
        argv.append('--shuffle-consts')
    if bool_config(config, 'shuffle_names', False):
        argv.append('--shuffle-names')
    if config.get('fake_name_count') not in (None, ''):
        argv.extend(['--fake-name-count', str(config.get('fake_name_count'))])
    if config.get('opcode_tunnel_decoys') not in (None, ''):
        argv.extend(['--opcode-tunnel-decoys', str(config.get('opcode_tunnel_decoys'))])
    if bool_config(config, 'opcode_tunnel_double_map', False):
        argv.append('--opcode-tunnel-double-map')
    if config.get('opcode_tunnel_stages') not in (None, ''):
        argv.extend(['--opcode-tunnel-stages', str(config.get('opcode_tunnel_stages'))])
    if bool_config(config, 'reference_obf', False):
        argv.append('--reference-obf')
    if config.get('reference_obf_rate') not in (None, ''):
        argv.extend(['--reference-obf-rate', str(config.get('reference_obf_rate'))])
    if config.get('fake_class_count') not in (None, ''):
        argv.extend(['--fake-class-count', str(config.get('fake_class_count'))])
    if bool_config(config, 'shuffle_varnames', False):
        argv.append('--shuffle-varnames')
    if config.get('payload_fragments') not in (None, ''):
        argv.extend(['--payload-fragments', str(config.get('payload_fragments'))])
    if bool_config(config, 'lifecycle_dispatcher', False):
        argv.append('--lifecycle-dispatcher')
    if config.get('fake_module_count') not in (None, ''):
        argv.extend(['--fake-module-count', str(config.get('fake_module_count'))])
    if bool_config(config, 'line_metadata_poison', False):
        argv.append('--line-metadata-poison')
    if config.get('stack_noise_rate') not in (None, ''):
        argv.extend(['--stack-noise-rate', str(config.get('stack_noise_rate'))])
    if config.get('extended_arg_noise_rate') not in (None, ''):
        argv.extend(['--extended-arg-noise-rate', str(config.get('extended_arg_noise_rate'))])
    if config.get('return_jump_gate_rate') not in (None, ''):
        argv.extend(['--return-jump-gate-rate', str(config.get('return_jump_gate_rate'))])
    if bool_config(config, 'depth_density', False):
        argv.append('--depth-density')
    if bool_config(config, 'per_code_opcode_table', False):
        argv.append('--per-code-opcode-table')
    return argv


def config_value(config, key, default=None):
    value = config.get(key, default)
    if is_empty_config(value):
        return default
    return value


def apply_config_overrides(fuser_args, config):
    string_keys = ('mod_name', 'binding_name', 'version', 'namespace', 'binding_class', 'taunt_text', 'bloat_style', 'inner_opcode_table')
    int_keys = (
        'key_len', 'noise_chunks', 'bloat_lines', 'bloat_kb',
        'const_poison_payload', 'const_poison_per_module', 'const_poison_jitter',
        'dead_stop_tail', 'jump_garbage_min', 'jump_garbage_max',
        'fake_code_count', 'bait_code_count', 'cf_gate_min', 'cf_gate_max', 'cf_gate_count', 'bytecode_trampoline_rate', 'anti_decompile_traps',
        'jump_poison_blocks', 'jump_poison_min', 'jump_poison_max',
        'obf2_fake_layers', 'obf2_fake_count', 'obf2_fake_min', 'obf2_fake_max', 'inner_taunt_repeat',
        'exception_gate_rate', 'call_perturb_rate',
        'statement_reorder_rate', 'statement_reorder_window',
        'inner_dataflow_rate', 'inner_dataflow_min', 'inner_dataflow_max', 'call_dispatcher_rate', 'fake_function_count',
        'fake_name_count', 'opcode_tunnel_decoys',
        'opcode_tunnel_stages', 'reference_obf_rate', 'fake_class_count',
        'payload_fragments', 'fake_module_count',
        'stack_noise_rate', 'extended_arg_noise_rate', 'return_jump_gate_rate',
        'outer_lambda_count', 'outer_taunt_repeat', 'outer_control_count', 'outer_doc_lines', 'outer_doc_min_bytes', 'outer_doc_max_bytes',
    )
    bool_keys = (
        'split_literals', 'mask_key', 'obfuscate_binding', 'outer_lambda_noise', 'outer_control_noise',
        'server_mcs_opmap', 'client_mcs_opmap',
        'string_encrypt_modules', 'string_encrypt_payload',
        'string_enc_zlib', 'string_enc_xor', 'string_enc_add', 'string_enc_reverse',
        'fold_string_consts', 'fold_number_consts', 'rewrite_boolops', 'flatten_control_flow',
        'return_gate', 'exception_gate', 'call_perturb', 'statement_reorder', 'inner_dataflow_noise',
        'const_pool_strings', 'const_pool_numbers', 'call_dispatcher', 'flatten_control_flow_v2',
        'inner_opcode_tunnel', 'shuffle_consts', 'shuffle_names', 'opcode_tunnel_double_map', 'reference_obf',
        'shuffle_varnames', 'lifecycle_dispatcher', 'line_metadata_poison',
        'depth_density', 'per_code_opcode_table',
        'metadata_poison', 'bytecode_trampoline',
        'aggressive_poison_stream', 'double_code_wrap', 'check_policy',
    )
    for key in string_keys:
        value = config_value(config, key)
        if value is not None:
            setattr(fuser_args, key, str(value))
    value = config_value(config, 'outer_taunt_text')
    if value is not None:
        setattr(fuser_args, 'outer_taunt_text', str(value))
    value = config_value(config, 'target_side')
    if value is not None:
        value = str(value).strip().lower()
        if value not in ('both', 'client', 'server'):
            raise SystemExit('error: target_side must be both/client/server')
        setattr(fuser_args, 'target_side', value)
    for key in int_keys:
        value = config_value(config, key)
        if value is not None:
            setattr(fuser_args, key, int(value))
    for key in bool_keys:
        if key in config and not is_empty_config(config.get(key)):
            setattr(fuser_args, key, bool_config(config, key, getattr(fuser_args, key, False)))
    return fuser_args


def copy_tree(src, dst, keep_sources=True, skip_sources=None):
    skip_sources = set(os.path.abspath(path) for path in (skip_sources or ()))
    if os.path.isdir(dst):
        def onerror(func, path, _exc):
            try:
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
                func(path)
            except Exception:
                raise
        shutil.rmtree(dst, onerror=onerror)
    os.makedirs(dst)
    for base, dirs, files in os.walk(src):
        rel = os.path.relpath(base, src)
        out_base = dst if rel == '.' else os.path.join(dst, rel)
        if not os.path.isdir(out_base):
            os.makedirs(out_base)
        for filename in files:
            lower = filename.lower()
            if lower.endswith('.pyc') or filename == '_payload_source.py':
                continue
            src_path = os.path.abspath(os.path.join(base, filename))
            if lower.endswith('.py') and (not keep_sources or src_path in skip_sources):
                continue
            shutil.copyfile(src_path, os.path.join(out_base, filename))
    write_file(os.path.join(dst, '__init__.py'), '')


def literal_value(node):
    if isinstance(node, ast.Str):
        return node.s
    return None


def load_config_returns(root):
    result = {}
    path = os.path.join(root, 'config.py')
    if not os.path.isfile(path):
        return result
    try:
        tree = ast.parse(read_file(path), path)
    except Exception:
        return result
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.body:
            continue
        for item in node.body:
            if isinstance(item, ast.Return):
                value = literal_value(item.value)
                if value is not None:
                    result[node.name] = value
                    break
    return result


def eval_register_arg(node, config):
    value = literal_value(node)
    if value is not None:
        return value
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            return config.get(func.attr)
        if isinstance(func, ast.Name):
            return config.get(func.id)
    return None


def infer_from_modmain(root, target_side='both'):
    target_side = (target_side or 'both').strip().lower()
    path = os.path.join(root, 'modMain.py')
    if not os.path.isfile(path):
        raise SystemExit('error: cannot find modMain.py in %s' % root)
    source = read_file(path)
    config = load_config_returns(root)
    tree = ast.parse(source, path)
    mod_name = os.path.basename(os.path.abspath(root))
    version = '0.0.1'
    server_specs = []
    client_specs = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for deco in node.decorator_list:
                if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute) and deco.func.attr == 'Binding':
                    for kw in deco.keywords:
                        if kw.arg == 'name':
                            mod_name = literal_value(kw.value) or mod_name
                        elif kw.arg == 'version':
                            version = literal_value(kw.value) or version
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'RegisterSystem':
            if len(node.args) < 3:
                continue
            namespace = eval_register_arg(node.args[0], config)
            system_name = eval_register_arg(node.args[1], config)
            class_path = eval_register_arg(node.args[2], config)
            if not system_name or not class_path:
                continue
            api_text = ''
            if isinstance(node.func.value, ast.Name):
                api_text = node.func.value.id.lower()
            elif isinstance(node.func.value, ast.Attribute):
                api_text = node.func.value.attr.lower()
            if 'client' in api_text or '.client.' in class_path.lower() or 'clientsystem' in class_path.lower() or '.uiscript.' in class_path.lower():
                client_specs.append((system_name, class_path))
            else:
                server_specs.append((system_name, class_path))
            if namespace:
                mod_name = namespace
    namespace = os.path.basename(os.path.abspath(root))
    if not server_specs and os.path.isfile(os.path.join(root, 'NeteaseServerSystem.py')):
        server_specs.append(('NeteaseServerSystem', namespace + '.NeteaseServerSystem.NeteaseServerSystem'))
    if not client_specs and os.path.isfile(os.path.join(root, 'NeteaseClientSystem.py')):
        client_specs.append(('NeteaseClientSystem', namespace + '.NeteaseClientSystem.NeteaseClientSystem'))
    return mod_name, version, dedupe(server_specs), dedupe(client_specs)


def dedupe(items):
    seen = set()
    result = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def namespace_from_folder(path):
    return os.path.basename(os.path.abspath(path))


def source_path_for_module(root, namespace, module_name):
    if not module_name.startswith(namespace + '.'):
        return None
    rel = module_name[len(namespace) + 1:].replace('.', os.sep) + '.py'
    return os.path.join(root, rel)


def remove_packed_system_sources(output_dir, namespace, server_specs, client_specs):
    removed = []
    seen = set()
    for _system_name, class_path in list(server_specs) + list(client_specs):
        module_name = class_path.rsplit('.', 1)[0]
        path = source_path_for_module(output_dir, namespace, module_name)
        if not path or path in seen:
            continue
        seen.add(path)
        if os.path.isfile(path):
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
            os.remove(path)
            removed.append(path)
    return removed


def packed_system_source_paths(root, namespace, server_specs, client_specs):
    paths = []
    seen = set()
    for _system_name, class_path in list(server_specs) + list(client_specs):
        module_name = class_path.rsplit('.', 1)[0]
        path = source_path_for_module(root, namespace, module_name)
        if path and path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def packed_source_paths_for_target(root, namespace, server_specs, client_specs, target_side, full_integrate_py=False, include_ui=True):
    target_side = (target_side or 'both').strip().lower()
    if full_integrate_py:
        if target_side == 'both':
            paths = []
            for base, _dirs, files in os.walk(root):
                for filename in files:
                    if filename.lower().endswith('.py'):
                        paths.append(os.path.abspath(os.path.join(base, filename)))
            return paths
        modules, _aliases = netease_modmain_fuser.scan_package_sources(root, namespace, include_ui)
        specs = client_specs if target_side == 'client' else server_specs
        seed_modules = [netease_modmain_fuser.module_path_from_class(class_path) for _system_name, class_path in specs]
        selected = netease_modmain_fuser.ordered_modules(
            modules, netease_modmain_fuser.dependency_closure(modules, seed_modules, namespace), namespace
        )
        paths = []
        for module_name in selected:
            path = source_path_for_module(root, namespace, module_name)
            if path:
                paths.append(os.path.abspath(path))
        return paths
    if target_side == 'both':
        return packed_system_source_paths(root, namespace, server_specs, client_specs)
    modules, _aliases = netease_modmain_fuser.scan_package_sources(root, namespace, include_ui)
    specs = client_specs if target_side == 'client' else server_specs
    seed_modules = [netease_modmain_fuser.module_path_from_class(class_path) for _system_name, class_path in specs]
    selected = netease_modmain_fuser.ordered_modules(modules, seed_modules, namespace)
    paths = []
    for module_name in selected:
        path = source_path_for_module(root, namespace, module_name)
        if path:
            paths.append(os.path.abspath(path))
    return paths


def parse_system_overrides(items):
    specs = []
    for item in items:
        if '=' not in item:
            raise SystemExit('error: system override expects NAME=module.Class, got %s' % item)
        name, class_path = item.split('=', 1)
        name = name.strip()
        class_path = class_path.strip()
        if name and class_path:
            specs.append((name, class_path))
    if not specs:
        raise SystemExit('error: empty system override')
    return specs


def intensity_settings(level):
    if level == 'low':
        return dict(
            const_poison_payload=4,
            const_poison_per_module=12,
            const_poison_jitter=2,
            dead_stop_tail=1,
            jump_garbage_min=0,
            jump_garbage_max=0,
            fake_code_count=0,
            bait_code_count=0,
            metadata_poison=False,
            aggressive_poison_stream=False,
            cf_gate_min=0,
            cf_gate_max=0,
            cf_gate_count=1,
            jump_poison_blocks=0,
            jump_poison_min=8,
            jump_poison_max=32,
            obf2_fake_layers=0,
            obf2_fake_count=0,
            obf2_fake_min=120,
            obf2_fake_max=900,
            inner_taunt_repeat=1,
            mask_key=False,
            double_code_wrap=False,
            fold_string_consts=False,
            fold_number_consts=False,
            rewrite_boolops=False,
            flatten_control_flow=False,
            return_gate=False,
            exception_gate=False,
            call_perturb=False,
            exception_gate_rate=0,
            call_perturb_rate=0,
            statement_reorder=False,
            statement_reorder_rate=15,
            statement_reorder_window=3,
            inner_dataflow_noise=False,
            inner_dataflow_rate=15,
            inner_dataflow_min=1,
            inner_dataflow_max=2,
            const_pool_strings=False,
            const_pool_numbers=False,
            call_dispatcher=False,
            call_dispatcher_rate=5,
            fake_function_count=0,
            flatten_control_flow_v2=False,
            inner_opcode_tunnel=False,
            shuffle_consts=False,
            shuffle_names=False,
            fake_name_count=0,
            opcode_tunnel_decoys=0,
            opcode_tunnel_double_map=False,
            opcode_tunnel_stages=1,
            reference_obf=False,
            reference_obf_rate=5,
            fake_class_count=0,
            shuffle_varnames=False,
            payload_fragments=0,
            lifecycle_dispatcher=False,
            fake_module_count=0,
            line_metadata_poison=False,
            stack_noise_rate=0,
            extended_arg_noise_rate=0,
            return_jump_gate_rate=0,
            depth_density=False,
            per_code_opcode_table=False,
        )
    if level == 'high':
        return dict(
            const_poison_payload=32,
            const_poison_per_module=96,
            const_poison_jitter=12,
            dead_stop_tail=0,
            jump_garbage_min=8,
            jump_garbage_max=32,
            fake_code_count=0,
            bait_code_count=0,
            metadata_poison=False,
            aggressive_poison_stream=False,
            cf_gate_min=0,
            cf_gate_max=0,
            cf_gate_count=1,
            jump_poison_blocks=2,
            jump_poison_min=8,
            jump_poison_max=24,
            obf2_fake_layers=1,
            obf2_fake_count=1,
            obf2_fake_min=80,
            obf2_fake_max=260,
            inner_taunt_repeat=3,
            mask_key=True,
            double_code_wrap=False,
            fold_string_consts=True,
            fold_number_consts=True,
            rewrite_boolops=True,
            flatten_control_flow=False,
            return_gate=False,
            exception_gate=False,
            call_perturb=False,
            exception_gate_rate=0,
            call_perturb_rate=0,
            statement_reorder=True,
            statement_reorder_rate=25,
            statement_reorder_window=4,
            inner_dataflow_noise=True,
            inner_dataflow_rate=20,
            inner_dataflow_min=1,
            inner_dataflow_max=3,
            const_pool_strings=True,
            const_pool_numbers=False,
            call_dispatcher=True,
            call_dispatcher_rate=6,
            fake_function_count=2,
            flatten_control_flow_v2=False,
            inner_opcode_tunnel=False,
            shuffle_consts=True,
            shuffle_names=True,
            fake_name_count=6,
            opcode_tunnel_decoys=1,
            opcode_tunnel_double_map=False,
            opcode_tunnel_stages=2,
            reference_obf=True,
            reference_obf_rate=8,
            fake_class_count=2,
            shuffle_varnames=True,
            payload_fragments=4,
            lifecycle_dispatcher=True,
            fake_module_count=1,
            line_metadata_poison=False,
            stack_noise_rate=4,
            extended_arg_noise_rate=0,
            return_jump_gate_rate=8,
            depth_density=False,
            per_code_opcode_table=False,
        )
    if level == 'experimental':
        return dict(
            const_poison_payload=34,
            const_poison_per_module=88,
            const_poison_jitter=12,
            dead_stop_tail=1,
            jump_garbage_min=20,
            jump_garbage_max=72,
            fake_code_count=2,
            bait_code_count=4,
            metadata_poison=True,
            aggressive_poison_stream=True,
            cf_gate_min=20,
            cf_gate_max=64,
            cf_gate_count=2,
            jump_poison_blocks=5,
            jump_poison_min=16,
            jump_poison_max=56,
            obf2_fake_layers=2,
            obf2_fake_count=2,
            obf2_fake_min=120,
            obf2_fake_max=520,
            inner_taunt_repeat=6,
            mask_key=True,
            double_code_wrap=True,
            fold_string_consts=True,
            fold_number_consts=True,
            rewrite_boolops=True,
            flatten_control_flow=True,
            return_gate=True,
            exception_gate=True,
            call_perturb=True,
            exception_gate_rate=14,
            call_perturb_rate=9,
            statement_reorder=True,
            statement_reorder_rate=45,
            statement_reorder_window=6,
            inner_dataflow_noise=True,
            inner_dataflow_rate=45,
            inner_dataflow_min=2,
            inner_dataflow_max=6,
            const_pool_strings=True,
            const_pool_numbers=True,
            call_dispatcher=True,
            call_dispatcher_rate=12,
            fake_function_count=6,
            flatten_control_flow_v2=True,
            inner_opcode_tunnel=True,
            shuffle_consts=True,
            shuffle_names=True,
            fake_name_count=16,
            opcode_tunnel_decoys=4,
            opcode_tunnel_double_map=True,
            opcode_tunnel_stages=3,
            reference_obf=True,
            reference_obf_rate=14,
            fake_class_count=8,
            shuffle_varnames=True,
            payload_fragments=12,
            lifecycle_dispatcher=True,
            fake_module_count=4,
            line_metadata_poison=True,
            stack_noise_rate=10,
            extended_arg_noise_rate=4,
            return_jump_gate_rate=18,
            depth_density=True,
            per_code_opcode_table=True,
        )
    return dict(
        const_poison_payload=12,
        const_poison_per_module=36,
        const_poison_jitter=6,
        dead_stop_tail=1,
        jump_garbage_min=8,
        jump_garbage_max=32,
        fake_code_count=2,
        bait_code_count=2,
        metadata_poison=False,
        aggressive_poison_stream=False,
        cf_gate_min=0,
        cf_gate_max=0,
        cf_gate_count=1,
        jump_poison_blocks=1,
        jump_poison_min=8,
        jump_poison_max=24,
        obf2_fake_layers=1,
        obf2_fake_count=1,
        obf2_fake_min=80,
        obf2_fake_max=240,
        inner_taunt_repeat=2,
        mask_key=True,
        double_code_wrap=False,
        fold_string_consts=True,
        fold_number_consts=False,
        rewrite_boolops=True,
        flatten_control_flow=False,
        return_gate=False,
        exception_gate=False,
        call_perturb=False,
        exception_gate_rate=0,
        call_perturb_rate=0,
        statement_reorder=True,
        statement_reorder_rate=20,
        statement_reorder_window=4,
        inner_dataflow_noise=True,
        inner_dataflow_rate=18,
        inner_dataflow_min=1,
        inner_dataflow_max=3,
        const_pool_strings=False,
        const_pool_numbers=False,
        call_dispatcher=False,
        call_dispatcher_rate=6,
        fake_function_count=1,
        flatten_control_flow_v2=False,
        inner_opcode_tunnel=False,
        shuffle_consts=False,
        shuffle_names=False,
        fake_name_count=0,
        opcode_tunnel_decoys=0,
        opcode_tunnel_double_map=False,
        opcode_tunnel_stages=1,
        reference_obf=False,
        reference_obf_rate=6,
        fake_class_count=0,
        shuffle_varnames=False,
        payload_fragments=0,
        lifecycle_dispatcher=False,
        fake_module_count=0,
        line_metadata_poison=False,
        stack_noise_rate=0,
        extended_arg_noise_rate=0,
        return_jump_gate_rate=0,
        depth_density=False,
        per_code_opcode_table=False,
    )


def build_args(input_dir, output_dir, include_ui, dump_payload, op_overrides=None, opmap_version=1, intensity='medium', dump_obf_pyc=False, enable_double_wrap=False, enable_flatten=False, enable_aggressive=False, enable_fake_code=False, full_integrate_py=False, config=None):
    config = config or {}
    namespace = namespace_from_folder(input_dir)
    target_side = str(config_value(config, 'target_side', 'both')).strip().lower()
    if target_side not in ('both', 'client', 'server'):
        raise SystemExit('error: target_side must be both/client/server')
    mod_name, version, server_specs, client_specs = infer_from_modmain(input_dir, target_side)
    namespace = str(config_value(config, 'namespace', namespace))
    mod_name = str(config_value(config, 'mod_name', mod_name))
    version = str(config_value(config, 'version', version))
    server_override = list_config(config.get('server_systems'))
    client_override = list_config(config.get('client_systems'))
    if server_override:
        server_specs = parse_system_overrides(server_override)
    if client_override:
        client_specs = parse_system_overrides(client_override)
    primary_server = server_specs[0] if server_specs else ('', '')
    primary_client = client_specs[0] if client_specs else ('', '')
    preset = intensity_settings(intensity)
    if enable_double_wrap:
        preset['double_code_wrap'] = True
    if enable_flatten:
        preset['flatten_control_flow'] = True
    if enable_aggressive:
        preset['aggressive_poison_stream'] = True
    if enable_fake_code:
        preset['fake_code_count'] = max(preset.get('fake_code_count', 0), 4)
        preset['bait_code_count'] = max(preset.get('bait_code_count', 0), 8)
    args = argparse.Namespace(
        output=os.path.join(output_dir, 'modMain.py'),
        mod_name=mod_name,
        binding_name=str(config_value(config, 'binding_name', namespace)),
        version=version,
        namespace=namespace,
        binding_class=str(config_value(config, 'binding_class', namespace)),
        server_system=primary_server[0],
        server_class=primary_server[1],
        extra_server_system=['%s=%s' % item for item in server_specs[1:]],
        client_system=primary_client[0],
        client_class=primary_client[1],
        extra_client_system=['%s=%s' % item for item in client_specs[1:]],
        script_root=input_dir,
        include_ui=include_ui,
        cipher=str(config_value(config, 'cipher', 'xor')),
        chacha_level=int(config_value(config, 'chacha_level', 8)),
        dump_payload_source=os.path.join(output_dir, '_payload_source.py') if dump_payload else None,
        dump_obf_pyc=os.path.join(output_dir, '_payload_obf_cpython.pyc') if dump_obf_pyc else None,
        precompiled_payload=None,
        no_dependency_closure=True,
        full_integrate_py=full_integrate_py,
        target_side=target_side,
        mcs_opmap_version=opmap_version,
        server_mcs_opmap=False,
        client_mcs_opmap=False,
        mcs_op_override=op_overrides or [],
        ladder_level=0,
        key_len=64,
        split_literals=True,
        string_encrypt_modules=True,
        string_encrypt_payload=True,
        string_enc_zlib=True,
        string_enc_xor=True,
        string_enc_add=True,
        string_enc_reverse=True,
        noise_chunks=48,
        bloat_lines=0,
        bloat_kb=0,
        bloat_style='strings',
        const_poison_payload=preset['const_poison_payload'],
        const_poison_per_module=preset['const_poison_per_module'],
        const_poison_jitter=preset['const_poison_jitter'],
        dead_stop_tail=preset['dead_stop_tail'],
        jump_garbage_min=preset['jump_garbage_min'],
        jump_garbage_max=preset['jump_garbage_max'],
        fake_code_count=preset['fake_code_count'],
        bait_code_count=preset['bait_code_count'],
        metadata_poison=preset['metadata_poison'],
        aggressive_poison_stream=preset['aggressive_poison_stream'],
        cf_gate_min=preset['cf_gate_min'],
        cf_gate_max=preset['cf_gate_max'],
        cf_gate_count=preset['cf_gate_count'],
        bytecode_trampoline=False,
        bytecode_trampoline_rate=35,
        anti_decompile_traps=0,
        jump_poison_blocks=preset['jump_poison_blocks'],
        jump_poison_min=preset['jump_poison_min'],
        jump_poison_max=preset['jump_poison_max'],
        obf2_fake_layers=preset['obf2_fake_layers'],
        obf2_fake_count=preset['obf2_fake_count'],
        obf2_fake_min=preset['obf2_fake_min'],
        obf2_fake_max=preset['obf2_fake_max'],
        inner_taunt_repeat=preset['inner_taunt_repeat'],
        mask_key=preset['mask_key'],
        double_code_wrap=preset['double_code_wrap'],
        fold_string_consts=preset['fold_string_consts'],
        fold_number_consts=preset['fold_number_consts'],
        rewrite_boolops=preset['rewrite_boolops'],
        flatten_control_flow=preset['flatten_control_flow'],
        return_gate=preset['return_gate'],
        exception_gate=preset['exception_gate'],
        call_perturb=preset['call_perturb'],
        exception_gate_rate=preset['exception_gate_rate'],
        call_perturb_rate=preset['call_perturb_rate'],
        statement_reorder=preset['statement_reorder'],
        statement_reorder_rate=preset['statement_reorder_rate'],
        statement_reorder_window=preset['statement_reorder_window'],
        inner_dataflow_noise=preset['inner_dataflow_noise'],
        inner_dataflow_rate=preset['inner_dataflow_rate'],
        inner_dataflow_min=preset['inner_dataflow_min'],
        inner_dataflow_max=preset['inner_dataflow_max'],
        const_pool_strings=preset['const_pool_strings'],
        const_pool_numbers=preset['const_pool_numbers'],
        call_dispatcher=preset['call_dispatcher'],
        call_dispatcher_rate=preset['call_dispatcher_rate'],
        fake_function_count=preset['fake_function_count'],
        flatten_control_flow_v2=preset['flatten_control_flow_v2'],
        inner_opcode_tunnel=preset['inner_opcode_tunnel'],
        inner_opcode_table=None,
        shuffle_consts=preset['shuffle_consts'],
        shuffle_names=preset['shuffle_names'],
        fake_name_count=preset['fake_name_count'],
        opcode_tunnel_decoys=preset['opcode_tunnel_decoys'],
        opcode_tunnel_double_map=preset['opcode_tunnel_double_map'],
        opcode_tunnel_stages=preset['opcode_tunnel_stages'],
        reference_obf=preset['reference_obf'],
        reference_obf_rate=preset['reference_obf_rate'],
        fake_class_count=preset['fake_class_count'],
        shuffle_varnames=preset['shuffle_varnames'],
        payload_fragments=preset['payload_fragments'],
        lifecycle_dispatcher=preset['lifecycle_dispatcher'],
        fake_module_count=preset['fake_module_count'],
        line_metadata_poison=preset['line_metadata_poison'],
        stack_noise_rate=preset['stack_noise_rate'],
        extended_arg_noise_rate=preset['extended_arg_noise_rate'],
        return_jump_gate_rate=preset['return_jump_gate_rate'],
        depth_density=preset['depth_density'],
        per_code_opcode_table=preset['per_code_opcode_table'],
        taunt_text=netease_modmain_fuser.DEFAULT_TAUNT_TEXT,
        outer_taunt_text=netease_modmain_fuser.DEFAULT_OUTER_TAUNT_TEXT,
        outer_lambda_noise=True,
        outer_lambda_count=1,
        outer_taunt_repeat=3,
        outer_control_noise=True,
        outer_control_count=2,
        outer_doc_lines=8,
        outer_doc_min_bytes=48,
        outer_doc_max_bytes=112,
        check_policy=True,
        netease_max=False,
        obfuscate_binding=True,
    )
    apply_config_overrides(args, config)
    return args, server_specs, client_specs


def main(argv=None):
    if argv is None:
        argv = [] if len(sys.argv) <= 1 else sys.argv[1:]
    if '--init-config' in argv:
        index = argv.index('--init-config')
        path = 'config.yml'
        if index + 1 < len(argv) and not argv[index + 1].startswith('-'):
            path = argv[index + 1]
        if os.path.exists(path):
            raise SystemExit('error: %s already exists' % path)
        write_file(path, DEFAULT_CONFIG_TEXT)
        print('wrote %s' % os.path.abspath(path))
        return
    config = {}
    if not argv or argv[0] == '--config':
        config_path = 'config.yml'
        if argv and argv[0] == '--config':
            if len(argv) < 2:
                raise SystemExit('error: --config requires a yml path')
            config_path = argv[1]
        if not os.path.isfile(config_path):
            raise SystemExit('error: cannot find %s; run --init-config first' % config_path)
        config = read_simple_yaml(config_path)
        argv = config_to_argv(config)
    parser = argparse.ArgumentParser(description='One-click folder input/output NetEase modMain fuser.')
    parser.add_argument('input_dir')
    parser.add_argument('output_dir')
    parser.add_argument('--target-side', choices=('both', 'client', 'server'), default='both', help='pack both sides, client only, or server only')
    parser.add_argument('--include-ui', action='store_true', default=True, help='pack UI scripts too; default on for folder mode')
    parser.add_argument('--no-ui', action='store_false', dest='include_ui')
    parser.add_argument('--strip-sources', action='store_true', help='strip original .py files; default keeps normal dependency files')
    parser.add_argument('--full-integrate-py', action='store_true', help='pack all package .py files and output only __init__.py + modMain.py')
    parser.add_argument('--intensity', choices=('low', 'medium', 'high', 'experimental'), default='medium', help='obfuscation intensity preset')
    parser.add_argument('--mcs-opmap-version', type=int, default=2, help='MCS opcode map version')
    parser.add_argument('--server-mcs-opmap', action='store_true', help='enable MCS opcode remap for server modules')
    parser.add_argument('--no-server-mcs-opmap', action='store_false', dest='server_mcs_opmap', help='disable MCS opcode remap for server modules')
    parser.add_argument('--client-mcs-opmap', action='store_true', help='enable MCS opcode remap for client modules')
    parser.add_argument('--no-client-mcs-opmap', action='store_false', dest='client_mcs_opmap', help='disable MCS opcode remap for client modules')
    parser.add_argument('--mcs-op-override', action='append', default=[], help='override opcode mapping, e.g. POP_JUMP_IF_TRUE=0x40')
    parser.add_argument('--dump-payload-source', action='store_true')
    parser.add_argument('--dump-obf-pyc', action='store_true', help='also write decrypted/obfuscated CPython pyc for un6 tests')
    parser.add_argument('--enable-double-wrap', action='store_true', help='manually enable risky double code wrapper')
    parser.add_argument('--enable-flatten', action='store_true', help='manually enable risky function control-flow flattening')
    parser.add_argument('--enable-aggressive-poison', action='store_true', help='manually enable risky aggressive skipped opcode stream')
    parser.add_argument('--enable-fake-code', action='store_true', help='manually enable risky fake/bait code objects')
    parser.add_argument('--jump-poison-blocks', type=int, default=None, help='insert JUMP_FORWARD-skipped poison blocks per code object')
    parser.add_argument('--jump-poison-min', type=int, default=None, help='minimum bytes per skipped poison block')
    parser.add_argument('--jump-poison-max', type=int, default=None, help='maximum bytes per skipped poison block')
    parser.add_argument('--obf2-fake-layers', type=int, default=None, help='append obf_2-style fake nested code-object layers')
    parser.add_argument('--obf2-fake-count', type=int, default=None, help='number of obf_2-style fake code objects per code object')
    parser.add_argument('--obf2-fake-min', type=int, default=None, help='minimum byte length per obf_2 fake stream')
    parser.add_argument('--obf2-fake-max', type=int, default=None, help='maximum byte length per obf_2 fake stream')
    parser.add_argument('--inner-taunt-repeat', type=int, default=None, help='repeat taunt text inside inner constants and fake co_names')
    parser.add_argument('--statement-reorder', action='store_true', help='safely reorder independent simple statements')
    parser.add_argument('--statement-reorder-rate', type=int, default=None, help='percentage of eligible reorder windows')
    parser.add_argument('--statement-reorder-window', type=int, default=None, help='maximum reorder window size')
    parser.add_argument('--inner-dataflow-noise', action='store_true', help='inject harmless dataflow noise into real function bodies')
    parser.add_argument('--inner-dataflow-rate', type=int, default=None, help='percentage of statements preceded by dataflow noise')
    parser.add_argument('--inner-dataflow-min', type=int, default=None, help='minimum dataflow noise statements per block')
    parser.add_argument('--inner-dataflow-max', type=int, default=None, help='maximum dataflow noise statements per block')
    parser.add_argument('--const-pool-strings', action='store_true', help='virtualize string constants through a tuple pool')
    parser.add_argument('--const-pool-numbers', action='store_true', help='virtualize integer constants through a tuple pool')
    parser.add_argument('--call-dispatcher', action='store_true', help='wrap eligible calls through a local dispatcher expression')
    parser.add_argument('--call-dispatcher-rate', type=int, default=None, help='percentage of eligible calls to dispatch')
    parser.add_argument('--fake-function-count', type=int, default=None, help='append fake module-level function forest')
    parser.add_argument('--flatten-control-flow-v2', action='store_true', help='enable shuffled control-flow flattening with decoy states')
    parser.add_argument('--inner-opcode-tunnel', action='store_true', help='experimental double inner opcode-map wrapper')
    parser.add_argument('--inner-opcode-table', default=None, help='custom std->custom opcode table path for inner opcode tunnel')
    parser.add_argument('--shuffle-consts', action='store_true', help='shuffle recursive co_consts indexes')
    parser.add_argument('--shuffle-names', action='store_true', help='shuffle recursive co_names indexes')
    parser.add_argument('--fake-name-count', type=int, default=None, help='append fake co_names before name shuffle')
    parser.add_argument('--opcode-tunnel-decoys', type=int, default=None, help='add encrypted decoy blobs inside opcode tunnel')
    parser.add_argument('--opcode-tunnel-double-map', action='store_true', help='use custom->mid->runtime opcode table inside tunnel')
    parser.add_argument('--opcode-tunnel-stages', type=int, default=None, help='split opcode tunnel loader into 1..3 runtime stages')
    parser.add_argument('--reference-obf', action='store_true', help='rewrite eligible obj.attr calls through getattr split strings')
    parser.add_argument('--reference-obf-rate', type=int, default=None, help='percentage of eligible attribute calls rewritten')
    parser.add_argument('--fake-class-count', type=int, default=None, help='append fake class forest into inner sources')
    parser.add_argument('--shuffle-varnames', action='store_true', help='shuffle non-argument fast local indexes')
    parser.add_argument('--payload-fragments', type=int, default=None, help='split outer payload literal into fragments')
    parser.add_argument('--lifecycle-dispatcher', action='store_true', help='route lifecycle calls through getattr dispatcher')
    parser.add_argument('--fake-module-count', type=int, default=None, help='create fake outer module containers')
    parser.add_argument('--line-metadata-poison', action='store_true', help='poison ASCII-safe code filename/name/lnotab metadata')
    parser.add_argument('--stack-noise-rate', type=int, default=None, help='insert stack-neutral bytecode noise percentage')
    parser.add_argument('--extended-arg-noise-rate', type=int, default=None, help='insert EXTENDED_ARG 0 noise percentage')
    parser.add_argument('--return-jump-gate-rate', type=int, default=None, help='insert skipped junk gates before return percentage')
    parser.add_argument('--depth-density', action='store_true', help='increase bytecode noise for nested code objects')
    parser.add_argument('--per-code-opcode-table', action='store_true', help='use independent opcode tunnel map per code object')
    parser.set_defaults(server_mcs_opmap=False, client_mcs_opmap=False)
    args = parser.parse_args(argv)
    input_dir = os.path.abspath(args.input_dir)
    output_dir = os.path.abspath(args.output_dir)
    dump_obf_pyc = args.dump_obf_pyc or args.intensity == 'experimental'
    config = dict(config)
    config['target_side'] = args.target_side
    fuser_args, server_specs, client_specs = build_args(input_dir, output_dir, args.include_ui or args.full_integrate_py, args.dump_payload_source, args.mcs_op_override, args.mcs_opmap_version, args.intensity, dump_obf_pyc, args.enable_double_wrap, args.enable_flatten, args.enable_aggressive_poison, args.enable_fake_code, args.full_integrate_py, config)
    fuser_args.server_mcs_opmap = args.server_mcs_opmap
    fuser_args.client_mcs_opmap = args.client_mcs_opmap
    if args.jump_poison_blocks is not None:
        fuser_args.jump_poison_blocks = args.jump_poison_blocks
    if args.jump_poison_min is not None:
        fuser_args.jump_poison_min = args.jump_poison_min
    if args.jump_poison_max is not None:
        fuser_args.jump_poison_max = args.jump_poison_max
    if args.obf2_fake_layers is not None:
        fuser_args.obf2_fake_layers = args.obf2_fake_layers
    if args.obf2_fake_count is not None:
        fuser_args.obf2_fake_count = args.obf2_fake_count
    if args.obf2_fake_min is not None:
        fuser_args.obf2_fake_min = args.obf2_fake_min
    if args.obf2_fake_max is not None:
        fuser_args.obf2_fake_max = args.obf2_fake_max
    if args.inner_taunt_repeat is not None:
        fuser_args.inner_taunt_repeat = args.inner_taunt_repeat
    if args.statement_reorder:
        fuser_args.statement_reorder = True
    if args.statement_reorder_rate is not None:
        fuser_args.statement_reorder_rate = args.statement_reorder_rate
    if args.statement_reorder_window is not None:
        fuser_args.statement_reorder_window = args.statement_reorder_window
    if args.inner_dataflow_noise:
        fuser_args.inner_dataflow_noise = True
    if args.inner_dataflow_rate is not None:
        fuser_args.inner_dataflow_rate = args.inner_dataflow_rate
    if args.inner_dataflow_min is not None:
        fuser_args.inner_dataflow_min = args.inner_dataflow_min
    if args.inner_dataflow_max is not None:
        fuser_args.inner_dataflow_max = args.inner_dataflow_max
    if args.const_pool_strings:
        fuser_args.const_pool_strings = True
    if args.const_pool_numbers:
        fuser_args.const_pool_numbers = True
    if args.call_dispatcher:
        fuser_args.call_dispatcher = True
    if args.call_dispatcher_rate is not None:
        fuser_args.call_dispatcher_rate = args.call_dispatcher_rate
    if args.fake_function_count is not None:
        fuser_args.fake_function_count = args.fake_function_count
    if args.flatten_control_flow_v2:
        fuser_args.flatten_control_flow_v2 = True
    if args.inner_opcode_tunnel:
        fuser_args.inner_opcode_tunnel = True
    if args.inner_opcode_table:
        fuser_args.inner_opcode_table = args.inner_opcode_table
    if args.shuffle_consts:
        fuser_args.shuffle_consts = True
    if args.shuffle_names:
        fuser_args.shuffle_names = True
    if args.fake_name_count is not None:
        fuser_args.fake_name_count = args.fake_name_count
    if args.opcode_tunnel_decoys is not None:
        fuser_args.opcode_tunnel_decoys = args.opcode_tunnel_decoys
    if args.opcode_tunnel_double_map:
        fuser_args.opcode_tunnel_double_map = True
    if args.opcode_tunnel_stages is not None:
        fuser_args.opcode_tunnel_stages = args.opcode_tunnel_stages
    if args.reference_obf:
        fuser_args.reference_obf = True
    if args.reference_obf_rate is not None:
        fuser_args.reference_obf_rate = args.reference_obf_rate
    if args.fake_class_count is not None:
        fuser_args.fake_class_count = args.fake_class_count
    if args.shuffle_varnames:
        fuser_args.shuffle_varnames = True
    if args.payload_fragments is not None:
        fuser_args.payload_fragments = args.payload_fragments
    if args.lifecycle_dispatcher:
        fuser_args.lifecycle_dispatcher = True
    if args.fake_module_count is not None:
        fuser_args.fake_module_count = args.fake_module_count
    if args.line_metadata_poison:
        fuser_args.line_metadata_poison = True
    if args.stack_noise_rate is not None:
        fuser_args.stack_noise_rate = args.stack_noise_rate
    if args.extended_arg_noise_rate is not None:
        fuser_args.extended_arg_noise_rate = args.extended_arg_noise_rate
    if args.return_jump_gate_rate is not None:
        fuser_args.return_jump_gate_rate = args.return_jump_gate_rate
    if args.depth_density:
        fuser_args.depth_density = True
    if args.per_code_opcode_table:
        fuser_args.per_code_opcode_table = True
    skip_sources = packed_source_paths_for_target(
        input_dir, fuser_args.namespace, server_specs, client_specs,
        fuser_args.target_side, args.full_integrate_py, args.include_ui or args.full_integrate_py
    )
    copy_tree(input_dir, output_dir, True, skip_sources)
    data = netease_modmain_fuser.build_modmain(fuser_args)
    write_file(fuser_args.output, data)
    print('wrote %s' % fuser_args.output)
    print('opcode remap: server=%s client=%s version=%s' % (fuser_args.server_mcs_opmap, fuser_args.client_mcs_opmap, fuser_args.mcs_opmap_version))
    if args.intensity == 'experimental':
        print('experimental mode: modMain.py uses full experimental runtime obfuscation')
    print('server systems: %s' % ', '.join('%s=%s' % item for item in server_specs))
    print('client systems: %s' % ', '.join('%s=%s' % item for item in client_specs))
    if skip_sources:
        print('skipped packed sources: %s' % ', '.join(os.path.relpath(path, input_dir) for path in skip_sources))
    if fuser_args.dump_obf_pyc:
        print('dumped CPython obfuscated pyc: %s' % fuser_args.dump_obf_pyc)
    issues = netease_modmain_fuser.netease_policy_checker.scan_path(fuser_args.output)
    print(netease_modmain_fuser.netease_policy_checker.format_issues(issues))
    if issues:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
