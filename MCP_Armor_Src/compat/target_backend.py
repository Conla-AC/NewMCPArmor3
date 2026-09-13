# -*- coding: utf-8 -*-
"""Dispatch Python 2.7 target-bytecode jobs from the Python 3.13 host."""

import base64
import json
import os
import subprocess
import sys
import tempfile

from MCP_Armor_Src.compat.python27 import require_python27


WORKER_ENV = 'MCPARMOR_PY27_WORKER'


def in_target_worker():
    return os.environ.get(WORKER_ENV) == '1'


def target_worker_required():
    return sys.version_info[0] >= 3 and not in_target_worker()


def _encode_value(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {'__mcp_bytes__': base64.b64encode(value).decode('ascii')}
    if isinstance(value, (list, tuple, set)):
        return [_encode_value(item) for item in value]
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            if isinstance(key, str):
                try:
                    output[key] = _encode_value(item)
                except TypeError:
                    continue
        return output
    raise TypeError('unsupported worker option value: %s' % type(value).__name__)


def _object_state(value):
    output = {}
    for key, item in vars(value).items():
        if key in ('source_project_analyses',):
            continue
        try:
            output[key] = _encode_value(item)
        except TypeError:
            continue
    return output


def _python27_executable(configured=None):
    return require_python27(configured)


def _worker_executable():
    configured = os.environ.get('MCPARMOR_PY27_WORKER_EXE')
    candidates = [configured]
    if getattr(sys, '_MEIPASS', None):
        candidates.append(os.path.join(sys._MEIPASS, 'MCPArmor_Py27_Worker.exe'))
    compiled = globals().get('__compiled__')
    containing_dir = getattr(compiled, 'containing_dir', None)
    if containing_dir:
        candidates.append(os.path.join(containing_dir,
                                       'MCPArmor_Py27_Worker.exe'))
    if getattr(sys, 'frozen', False):
        candidates.append(os.path.join(os.path.dirname(sys.executable),
                                       'MCPArmor_Py27_Worker.exe'))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'MCPArmor_Py27_Worker.exe'))
    candidates.append(os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))),
        'MCPArmor_Py27_Worker.exe'))
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise RuntimeError('Python 2.7 worker executable was not bundled; '
                       'rebuild MCPArmor_Py27_Worker.exe')


def run_target_job(operation, source, output, options, rel=None, args=None):
    """Run one target-code job and return only after its output is verified."""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    request = {
        'operation': operation,
        'source': os.path.abspath(source),
        'output': os.path.abspath(output),
        'rel': rel,
        'options': _object_state(options),
        'args': _object_state(args) if args is not None else {},
    }
    handle, request_path = tempfile.mkstemp(prefix='mcparmor_py27_', suffix='.json')
    os.close(handle)
    try:
        with open(request_path, 'w', encoding='utf-8') as stream:
            json.dump(request, stream, ensure_ascii=True, sort_keys=True)
        env = os.environ.copy()
        env[WORKER_ENV] = '1'
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        # Python 2 otherwise falls back to an ASCII stdio codec in frozen
        # console-less children.  Source diagnostics may legitimately contain
        # NetEase formatting characters such as U+00A7.
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONPATH'] = root + os.pathsep + env.get('PYTHONPATH', '')
        # A frozen 3.13 CLI delegates code-object work to a real Python 2.7
        # worker executable. Never execute py27 code in the 3.13 process.
        frozen = bool(getattr(sys, 'frozen', False)
                      or globals().get('__compiled__'))
        if frozen:
            command = [_worker_executable(), request_path]
        else:
            configured_python27 = getattr(args, 'python27', None)
            if not configured_python27:
                configured_python27 = getattr(options, 'python27', None)
            python27 = _python27_executable(configured_python27)
            env['MCPARMOR_PY27'] = python27
            command = [python27, '-m',
                       'MCP_Armor_Src.compat.py27_worker', request_path]
        subprocess.check_call(command, cwd=root, env=env)
        if not os.path.exists(output):
            raise RuntimeError('Python 2.7 target backend produced no output: %s' % output)
    finally:
        try:
            os.remove(request_path)
        except OSError:
            pass\n