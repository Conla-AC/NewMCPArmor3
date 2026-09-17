# -*- coding: utf-8 -*-
"""Locate and validate the CPython 2.7 target interpreter."""

import os
import subprocess

try:
    from shutil import which as _which
except ImportError:  # Python 2.7 target workers still import this module.
    from distutils.spawn import find_executable as _which


ENV_NAME = 'MCPARMOR_PY27'
STATE_FILE = os.path.join(
    os.environ.get('LOCALAPPDATA', ''), 'MCPArmor', 'python27_path.txt')


class Python27Error(RuntimeError):
    pass


def _normalize_candidate(candidate):
    if not candidate:
        return None
    candidate = os.path.expandvars(os.path.expanduser(
        str(candidate).strip().strip('"')))
    if not candidate:
        return None
    if os.path.isdir(candidate):
        candidate = os.path.join(
            candidate, 'python.exe' if os.name == 'nt' else 'python')
    if os.path.isabs(candidate) or os.path.dirname(candidate):
        return os.path.abspath(candidate) if os.path.isfile(candidate) else None
    found = _which(candidate)
    return os.path.abspath(found) if found else None


def resolve_python27(configured=None, required=False):
    """Resolve a Python 2.7 executable from config, environment, or defaults.

    A configured value may point either to ``python.exe`` or its installation
    directory. Configuration takes precedence over ``MCPARMOR_PY27``.
    """
    saved = None
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, 'rb') as stream:
                saved = stream.read().decode('utf-8').strip()
        except Exception:
            saved = None
    explicit = configured or os.environ.get(ENV_NAME) or saved
    if explicit:
        resolved = _normalize_candidate(explicit)
        if resolved:
            return resolved
        if required:
            raise Python27Error(
                'configured Python 2.7 interpreter was not found: %s' % explicit)

    candidates = [r'C:\Python27\python.exe', 'python2.7', 'python2']
    for candidate in candidates:
        resolved = _normalize_candidate(candidate)
        if resolved:
            return resolved
    if required:
        raise Python27Error(
            'Python 2.7 target backend was not found; set runtime.python27 '
            'in the YAML config, pass --python27, or set MCPARMOR_PY27')
    return None


def require_python27(configured=None):
    """Return a resolved executable after confirming it is CPython 2.7."""
    executable = resolve_python27(configured, required=True)
    command = [
        executable, '-c',
        'import platform,sys;sys.stdout.write(platform.python_implementation()+'
        '":"+str(sys.version_info[0])+"."+str(sys.version_info[1]))',
    ]
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
    except (IOError, OSError) as error:
        raise Python27Error(
            'failed to start Python 2.7 interpreter %s: %s' %
            (executable, error))
    if not isinstance(stdout, str):
        stdout = stdout.decode('ascii', 'replace')
    if not isinstance(stderr, str):
        stderr = stderr.decode('utf-8', 'replace')
    version = stdout.strip()
    if process.returncode != 0 or version != 'CPython:2.7':
        detail = version or stderr.strip() or 'unknown interpreter'
        raise Python27Error(
            'target backend requires CPython 2.7, but %s reported %s' %
            (executable, detail))
    return executable
