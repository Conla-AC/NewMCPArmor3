# -*- coding: utf-8 -*-
"""Binary-safe filesystem helpers used by the Python 2.7 pipeline."""
from __future__ import absolute_import

import os
import sys


def python_compile_filename(path):
    """Return a filename accepted by Python 2's compile/AST C API."""
    if sys.version_info[0] < 3 and isinstance(path, unicode):
        return path.encode('mbcs')
    return path


def read_file(path):
    with open(path, 'rb') as fh:
        return fh.read()


def write_file(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, 'wb') as fh:
        fh.write(data)


def ensure_dir(path):
    if path and not os.path.isdir(path):
        os.makedirs(path)


def relpath(path, root):
    return os.path.relpath(path, root).replace('\\', '/')
