# -*- coding: utf-8 -*-
"""UTF-8 text and binary-safe filesystem helpers for the Python 3 host."""


import os
import sys


def python_compile_filename(path):
    """Return a native string filename accepted by Python 3's compiler."""
    return os.fspath(path) if hasattr(os, 'fspath') else path


def read_file(path):
    with open(path, 'rb') as fh:
        return fh.read()


def write_file(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    if isinstance(data, type(u'')):
        data = data.encode('utf-8')
    with open(path, 'wb') as fh:
        fh.write(data)


def read_text(path, encoding='utf-8-sig'):
    """Read a source/configuration file as Unicode text."""
    if sys.version_info[0] < 3:
        with open(path, 'rb') as fh:
            return fh.read().decode(encoding)
    with open(path, 'r', encoding=encoding, newline='') as fh:
        return fh.read()


def decode_source_bytes(data):
    """Decode UTF-8/UTF-16 source files accepted by the project pipeline."""
    if not isinstance(data, bytes):
        return data
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        text = data.decode('utf-16')
    else:
        text = data.decode('utf-8-sig', 'replace')
    if sys.version_info[0] < 3:
        return text.encode('utf-8')
    return text


def ensure_dir(path):
    if path and not os.path.isdir(path):
        os.makedirs(path)


def relpath(path, root):
    return os.path.relpath(path, root).replace('\\', '/')
