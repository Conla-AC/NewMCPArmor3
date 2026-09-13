# -*- coding: utf-8 -*-
"""Version-correct helpers for writing host and NetEase target ``.pyc`` files."""

import time
try:
    from importlib import _bootstrap_external
except ImportError:
    _bootstrap_external = None


def build_timestamp_pyc(code, timestamp=None, source_size=0):
    """Return a valid PEP 552 timestamp-based pyc payload for *code*."""
    if timestamp is None:
        timestamp = time.time()
    if _bootstrap_external is None:
        import imp
        import marshal
        import struct
        return (imp.get_magic() +
                struct.pack('<I', int(timestamp) & 0xFFFFFFFF) +
                marshal.dumps(code))
    return bytes(_bootstrap_external._code_to_timestamp_pyc(
        code,
        int(timestamp) & 0xFFFFFFFF,
        int(source_size) & 0xFFFFFFFF,
    ))\n