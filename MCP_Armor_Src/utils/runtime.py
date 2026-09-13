# -*- coding: utf-8 -*-
"""Interpreter compatibility checks."""


import sys


def require_py313():
    """Require the production host runtime used by the migrated backend."""
    if sys.version_info[:2] != (3, 12):
        raise SystemExit('MCP Armor backend requires CPython 3.12')\n