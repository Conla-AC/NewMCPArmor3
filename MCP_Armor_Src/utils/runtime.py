# -*- coding: utf-8 -*-
"""Interpreter compatibility checks."""
from __future__ import absolute_import

import sys


def require_py27():
    if sys.version_info[0] != 2:
        raise SystemExit('MCP Armor backend must be run by Python 2.7')
