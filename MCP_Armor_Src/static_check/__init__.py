# -*- coding: utf-8 -*-
"""Pre-obfuscation source compliance checks."""
from __future__ import absolute_import

from MCP_Armor_Src.static_check.scanner import (
    BYPASS_FILENAME,
    StaticCheckFailure,
    enforce_source_compliance,
    scan_source,
)

__all__ = [
    'BYPASS_FILENAME',
    'StaticCheckFailure',
    'enforce_source_compliance',
    'scan_source',
]
