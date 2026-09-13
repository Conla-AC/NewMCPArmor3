# -*- coding: utf-8 -*-
"""HWID-based local license validation."""


from MCP_Armor_Src.hwid.license import (
    format_cli_failure,
    get_license_url,
    get_local_license_path,
    is_free_mode,
    validate_license,
)
from MCP_Armor_Src.hwid.machine import (
    encrypted_hwid,
    machine_fingerprint,
)

__all__ = [
    'encrypted_hwid',
    'format_cli_failure',
    'get_license_url',
    'get_local_license_path',
    'is_free_mode',
    'machine_fingerprint',
    'validate_license',
]\n