# -*- coding: utf-8 -*-
"""Stable Windows machine fingerprint generation."""


import hashlib
import os
import platform

from MCP_Armor_Src.hwid.crypto import xor_encrypt_hex


def _windows_machine_guid():
    try:
        try:
            import winreg
        except ImportError:
            import winreg as winreg
        access = winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_64KEY', 0)
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SOFTWARE\Microsoft\Cryptography', 0, access)
        try:
            value, _kind = winreg.QueryValueEx(key, 'MachineGuid')
            return value
        finally:
            winreg.CloseKey(key)
    except (EnvironmentError, ImportError, OSError):
        return None


def _fallback_machine_seed():
    fields = (
        platform.node(),
        os.environ.get('COMPUTERNAME', ''),
        os.environ.get('PROCESSOR_IDENTIFIER', ''),
        os.environ.get('SYSTEMDRIVE', ''),
    )
    return '|'.join(value for value in fields if value)


def machine_fingerprint():
    seed = _windows_machine_guid() or _fallback_machine_seed()
    if not seed:
        raise RuntimeError('unable to read a stable machine identifier')
    if not isinstance(seed, bytes):
        seed = seed.encode('utf-8')
    return hashlib.sha256(seed).hexdigest().upper()[:32]


def encrypted_hwid():
    return xor_encrypt_hex(machine_fingerprint())
