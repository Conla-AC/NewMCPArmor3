# -*- coding: utf-8 -*-
"""Remote encrypted-HWID license table and expiration validation."""
from __future__ import absolute_import

import calendar
import datetime
from MCP_Armor_Src.hwid.machine import encrypted_hwid
from MCP_Armor_Src.hwid.network import fetch_json
from MCP_Armor_Src.hwid.time_source import taobao_timestamp


LICENSE_URL = (
    'https://gitee.com/online-ah/mini-world_-obf/raw/master/hwid.json')
CHINA_UTC_OFFSET_SECONDS = 8 * 60 * 60


class LicenseStatus(object):
    def __init__(self, valid, code, reason, expires=None, source=None):
        self.valid = bool(valid)
        self.code = code
        self.reason = reason
        self.expires = expires
        self.source = source


def get_license_url():
    return LICENSE_URL


def _normalize_code(value):
    return ''.join(str(value or '').replace('-', '').split()).upper()


def _parse_expiration(value):
    if isinstance(value, (int, float)):
        stamp = float(value)
        return (stamp / 1000.0 if stamp > 100000000000.0 else stamp), str(value)
    text = str(value or '').strip()
    if text.isdigit():
        stamp = float(text)
        return (stamp / 1000.0 if stamp > 100000000000.0 else stamp), text
    formats = (
        ('%Y-%m-%d %H:%M:%S', False),
        ('%Y-%m-%dT%H:%M:%S', False),
        ('%Y-%m-%dT%H:%M:%SZ', True),
        ('%Y-%m-%d', False),
    )
    for pattern, utc in formats:
        try:
            parsed = datetime.datetime.strptime(text, pattern)
        except ValueError:
            continue
        if pattern == '%Y-%m-%d':
            parsed = parsed.replace(hour=23, minute=59, second=59)
        stamp = calendar.timegm(parsed.timetuple())
        if not utc:
            stamp -= CHINA_UTC_OFFSET_SECONDS
        return float(stamp), text
    raise ValueError('invalid expiration time: %s' % text)


def _normalize_table(payload):
    table = payload.get('hwid') if isinstance(payload, dict) else None
    if not isinstance(table, dict):
        raise ValueError('license JSON must contain an hwid object')
    return dict((_normalize_code(key), expiration)
                for key, expiration in table.items())


def validate_license(license_url=None, now=None, code=None, table=None):
    code = _normalize_code(code or encrypted_hwid())
    source = license_url or get_license_url()
    if table is None:
        try:
            table = fetch_json(source, timeout=8, no_cache=True)
        except Exception as exc:
            return LicenseStatus(False, code, 'license_server_unavailable:%s' % exc,
                                 source=source)
    try:
        table = _normalize_table(table)
    except (TypeError, ValueError) as exc:
        return LicenseStatus(False, code, 'license_data_invalid:%s' % exc,
                             source=source)
    if code not in table:
        return LicenseStatus(False, code, 'hwid_not_authorized', source=source)
    try:
        expires_at, expires_text = _parse_expiration(table[code])
    except (TypeError, ValueError) as exc:
        return LicenseStatus(False, code, 'expiration_invalid:%s' % exc,
                             source=source)
    if now is None:
        try:
            now = taobao_timestamp()
        except Exception as exc:
            return LicenseStatus(False, code, 'time_server_unavailable:%s' % exc,
                                 expires_text, source)
    if float(now) > expires_at:
        return LicenseStatus(False, code, 'license_expired', expires_text,
                             source)
    return LicenseStatus(True, code, 'ok', expires_text, source)


def format_cli_failure(status):
    if status.reason == 'license_expired':
        title = 'HWID license expired; please renew your license.'
    elif status.reason == 'hwid_not_authorized':
        title = 'HWID is not authorized; please request or renew a license.'
    elif status.reason.startswith('license_server_unavailable:'):
        title = 'HWID license server is unavailable.'
    elif status.reason.startswith('time_server_unavailable:'):
        title = 'Taobao time API is unavailable; license cannot be verified.'
    else:
        title = 'HWID license validation failed: %s' % status.reason
    rows = [title, 'HWID: %s' % status.code]
    if status.expires:
        rows.append('EXPIRES: %s' % status.expires)
    if status.source:
        rows.append('LICENSE_SERVER: %s' % status.source)
    return '\n'.join(rows)
