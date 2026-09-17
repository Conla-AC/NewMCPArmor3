# -*- coding: utf-8 -*-
"""Trusted current time from Taobao's timestamp endpoint."""


from MCP_Armor_Src.hwid.network import fetch_json


TAOBAO_TIME_URL = (
    'https://api.m.taobao.com/rest/api3.do?api=mtop.common.getTimestamp')
TAOBAO_TIME_FALLBACK_URL = (
    'https://acs.m.taobao.com/gw/mtop.common.getTimestamp/')


def _timestamp_from_response(payload):
    value = payload.get('data', {}).get('t') if isinstance(payload, dict) else None
    if value is None:
        raise ValueError('Taobao response has no data.t timestamp')
    timestamp = float(value)
    if timestamp > 100000000000.0:
        timestamp /= 1000.0
    if timestamp <= 0:
        raise ValueError('Taobao returned an invalid timestamp')
    return timestamp


def taobao_timestamp(timeout=6):
    urls = [TAOBAO_TIME_URL, TAOBAO_TIME_FALLBACK_URL]
    errors = []
    for url in urls:
        try:
            return _timestamp_from_response(fetch_json(url, timeout, True))
        except Exception as exc:
            errors.append('%s: %s' % (url, exc))
    raise IOError('Taobao time API unavailable (%s)' % '; '.join(errors))
