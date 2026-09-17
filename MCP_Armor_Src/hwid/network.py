# -*- coding: utf-8 -*-
"""Minimal JSON HTTP client shared by Python 2.7 and Python 3."""


import json
import time

try:
    from urllib.request import Request, urlopen
except ImportError:
    from urllib2 import Request, urlopen


def fetch_json(url, timeout=6, no_cache=False):
    if no_cache:
        separator = '&' if '?' in url else '?'
        url = '%s%s_mcp_time=%d' % (url, separator, int(time.time() * 1000))
    request = Request(url, headers={
        'User-Agent': 'MCPArmor-HWID/1.0',
        'Accept': 'application/json,text/plain,*/*',
        'Cache-Control': 'no-cache',
    })
    response = urlopen(request, timeout=float(timeout))
    try:
        payload = response.read()
    finally:
        response.close()
    if not isinstance(payload, str):
        payload = payload.decode('utf-8')
    return json.loads(payload)
