#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""Isolated NetEase Python 2.7 code-object worker.

The main application and orchestration run on Python 3.13. Only compilation
and bytecode/code-object transforms execute here because CPython code objects
and marshal streams are version-specific.
"""

import base64
import json
import os
import sys


class State(object):
    pass


def _decode_value(value):
    if isinstance(value, dict):
        if set(value) == set(['__mcp_bytes__']):
            return base64.b64decode(value['__mcp_bytes__'])
        return dict((key, _decode_value(item)) for key, item in value.items())
    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    return value


def _state(mapping):
    result = State()
    for key, value in mapping.items():
        setattr(result, key, _decode_value(value))
    return result


def main(argv=None):
    if sys.version_info[:2] != (2, 7):
        raise SystemExit('MCP Armor target worker requires CPython 2.7')
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        raise SystemExit('usage: py27_worker REQUEST.json')
    with open(argv[0], 'rb') as stream:
        request = json.loads(stream.read().decode('utf-8'))
    from MCP_Armor_Src.pipeline.processor import obfuscate_file, process_folder
    options = _state(request['options'])
    operation = request['operation']
    if operation == 'file':
        obfuscate_file(request['source'], request['output'], options,
                       request.get('rel'))
    elif operation == 'folder':
        process_folder(request['source'], request['output'],
                       _state(request.get('args', {})), options)
    else:
        raise SystemExit('unknown target backend operation: %s' % operation)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())\n