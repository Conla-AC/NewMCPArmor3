#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Regression tests for the local hwid.json/i.txt isFree policy switch."""

from __future__ import print_function

import io
import json
import os
import sys
import tempfile

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
sys.path.insert(0, ROOT_DIR)

from MCP_Armor_Src.hwid import license as license_module


def _write(path, payload):
    with io.open(path, 'w', encoding='utf-8') as stream:
        data = json.dumps(payload)
        try:
            unicode_type = unicode
        except NameError:
            unicode_type = str
        if not isinstance(data, unicode_type):
            data = data.decode('utf-8')
        stream.write(data)


def main():
    original_hwid = license_module.encrypted_hwid
    original_env = os.environ.get('MCPARMOR_HWID_FILE')
    root = tempfile.mkdtemp(prefix='mcparmor_isfree_')
    free_path = os.path.join(root, 'i.txt')
    locked_path = os.path.join(root, 'hwid.json')
    input_path = os.path.join(root, 'input.py')
    output_path = os.path.join(root, 'output.py')
    with io.open(input_path, 'w', encoding='utf-8') as stream:
        stream.write(u'value = 1\n')
    try:
        _write(free_path, {'isFree': True, 'hwid': {}})
        os.environ['MCPARMOR_HWID_FILE'] = free_path

        def fail_if_called():
            raise AssertionError('encrypted_hwid must not run in isFree mode')

        license_module.encrypted_hwid = fail_if_called
        free = license_module.validate_license()
        assert free.valid and free.reason == 'free_mode'
        assert license_module.is_free_mode()

        # The explicit table path is also covered, which is what callers use
        # for deterministic/offline checks.
        inline = license_module.validate_license(table={'isFree': True}, code=None)
        assert inline.valid and inline.reason == 'free_mode'

        _write(locked_path, {'isFree': False,
                             'hwid': {'ABC': '2099-12-31 23:59:59'}})
        license_module.encrypted_hwid = lambda: 'ABC'
        os.environ['MCPARMOR_HWID_FILE'] = locked_path
        locked = license_module.validate_license(now=1700000000)
        assert locked.valid and locked.reason == 'ok'

        # CLI must pass through the same switch before touching the backend.
        from MCP_Armor_Src.cli import application
        original_process_single = application.process_single
        try:
            calls = []
            application.process_single = lambda *args: calls.append(args) or 'stub'
            os.environ['MCPARMOR_HWID_FILE'] = free_path
            license_module.encrypted_hwid = fail_if_called
            application.main([input_path, '-o', output_path])
            assert calls, 'CLI did not reach the backend in free mode'

            os.environ['MCPARMOR_HWID_FILE'] = locked_path
            license_module.encrypted_hwid = lambda: 'NOT_IN_TABLE'
            try:
                application.main([input_path, '-o', output_path])
            except SystemExit as exc:
                assert exc.code == 3
            else:
                raise AssertionError('CLI accepted unauthorized HWID')
        finally:
            application.process_single = original_process_single

        if sys.version_info[0] >= 3:
            os.environ['MCPARMOR_HWID_FILE'] = free_path
            from MCP_Armor_Easy_UI import app as easyui_app
            easyui_app._safe_hwid = fail_if_called
            assert easyui_app._license_details() == ('free-mode', 'Free mode')
        print('HWID_ISFREE_TEST_OK')
    finally:
        license_module.encrypted_hwid = original_hwid
        if original_env is None:
            os.environ.pop('MCPARMOR_HWID_FILE', None)
        else:
            os.environ['MCPARMOR_HWID_FILE'] = original_env


if __name__ == '__main__':
    main()\n