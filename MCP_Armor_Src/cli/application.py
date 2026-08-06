# -*- coding: utf-8 -*-
"""Top-level CLI application orchestration."""
from __future__ import absolute_import, print_function

import os
import random
import sys
import time

from MCP_Armor_Src.cli.config import (
    apply_config,
    apply_netease_profile,
    collect_provided_options,
    read_config_file,
)

from MCP_Armor_Src.cli.example_config import (
    EXAMPLE_CONFIG,
)

from MCP_Armor_Src.cli.parser import (
    build_arg_parser,
)

from MCP_Armor_Src.pipeline.options import (
    merge_options,
)

from MCP_Armor_Src.pipeline.processor import (
    deploy_output_folder,
    process_folder,
    process_single,
)

from MCP_Armor_Src.hwid import (
    encrypted_hwid,
    format_cli_failure,
    validate_license,
)

from MCP_Armor_Src.static_check import (
    StaticCheckFailure,
)

from MCP_Armor_Src.utils.filesystem import (
    write_file,
)

from MCP_Armor_Src.utils.runtime import (
    require_py27,
)


def _print_cli(message):
    """Write Unicode-safe status lines for Python 2 UI subprocesses."""
    if sys.version_info[0] < 3 and isinstance(message, unicode):
        message = message.encode('utf-8')
    sys.stdout.write(message + '\n')


def main(argv=None):
    require_py27()
    random.seed(int(time.time() * 1000000) ^ os.getpid())
    parser = build_arg_parser()
    if argv is None:
        argv = sys.argv[1:]
    args = parser.parse_args(argv)
    if args.show_hwid:
        _print_cli('HWID: %s' % encrypted_hwid())
        return
    license_status = validate_license()
    if not license_status.valid:
        sys.stderr.write(format_cli_failure(license_status) + '\n')
        raise SystemExit(3)
    args._provided_options = collect_provided_options(argv)
    if args.input:
        args._provided_options.add('input')
    if args.write_config:
        write_file(args.write_config, EXAMPLE_CONFIG)
        _print_cli('wrote example config %s' % args.write_config)
        return
    if args.config:
        args = apply_config(args, read_config_file(args.config))
    try:
        args = apply_netease_profile(args)
    except ValueError as exc:
        parser.error(str(exc))
    if not args.input:
        parser.error('input is required; pass positional input or project.input in config')
    if not args.output:
        parser.error('output is required; pass -o/--output or project.output in config')
    opts = merge_options(args)
    is_folder = args.folder or os.path.isdir(args.input)
    try:
        if is_folder:
            if not os.path.isdir(args.input):
                parser.error('folder mode input does not exist: %s' % args.input)
            counts = process_folder(args.input, args.output, args, opts)
            _print_cli('wrote folder %s | obfuscated=%d copied=%d fixed=%d' % (args.output, counts['obfuscated'], counts['copied'], counts['fixed']))
            if args.deploy_target:
                deployed = deploy_output_folder(args.output, args.deploy_target)
                _print_cli('deployed .py files to %s' % deployed)
        else:
            if not os.path.isfile(args.input):
                parser.error('input file does not exist: %s' % args.input)
            result = process_single(args.input, args.output, args, opts)
            _print_cli('wrote %s | %s' % (args.output, result))
    except StaticCheckFailure as error:
        sys.stderr.write(str(error) + '\n')
        raise SystemExit(4)
