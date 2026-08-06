# -*- coding: utf-8 -*-
"""Stable application entry point."""
from __future__ import absolute_import

from MCP_Armor_Src.cli.application import main as _application_main


def main_run(argv=None):
    return _application_main(argv)
