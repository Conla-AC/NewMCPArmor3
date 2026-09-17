#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP Shiled 中文 UI 启动入口。"""

import os
import sys


if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from MCP_Armor_UI.app import main


if __name__ == "__main__":
    if "--mcparmor-cli" in sys.argv:
        from MCP_Armor_Src.main_start import main_run
        argv = list(sys.argv[1:])
        argv.remove("--mcparmor-cli")
        main_run(argv)
    else:
        main()
