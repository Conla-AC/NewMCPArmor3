# -*- coding: utf-8 -*-
"""MCPArmor CLI compatibility entry point.

The packaged UI and older build scripts expect a root ``main.py``.  Keep this
thin shim so source checkouts, PyInstaller specs and existing integrations all
resolve the same Python 3 host implementation.
"""

from MCP_Armor_Src.main_start import main_run


if __name__ == '__main__':
    main_run()\n