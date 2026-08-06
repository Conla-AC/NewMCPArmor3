# -*- coding: utf-8 -*-
"""Python 2 AST transformations.

This layer may depend on ``utils`` but must not depend on bytecode or loader
implementations. Its public contract is AST/source in and AST/source out.
"""
from MCP_Armor_Src.ast_obf.references import obfuscate_source_references
from MCP_Armor_Src.ast_obf.analysis import analyze_source, analyze_source_project

__all__ = [
    'analyze_source', 'analyze_source_project',
    'obfuscate_source_references',
]
