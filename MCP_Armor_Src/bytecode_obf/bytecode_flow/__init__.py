# -*- coding: utf-8 -*-
"""Verified ByteCode_Flow support for Python 2.7 bytecode."""

from MCP_Armor_Src.bytecode_obf.bytecode_flow.block_seeds import apply_block_seed_flow
from MCP_Armor_Src.bytecode_obf.bytecode_flow.block_shuffle import apply_basic_block_shuffle
from MCP_Armor_Src.bytecode_obf.bytecode_flow.decoy_islands import apply_decoy_islands
from MCP_Armor_Src.bytecode_obf.bytecode_flow.dispatcher import apply_state_dispatcher
from MCP_Armor_Src.bytecode_obf.bytecode_flow.builder import build_control_flow_graph
from MCP_Armor_Src.bytecode_obf.bytecode_flow.abstract_frame import (
    AbstractFrame, AbstractValue, FrameAnalysisResult,
    analyze_abstract_frames, analyze_code_tree, normalize_opcode_bytes,
    frame_analysis_gate,
)
from MCP_Armor_Src.bytecode_obf.bytecode_flow.transform import apply_conditional_edge_proxies
from MCP_Armor_Src.bytecode_obf.bytecode_flow.slot_permutation import permute_local_slots
from MCP_Armor_Src.bytecode_obf.bytecode_flow.semantic_templates import apply_semantic_templates
from MCP_Armor_Src.bytecode_obf.bytecode_flow.flow_audit import audit_bytecode_flow
from MCP_Armor_Src.bytecode_obf.bytecode_flow.validator import (
    BytecodeValidationResult,
    validate_code_object_layout,
)

__all__ = [
    'apply_block_seed_flow',
    'apply_basic_block_shuffle',
    'apply_decoy_islands',
    'apply_state_dispatcher',
    'apply_conditional_edge_proxies',
    'build_control_flow_graph',
    'AbstractFrame',
    'AbstractValue',
    'FrameAnalysisResult',
    'analyze_abstract_frames',
    'analyze_code_tree',
    'normalize_opcode_bytes',
    'frame_analysis_gate',
    'permute_local_slots',
    'apply_semantic_templates',
    'audit_bytecode_flow',
]
