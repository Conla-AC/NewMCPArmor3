# -*- coding: utf-8 -*-
"""Recovered ZKM presets, separate from UI widget state."""

AST_CHECKS = [('global_rename', 'globally rename identifiers', '全局名称重命名'),
 ('module_rename', 'rename modules / folders', '文件与文件夹重命名'),
 ('function_split', 'split functions / classes', '函数 / 类分割'),
 ('string_split', 'split string literals', '字符串分割'),
 ('string_xor', 'dynamic XOR strings', '动态 XOR 字符串加密'),
 ('linearize_calls', 'linearize calls', '链式调用拆分'),
 ('constant_pool', 'constant pool', '常量池'),
 ('constant_rewrite', 'rewrite integer constants', '整数常量改写'),
 ('schedule', 'expression scheduling', '表达式安全调度'),
 ('exception_shell', 'exception obfuscation', '异常流混淆'),
 ('reference_obf', 'obfuscate references', '引用混淆'),
 ('identity_weave', 'identity weave', '恒等式编织'),
 ('dead_flow', 'safe dead branches', '不可达分支'),
 ('parenthesis_noise', 'parenthesis noise', '括号视觉噪声'),
 ('comment_noise', 'comment noise', '注释视觉噪声')]

BYTE_CHECKS = [('flow_block_seeds', 'block seeds', '块种子'),
 ('flow_block_shuffle', 'block shuffle', '块重排'),
 ('flow_loop_dispatch', 'loop dispatch', '循环分发'),
 ('stack_noise', 'stack noise', '栈噪声'),
 ('jump_inversion', 'jump inversion', '跳转反转'),
 ('oparg_poison', 'oparg poison', 'oparg 错位'),
 ('taken_jump_poison', 'JMP poison (skip invalid opcode)', 'JMP 花指令（跳过非法 opcode）')]

ADVANCED_BYTE_CHECKS = [('safe_dead_blocks', 'safe dead blocks', '安全死代码块'),
 ('opaque_predicates', 'opaque predicates', '不透明谓词'),
 ('decoy_islands', 'decoy islands', '诱饵岛'),
 ('jump_trampolines', 'jump trampolines', '跳转跳板链'),
 ('code_bytes_split', 'split code bytes', '字节码拆分'),
 ('code_ref_table', 'code reference table', '代码引用表'),
 ('code_tuple_field_shuffle', 'shuffle code tuple fields', '代码元组字段乱序'),
 ('code_tuple_fragments', 'code tuple fragments', '代码元组碎片'),
 ('code_tuple_provider_graph', 'tuple provider graph', '元组 Provider 图'),
 ('code_field_descriptors', 'code field descriptors', '代码字段描述符'),
 ('code_fused_restore', 'fused code restore', '融合代码恢复'),
 ('loader_reference_cleanup', 'loader reference cleanup', '加载器引用清理'),
 ('code_capsule_proxy', 'code capsule proxy', '代码胶囊代理'),
 ('index_pool_shuffle', 'index pool shuffle', '索引池乱序'),
 ('delayed_const_access', 'delayed constant access', '延迟常量访问'),
 ('slot_mirage', 'slot mirage', '槽位幻象'),
 ('strategy_variation', 'strategy variation', '策略变体')]

AST_DEFAULTS = {'off': {},
 'low': {'global_rename': True, 'module_rename': True, 'string_split': True, 'string_xor': True},
 'medium': {'global_rename': True,
            'module_rename': True,
            'string_split': True,
            'string_xor': True,
            'linearize_calls': True,
            'schedule': True,
            'constant_pool': True},
 'high': {'global_rename': True,
          'module_rename': True,
          'string_split': True,
          'string_xor': True,
          'linearize_calls': True,
          'schedule': True,
          'constant_pool': True,
          'constant_rewrite': True,
          'exception_shell': True,
          'dead_flow': True,
          'parenthesis_noise': True,
          'comment_noise': True}}

BYTE_DEFAULTS = {'low': {'flow_ratio': 25,
         'flow_max_edges': 2,
         'taken_jump_poison': True,
         'oparg_poison': True,
         'safe_dead_blocks': True,
         'stack_noise': True,
         'jump_inversion': True},
 'medium': {'flow_ratio': 50,
            'flow_max_edges': 4,
            'flow_block_seeds': True,
            'taken_jump_poison': True,
            'oparg_poison': True,
            'safe_dead_blocks': True,
            'stack_noise': True,
            'jump_inversion': True,
            'jump_trampolines': True,
            'opaque_predicates': True,
            'decoy_islands': True,
            'code_bytes_split': True,
            'code_ref_table': True,
            'code_tuple_field_shuffle': True,
            'loader_reference_cleanup': True},
 'high': {'flow_ratio': 75,
          'flow_max_edges': 6,
          'flow_block_seeds': True,
          'flow_block_shuffle': True,
          'taken_jump_poison': True,
          'oparg_poison': True,
          'safe_dead_blocks': True,
          'stack_noise': True,
          'jump_inversion': True,
          'jump_trampolines': True,
          'opaque_predicates': True,
          'decoy_islands': True,
          'code_bytes_split': True,
          'code_ref_table': True,
          'code_tuple_field_shuffle': True,
          'code_tuple_fragments': True,
          'code_tuple_provider_graph': True,
          'code_field_descriptors': True,
          'code_fused_restore': True,
          'loader_reference_cleanup': True,
          'code_capsule_proxy': True,
          'index_pool_shuffle': True,
          'delayed_const_access': True,
          'slot_mirage': True,
          'strategy_variation': True}}

VM_CHECKS = [('vm_ir', 'VM-IR', 'VM-IR'), ('vm_extension', 'VM extension', 'VM 拓展')]

def split_patterns(value):
    import re
    if isinstance(value, (tuple, list)):
        return list(value)
    return [part.strip() for part in re.split(r'[;,\n]+', value) if part.strip()]


def default_settings():
    result = {key: False for key, _, _ in AST_CHECKS + BYTE_CHECKS + ADVANCED_BYTE_CHECKS + VM_CHECKS}
    result.update(AST_DEFAULTS['medium'])
    result.update(BYTE_DEFAULTS['medium'])
    result.update(ast_level='medium', bytecode_level='medium', vm_ratio=15,
                  vm_min_ops=8, vm_max_ops=160, vm_max_functions=8,
                  vm_include='', vm_exclude='On*; *Tick*; *Update*; *Timer*; *Frame*; *Render*; Listen*; Notify*; NeteaseMod*; __*__',
                  vm_allow_loops=False, vm_debug=False, vm_dialects=1,
                  vm_flow_constants=False, vm_exception_trap_ratio=0,
                  string_xor_mode='random', string_xor_text='MCP_Shiled',
                  string_xor_number=173, string_xor_min_length=4,
                  string_xor_limit=512, string_xor_variants=4, string_xor_decoys=2,
                  string_xor_debug=False, string_split_parts=3)
    return result


def default_other():
    return dict(loader_mode='cpickle', loader_dialect='auto', loader_vm=False, debug=False,
                output_date='2012-03-15', clean_output=True,
                log_enabled=True, no_bytecode_obf=False, opcode_replacement=True,
                mcs_opmap_version=1, anti_debug=False, write_rename_mapping=True,
                exclude='modMain.py; config.py; __init__.py',
                ast_exclude='', source_only='', module_rename_exclude='modMain.py; config.py; __init__.py')\n