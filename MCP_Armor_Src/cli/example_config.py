# -*- coding: utf-8 -*-
"""Canonical example YAML configuration."""



EXAMPLE_CONFIG = '''# py27_byte_obf config.yml
runtime:
  python27: null           # CPython 2.7 directory or full python.exe path

static_check:
  enabled: true            # false skips source compliance checks

project:
  input: MoreTag_clean_input
  output: MoreTag_config_out
  folder: true
  obfuscate_init: false    # true also protects package __init__.py files
  emit_pyc: false          # true writes obfuscated modules as Python 2.7 pyc
  target_side: all        # all/server/client
  include:
    - "*.py"
  exclude:
    - modMain.py
    - __init__.py
  clean_output: true
  copy_pyc: false
  deploy_target: null     # example: C:/.../behavior_pack_xxx/NeteaseMod

netease:
  profile: none            # none/safe/strong/strong-plus/diagnostic, also accepts netease-* aliases
  fix_register: true
  package_name: NeteaseMod
  namespace: Script_NeteaseMod

basic:
  preset: max
  output_date: 2012-03-15       # fixed watermark/pyc timestamp; accepts YYYY-MM-DD or full timestamp
  resource_profile: balanced # compact/balanced/strong/unlimited
  payload_cipher: legacy       # legacy or chacha; chacha calls NetEase _chacha at runtime
  anti_debug: false            # bind decryption to NetEase native _chacha and behavior-pack header.uuid
  experimental_anti_debug: false # optional trace/profile/module/timing checks; compatibility is not guaranteed
  loader_mode: netease-func
  key_len: 16
  filename_mode: mem
  debug: false              # full staged loader/payload/code tuple/opcode/source-string logs

source:
  global_rename: true    # project-wide definitions/imports/members/arguments/locals; NetEase ABI names are protected
  module_rename: false   # rename .py filenames and relink imports/RegisterSystem/RegisterUI paths (folder mode only)
  module_rename_exclude: ["modMain.py", "config.py", "__init__.py"]
  function_split: false          # folder mode: extract eligible functions into sibling modules before Rename
  linearize_calls: false  # source AST layer: split obj.method(...).next(...) into ordered temps
  schedule: false          # source AST layer: split pure expressions then dependency-safe reorder
  string_split: false      # source AST layer: split safe string literals into equivalent concatenations
  string_split_parts: 3
  string_xor: false        # source AST layer: XOR-encrypt ordinary str/unicode literals and decode on demand
  string_xor_mode: random  # random/text/number/chacha; chacha calls NetEase _chacha at runtime
  string_xor_text: MCP_Shiled
  string_xor_number: 173   # fixed numeric XOR key (0-255)
  string_xor_min_length: 4
  string_xor_limit: 512    # maximum encrypted literals per file; 0 disables replacements
  string_xor_variants: 4   # maximum real decoder variants; small files adapt down to 2-3
  string_xor_decoys: 2     # maximum fake variants; small files adapt down to 1-2
  string_xor_debug: false   # print [DEBUG] ... Loaded for each decoder/decryption stage
  constant_pool: false     # source AST layer: module-local pool for safe strings
  constant_pool_min: 4
  constant_pool_max: 128
  constant_rewrite: false  # source AST layer: rewrite selected local integer constants
  constant_rewrite_limit: 8
  exception_shell: false   # source AST layer: safe exception shells around harmless guards
  parenthesis_noise: false # source renderer: redundant parentheses
  comment_noise: false     # source renderer: harmless randomized comments
  comment_noise_count: 2
  dead_flow: false         # source AST layer: inject unreachable fake branches / pseudo control flow
  dead_flow_blocks: 1      # max dead-flow blocks per function; 1-2 is usually enough
  vm: false                # legacy alias; equivalent to vm_extension
  vm_ir: false             # full-coverage VM-IR profile (maps to VM full mode)
  vm_extension: false      # selective AST VM plus provider/carrier extensions
  vm_full: false           # 100% of supported non-hot functions, loops enabled, expanded limits
  vm_ratio: 15             # percentage of eligible functions selected
  vm_min_ops: 8            # skip tiny functions where VM overhead is not worthwhile
  vm_max_ops: 160          # keep very large/complex functions native
  vm_max_functions: 8      # per-file cap; 0 means unlimited
  vm_include: []           # optional function-name globs; empty means all eligible names
  vm_exclude: ["On*", "*Tick*", "*Update*", "*Timer*", "*Frame*", "*Render*", "Listen*", "Notify*", "NeteaseMod*", "__*__"]
  vm_allow_loops: false    # opt-in: loop virtualization is supported but costs more per iteration
  vm_debug: false          # print one runtime installation log per virtualized module
  flow_hardening: false    # project analysis + internal predicates + flow-bound multi-dialect VM
  project_analysis: true   # required by project-wide global Rename planning
  internal_predicates: false # hidden parameters only for closed private same-module call groups
  internal_predicate_ratio: 70
  hot_patterns: ["On*", "*Tick*", "*Update*", "*Timer*", "*Frame*", "*Render*", "Listen*", "Notify*", "Callback", "Destroy", "__*__"]
  vm_dialects: 4           # independent opcode/row/runtime families per source module (1-8)
  vm_flow_constants: false # constants, names and block transitions depend on live VM flow state
  vm_exception_trap_ratio: 0 # failure-only cold-path traps; normal execution never raises them
  reference_obf: false     # polymorphic encrypted getattr indirection for field/method reads
  reference_obf_ratio: 35
  reference_obf_exclude: ["__*__", "func_*", "co_*"]
  tuple_arg_decoys: 0      # dead Python 2 tuple-argument functions; naturally emit .0 slots
  dotzero_relay: false     # one-shot generator relay for the VM capability token
  default_capsule: false   # one-shot function-default capsule used by Identity Weave
  identity_weave: false    # install real func_code into a decoy public function at startup
  identity_ratio: 45
  identity_max: 12
  identity_variation: false # randomize code/default/doc carrier roles and decoy body shape
  decompiler_carriers: 0   # 1-4 cold nested code-object carriers; no real call-path work
  decoy_docstrings: false  # random binary docstrings beside unreachable AST traps
  decoy_docstring_min: 1024
  decoy_docstring_max: 4096
  exception_lattice: false # add nested try/except/else/finally traps inside carriers
  class_body_trap: false   # add nested class-body/method-role traps inside carriers
  schedule_max_exprs: 4    # max extracted expressions per statement
  schedule_window: 8       # max adjacent simple statements considered for reordering

bytecode:
  enabled: true             # false = keep source AST layers/loaders, skip bytecode/code-object transforms
  code_tuple_payload: true  # true = recursive cPickle CodeType tuple payload; false = legacy marshal payload
  code_bytes_split: false   # split co_code bytes inside recursive code tuple payload, then join in loader
  code_bytes_split_min: 48
  code_bytes_split_max_chunks: 6
  code_bytes_fake_chunks: 0  # fake chunks stored beside real split co_code chunks; ignored by loader order
  code_ref_table: false      # store nested code objects in an external table and rebuild dynamically
  code_ref_decoys: 0         # fake encrypted code tuple rows appended to the code ref table
  code_ref_wide_rows: false  # append random junk fields to code ref rows; loader reads only first fields
  code_ref_mask_markers: false # mask nested code ref marker ids inside co_consts
  code_tuple_field_shuffle: false # shuffle CodeType tuple fields and restore order in loader
  code_tuple_fragments: false # split CodeType tuple fields into shuffled fragment rows
  code_tuple_fragment_providers: false # wrap CodeType fragment rows as runtime provider records
  code_tuple_provider_graph: false # resolve provider seeds through small dependency graph nodes
  code_tuple_provider_decoys: 0    # extra fake provider graph records per code tuple
  code_capsule_proxy: false        # wrap final CodeType execution in a closure-backed callable proxy
  code_capsule_protocol_guard: false # protect capsule introspection/pickle/copy/repr protocols
  lazy_function_capsules: false    # selected cold functions use independent encrypted Code Tuple payloads
  lazy_capsule_ratio: 20           # percentage of eligible functions selected per file
  lazy_capsule_max_functions: 8    # per-file cap; 0 means unlimited
  lazy_capsule_mode: adaptive      # adaptive/once/call/count; adaptive currently uses bounded retention
  lazy_capsule_retain_calls: 4     # calls retained before re-encryption-style eviction in count mode
  lazy_capsule_cross_key: false    # bind each lazy key to the outer module key during one-shot bootstrap
  lazy_capsule_rotate_payload: false # rotate encrypted chunks/key after each real hydration
  lazy_capsule_rotate_max_bytes: 262144 # skip runtime rotation above this serialized payload size
  lazy_capsule_carrier_swap: false # execute hydrated code through an independent decoy function carrier
  lazy_capsule_manager_proxy: false # expose the capsule manager through a protocol-guarded callable object
  lazy_capsule_carrier_route_rotation: false # rotate among three func_code write/restore paths
  lazy_capsule_include: []         # optional function-name globs
  lazy_capsule_exclude: ["On*", "*Tick*", "*Update*", "*Timer*", "*Frame*", "*Render*", "Listen*", "Notify*", "NeteaseMod*", "__*__"]
  lazy_capsule_debug: false        # print registry/hydration/eviction diagnostics
  code_field_descriptors: false    # materialize all 14 CodeType fields through runtime descriptors/providers
  code_provider_context_bind: false # bind providers to build/code/parent/field context and reject detached loads
  code_fused_restore: false        # fuse storage-opcode/operand restoration into final CodeType construction
  loader_reference_cleanup: false # clear payload/key/table/provider references before module execution
  code_global_arena: false         # interleave all code-object fields in one module-wide arena
  code_template_delta: false       # store arena nodes as deltas over templates/earlier nodes
  code_global_arena_decoys: 0      # fake structurally valid arena nodes and field rows
  code_block_relocation: false     # shuffle basic blocks and rebuild jump operands in the loader
  code_block_reloc_decoys: 0       # fake basic-block rows excluded from the real layout
  code_unit_arena: false           # store instructions as shuffled records and join them in the loader
  code_unit_arena_decoys: 0        # fake instruction records excluded from the real order
  code_operand_graph: false        # rebuild opcode/oparg bytes from masked symbolic fields
  code_const_arena: false          # move co_consts values into one shuffled module-wide arena
  code_const_arena_decoys: 0       # fake constant rows excluded from real references
  code_const_provider_graph: false # resolve constants through masked dependency providers
  code_const_arena_limit: 1024     # max referenced constants moved per module; 0 means unlimited
  stack_pad: 0              # structural bytecode layer: inflate co_stacksize without runtime work
  lnotab_noise: 0           # structural bytecode layer: append traceback line-table noise
  const_salts: 0            # structural bytecode layer: append static salt constants
  name_chaff: 0             # structural bytecode layer: append unused co_names chaff
  entry_noise: 0            # structural bytecode layer: prepend legal stack-neutral entry noise
  exception_decoys: 0       # structural bytecode layer: prepend skipped exception/finally-shaped decoy blocks
  stack_noise: false        # insert internal LOAD_CONST/POP_TOP stack-equivalent noise blocks
  stack_noise_interval: 18  # instruction interval between stack-equivalent noise blocks
  stack_noise_limit: 6      # maximum stack-equivalent noise blocks per function code object
  jump_inversion: false     # invert selected POP_JUMP_IF_FALSE/TRUE branches
  jump_inversion_limit: 4   # maximum conditional jump inversions per function code object
  jump_trampolines: false   # replace selected direct jumps with two-stage absolute jump chains
  jump_trampoline_limit: 4  # maximum jump trampoline chains per function code object
  strategy_variation: false # deterministically vary active bytecode strategies per code object
  strategy_seed: 0          # reproducible per-code strategy variation seed
  delayed_const_access: false # replace selected LOAD_CONST with tuple index indirection
  delayed_const_limit: 3    # maximum delayed constant reads per function code object
  extended_arg_prefix: false # prefix selected argument opcodes with EXTENDED_ARG 0
  extended_arg_interval: 11  # selection interval for noncanonical argument encoding
  extended_arg_limit: 6      # maximum prefixes per function code object
  slot_mirage: false         # rename cold non-argument fast-local slots to .N without changing indexes
  slot_mirage_limit: 8
  source_only: []           # skip bytecode transforms; enabled VM remains active even when other AST layers are excluded
  ast_exclude: []           # glob list: files that keep bytecode transforms but skip source AST layers
  const_noise: 12
  tail_noise: 3
  mcs_opmap_version: 1
  opcode_replacement: true  # master switch; false keeps standard Python opcodes
  runtime_opcode_layer: true
  per_code_runtime_opcode: true
  runtime_opcode_decoys: 128
  opcode_exclude: []        # files still obfuscated, but without opcode remap/layer
  adaptive_strength: true
  adaptive_max_scale: 4
  fake_mcs_tables: 3
  split_gates: true
  split_interval: 18
  split_bad_units: 2
  split_nop_bloat: 2
  split_adaptive: true
  loop_shadow_gates: false  # experimental
  fake_code_objects: 0
  fake_code_nop_bloat: 0
  fake_code_stop_bloat: 0
  ghost_names: 24
  opcode_restore_noise: 12
  const_swamp: 16
  root_const_swamp: 0
  const_ref_chains: 0
  real_block_reorder: false # experimental
  real_block_reorder_limit: 2
  safe_dead_blocks: false   # insert skipped dead blocks; combine with oparg_poison for if-true taken-jump poison
  taken_jump_poison: false  # shorthand: enable safe_dead_blocks + oparg_poison as a taken conditional jump gate
  safe_dead_interval: 20
  safe_dead_width: 4
  safe_dead_limit: 6
  decoy_islands: false      # verified legal opaque-entry islands for cold functions
  decoy_island_ratio: 20    # percentage of eligible functions selected
  decoy_island_limit: 2     # maximum islands per selected function
  decoy_island_width: 4     # maximum legal operations in each island
  decoy_island_growth: 15   # strict per-function bytecode growth percentage
  oparg_poison: false       # dangerous / skipped safe-dead blocks only
  opaque_predicates: false  # legal opaque blocks; short parameterized functions use a runtime arg-is-arg predicate
  opaque_interval: 28
  opaque_width: 3
  opaque_limit: 4
  index_pool_shuffle: false
  index_pool_mirrors: 0
  control_flow_flatten: false # experimental / real while-state jumps
  control_flow_max_blocks: 18
  inner_opcode_tunnel: false
  opcode_runtime: std

outer:
  loader_junk: 6
  trampoline_layers: 3
  decoy_opcode_rows: 48
  fake_ref_layers: 9
  payload_splits: 3
  payload_graph_split: true
  fake_payload_mirrors: 2
  payload_graph_decoys: 16
  loader_decoy_tuples: 0
  outer_decompiler_baits: 0 # cold recursive CodeType baits for outer pyc decompilers
  outer_decompiler_bait_budget: 8192 # hard source-byte cap per protected module
  import_facade_layer: false
  reflection_metadata_decoy: false
  module_registry_protection: false
  closure_vault: false          # keep runtime key/entry references in closure cells
  tuple_gateway: false          # real Python 2 tuple-argument dispatch; naturally emits .0/.1 fast-local slots
  closure_index_mirage: false   # split runtime key/entry roles across genuine closure cells and decoys
  generator_frame_mirage: false # suspend one real and two decoy generators with similarly shaped gi_frame locals
  method_descriptor_mirage: false # bind three method descriptors; only one randomized im_func/im_self/im_class route is real
  defaults_dict_doppelganger: false # rotate real/decoy func_defaults while func_dict presents a coherent false route
  dynamic_method: false         # bind the outer invocation method at runtime
  dynamic_class: false          # construct the outer engine class with type()
  callable_proxy: false         # invoke the real loader through a __call__ object
  frame_namespace: false        # obtain globals through generator.gi_frame, without sys
  generator_stages: false       # stage outer execution through a suspended generator
  exception_state: false        # drive outer stages through typed exceptions
  no_sys_import: false          # disable sys-dependent import facade for the outer layer
  api_decoy_refs: 32

taunt:
  text: ShitArmor_DEOBF
  inner_consts: 8
  outer_refs: 24

metadata:
  poison: true
  binary: false
  name_poison: false

bad:
  dead_bad_bytecode: 8
  dead_bad_units: 24
  dead_nop_bloat: 96
  dead_stop_bloat: 48
  dead_arg_poison: 12
  dead_exception_poison: 6
  dead_call_poison: 6
'''
