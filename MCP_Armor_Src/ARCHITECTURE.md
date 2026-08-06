# MCP Armor Architecture

The historical single-file implementation has been split along transformation
and runtime boundaries. The root `main.py` remains the stable command
entry point only.

## Dependency direction

```text
main -> cli -> hwid
             `-> pipeline
                 |-> ast_obf/analysis + predicates
                 |-> ast_obf/VM
                 |-> bytecode_obf
                 |-> opcode_rep_netease
                 `-> loaders

ast_obf ---------> utils
bytecode_obf ----> utils
loaders ---------> utils
```

Imports must not point upward or sideways against this graph. In particular:

- `utils` contains only dependency-light generic helpers.
- `hwid` owns machine fingerprints, XOR tokens and online license validation.
- `cli` owns argparse, YAML/config aliases, presets and validation.
- `ast_obf` owns source parsing, AST transforms and source rendering.
- `bytecode_obf` owns `CodeType`, opcode maps and bytecode transforms.
- `loaders` owns payload encoding, Code Tuple serialization and loader source.
- Cross-layer data is passed explicitly through options/results, not globals.

## Migration rules

1. Keep root `main.py` as the stable external command.
2. Add new transforms to the narrowest matching feature module.
3. Add characterization tests before changing tightly coupled algorithms.
4. Do not use wildcard imports or package-level side effects.
5. Keep all backend modules valid on CPython 2.7.18.

## Source VM

`ast_obf/analysis.py` scans the complete folder before file transforms. It
builds conservative same-module call groups, marks callback/reflection/import
escapes, assigns hot-path and size budgets, and annotates reparsed AST nodes.
`ast_obf/predicates.py` may change signatures only for closed private groups;
the definition and every resolved call site receive the same hidden predicate.
Unknown, reflected, decorated, nested, public and NetEase hot entry points keep
their original signatures.

`ast_obf/VM` compiles eligible Python 2 AST functions into a randomized
register instruction set. Small functions use fused basic-block handlers;
large functions use a shared token-dispatch interpreter and packed records.
Packed records have two storage forms: compressed text-safe records for source
output, and raw binary constants for an enclosing bytecode loader.

Full mode selects every supported function and enables loops, while disabling
duplicate bytecode CFG expansion around the VM runtime. Payloads decode lazily
on first call, opcode tokens are resolved to handlers once, and temporary
registers are reused. Generator expressions, closure factories, `with`,
`try/finally`, and generators remain native until their semantics can be
preserved without an eager or scope-changing approximation.

Flow hardening installs 1-8 independent VM dialect families per module. Each
dialect has its own opcode tokens, row layout, dispatcher and provider table.
Basic-block seeds form a live flow state; a hidden interprocedural token, when
available, derives the entry seed. VM constants use their owning block seed,
the encrypted names table uses the entry seed, and wrong transitions fail
before dispatch. Optional exception traps run only after a failed check. Hot
callbacks have a zero VM/reference budget, and large functions receive a
reduced selection budget to contain frame cost.

`ast_obf/references.py` runs before the VM and rewrites selected attribute and
method reads through polymorphic encrypted resolvers. Each module mixes XOR,
additive, and rolling encodings with randomized signatures, seals, argument
order, cache flow, and row direction. This keeps API names out of VM name
tables without changing attribute stores or descriptor semantics.

Decompiler carriers are cold AST bundles that are defined and immediately
deleted. Their recursive code constants contain tuple-argument functions,
generators, exception lattices, nested class traps, and optional bounded
binary docstrings. They never enter a real call path.

Outer pyc decompiler baits use three randomized Python-2 source shapes rather
than one stable template.  Every shape contains tuple-argument, generator or
comprehension, exception, closure, or class code objects, but only its outer
function is created at import time.  A per-module hard source-byte budget is
applied after random rendering.  The resource governor caps it to 2 KiB for
compact, 3-4 KiB for balanced, and 8-12 KiB for strong builds; micro modules
disable the layer entirely.

The optional `anti_debug` loader layer is disabled by default. It binds payload
decryption to the nearest behavior-pack `manifest.json` `header.uuid` and to a
random per-build behavior fingerprint of NetEase's native `_chacha` extension.
Module and API names are stored as encoded integer rows, and failed checks
silently perturb the real payload key. The generated outer loader contains no
plain import statements.

The broader trace/profile/module/timing and HMAC CodeType checks live behind
the separate `experimental_anti_debug` option. They are also disabled by
default because embedded Python runtimes may expose nonstandard tracing state.
Both layers run only during payload hydration and install no callback or Tick
hook.
