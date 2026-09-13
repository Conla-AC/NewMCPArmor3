# Function split / output date

Folder mode supports `source.function_split: true` (or
`--source-function-split`).  MCPArmor copies the project to a temporary
staging tree, extracts eligible top-level functions and ordinary class methods
into sibling `__mcp_fn_*.py` modules, injects imports, then runs module Rename
and the remaining AST/bytecode pipeline.  The original source tree is left
unchanged.  Decorated functions, functions with default expressions,
generators, multiline signatures and nested definitions stay in place to
preserve Python 2/NetEase behavior.

`basic.output_date` / `--output-date` controls the watermark and emitted-pyc
timestamp.  The default is `2012-03-15`; a full `YYYY-MM-DD HH:MM:SS` value is
also accepted.

See `tests/project_split_output` for a runnable Python 2 sample.\n