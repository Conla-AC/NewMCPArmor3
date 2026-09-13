# Python 3.13 migration

## Runtime contract

- Host CLI and project pipeline: CPython 3.13.
- NetEase generated source and bytecode: CPython 2.7.
- Target bytecode compiler: isolated `compat.py27_worker` process.

The split is required because `CodeType`, opcode layouts and marshal streams
are not portable between CPython releases. The host never places Python 3.13
code objects into a NetEase payload.

## Configuration

Set `MCPARMOR_PY27` when the target compiler is not installed at
`C:\Python27\python.exe`:

```powershell
$env:MCPARMOR_PY27 = 'D:\runtime\Python27\python.exe'
python -m MCP_Armor_Src --config config.yaml
```

The interpreter can also be stored in YAML. Both an installation directory
and the full executable path are accepted:

```yaml
runtime:
  python27: D:/runtime/Python27
```

## Verification

Run host checks with Python 3.13 and execute generated target probes with
Python 2.7:

```powershell
python -m compileall -q -f MCP_Armor_Src
python -m MCP_Armor_Src --show-hwid
python tests/run_static_check.py
python tests/run_reflection_bootstrap.py
python tests/run_resource_budget.py
python tests/run_python313_migration.py
```\n