param(
    [string]$Python = 'C:\Users\GuoDo\AppData\Local\Programs\Python\Python313\python.exe',
    [ValidateSet('CLI', 'UI', 'EasyUI')]
    [string[]]$Targets = @('CLI', 'UI', 'EasyUI')
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Nuitka = Join-Path $Root 'build\_nuitka_py313'
$Cache = Join-Path $Root 'build\nuitka_cache'
$Work = Join-Path $Root 'build\nuitka_three'
$Release = Join-Path $Root 'Pack_Nuitka_Enigma_Input'
$Worker = Join-Path $Root 'build\py27_worker\dist\MCPArmor_Py27_Worker.exe'
$License = Join-Path $Root 'i.txt'

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Python 3.13 not found: $Python"
}
if (-not (Test-Path -LiteralPath $Worker -PathType Leaf)) {
    & (Join-Path $Root 'build\build_py27_worker.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Python 2.7 worker build failed' }
}
New-Item -ItemType Directory -Force -Path $Cache, $Work, $Release | Out-Null
$env:PYTHONPATH = $Nuitka
$env:NUITKA_CACHE_DIR = $Cache
$env:PYTHONDONTWRITEBYTECODE = '1'

$common = @(
    '-m', 'nuitka', '--onefile', '--standalone', '--zig',
    '--assume-yes-for-downloads', '--remove-output',
    '--onefile-no-compression', '--jobs=8',
    "--output-dir=$Work", '--include-package=MCP_Armor_Src'
)

function Build-Target([string]$Entry, [string]$Name, [bool]$Gui, [string[]]$Extra) {
    Write-Host "[Nuitka] Building $Name ..."
    $console = if ($Gui) { '--windows-console-mode=disable' } else { '--windows-console-mode=force' }
    $args = $common + @($console, "--output-filename=$Name") + $Extra + @($Entry)
    & $Python @args
    if ($LASTEXITCODE -ne 0) { throw "Nuitka failed: $Name ($LASTEXITCODE)" }
    $built = Join-Path $Work $Name
    if (-not (Test-Path -LiteralPath $built -PathType Leaf)) { throw "Missing output: $built" }
    Copy-Item -LiteralPath $built -Destination (Join-Path $Release $Name) -Force
}

if ($Targets -contains 'CLI') {
    Build-Target (Join-Path $Root 'main.py') '01_MCPArmor_CLI.exe' $false @()
}
if ($Targets -contains 'UI') {
    Build-Target (Join-Path $Root 'MCP_Armor_UI\main.py') '02_MCPArmor_UI.exe' $true @(
        '--enable-plugin=tk-inter', '--include-package=MCP_Armor_UI',
        "--include-data-dir=$(Join-Path $Root 'MCP_Armor_UI\assets')=MCP_Armor_UI/assets",
        "--include-data-files=$Worker=MCPArmor_Py27_Worker.exe"
    )
}
if ($Targets -contains 'EasyUI') {
    Build-Target (Join-Path $Root 'MCP_Armor_Easy_UI\main.py') '03_MCPArmor_Easy_UI.exe' $true @(
        '--enable-plugin=tk-inter', '--include-package=MCP_Armor_Easy_UI',
        "--include-data-dir=$(Join-Path $Root 'MCP_Armor_Easy_UI\assets')=MCP_Armor_Easy_UI/assets",
        "--include-data-files=$Worker=MCPArmor_Py27_Worker.exe"
    )
}

$hashes = Get-ChildItem -LiteralPath $Release -Filter '*.exe' | Sort-Object Name | ForEach-Object {
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
    '{0}  {1}  {2}' -f $hash.Hash, $_.Length, $_.Name
}
$hashes | Set-Content -LiteralPath (Join-Path $Release 'SHA256.txt') -Encoding ascii
if (Test-Path -LiteralPath $License -PathType Leaf) {
    # Keep the policy external to the onefile executable so it can be updated
    # without rebuilding.  The runtime searches beside the EXE first.
    Copy-Item -LiteralPath $License -Destination (Join-Path $Release 'i.txt') -Force
    Write-Host "[Nuitka] Copied local license policy: $License"
}
Write-Host "[Nuitka] Complete: $Release"\n