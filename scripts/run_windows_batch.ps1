#Requires -Version 5.1
param(
    [int]$Count = 1,
    [int]$Workers = 1
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$venvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    throw "找不到 .venv\Scripts\python.exe，先运行 scripts\setup_windows.ps1"
}

chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$env:PYTHONUNBUFFERED = "1"
$env:PYTHONUTF8 = "1"
if (-not $env:GROK_HEADLESS) { $env:GROK_HEADLESS = "1" }
if (-not $env:GROK_USE_XVFB) { $env:GROK_USE_XVFB = "0" }
if (-not $env:MONITOR_HOST) { $env:MONITOR_HOST = "127.0.0.1" }
if (-not $env:PROXY_HOME_PORTS) { $env:PROXY_HOME_PORTS = ((17901..17950) -join ",") }

& $venvPy -u (Join-Path $Root "run_batch_headless.py") $Count $Workers
exit $LASTEXITCODE
