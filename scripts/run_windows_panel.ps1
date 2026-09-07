#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$venvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    throw "找不到 .venv\Scripts\python.exe，先运行 scripts\setup_windows.ps1"
}

$envFile = Join-Path $Root ".env.monitor"

function Import-MonitorEnv([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($raw in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith("#")) { continue }
        $eq = $line.IndexOf("=")
        if ($eq -lt 1) { continue }
        $key = $line.Substring(0, $eq).Trim()
        if ($key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { continue }
        $val = $line.Substring($eq + 1).Trim()
        if ($val.Length -ge 2 -and $val.StartsWith('"') -and $val.EndsWith('"')) {
            $val = $val.Substring(1, $val.Length - 2)
        }
        $existing = [Environment]::GetEnvironmentVariable($key, "Process")
        if ([string]::IsNullOrWhiteSpace($existing)) {
            Set-Item -Path "Env:$key" -Value $val
        }
    }
}

function Save-MonitorToken([string]$Path, [string]$Token) {
    $lines = New-Object System.Collections.Generic.List[string]
    $replaced = $false
    if (Test-Path -LiteralPath $Path) {
        foreach ($raw in Get-Content -LiteralPath $Path -Encoding UTF8) {
            if ($raw -match '^\s*MONITOR_TOKEN\s*=') {
                [void]$lines.Add("MONITOR_TOKEN=$Token")
                $replaced = $true
            } else {
                [void]$lines.Add($raw)
            }
        }
    }
    if (-not $replaced) {
        [void]$lines.Add("MONITOR_TOKEN=$Token")
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllLines($Path, $lines.ToArray(), $utf8NoBom)
}

Import-MonitorEnv $envFile

if (-not $env:MONITOR_TOKEN) {
    $env:MONITOR_TOKEN = & $venvPy -c "import secrets; print(secrets.token_urlsafe(32))"
    Save-MonitorToken $envFile $env:MONITOR_TOKEN
    Write-Host "Generated MONITOR_TOKEN and saved to .env.monitor"
}
$env:MONITOR_HOST = if ($env:MONITOR_HOST) { $env:MONITOR_HOST } else { "127.0.0.1" }
$env:MONITOR_PORT = if ($env:MONITOR_PORT) { $env:MONITOR_PORT } else { "8787" }
$env:PYTHONUNBUFFERED = "1"
$env:PYTHONUTF8 = "1"
if (-not $env:GROK_HEADLESS) { $env:GROK_HEADLESS = "1" }
$env:GROK_USE_XVFB = "0"
# 本机 Clash/Kookeey 动态家宽转发口；可在启动前显式覆盖。
if (-not $env:PROXY_HOME_PORTS) { $env:PROXY_HOME_PORTS = ((17901..17950) -join ",") }

Write-Host "Panel http://$($env:MONITOR_HOST):$($env:MONITOR_PORT)/  token=$($env:MONITOR_TOKEN)"
& $venvPy -u (Join-Path $Root "webui\monitor.py")
exit $LASTEXITCODE
