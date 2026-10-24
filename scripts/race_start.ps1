# race_start.ps1 —— SecAutoMind Runner 一键启动（Windows/本机）
#
# 做的事（和 race_start.sh 同功能）：
#   1. 设参赛推荐 env var
#   2. 自动探测 runner 二进制
#   3. 日志落盘到 .\logs\runner_YYYYMMDD_HHMMSS.log
#   4. 启动后 tail -f 实时看；Ctrl+C 优雅停止
#
# 用法：
#   $env:CTF2_AGENT_TOKEN='xxx'; .\scripts\race_start.ps1
#   $env:CTF2_AGENT_TOKEN='xxx'; .\scripts\race_start.ps1 -DryRun
#   .\scripts\race_start.ps1 -CheckOnly

param(
  [switch]$DryRun,
  [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot

# ── env 自动设 ────────────────────────────────────────────────
$env:CTF_POLL_INTERVAL       = if ($env:CTF_POLL_INTERVAL)       { $env:CTF_POLL_INTERVAL }       else { "30" }
$env:CTF_SOLVE_TIMEOUT       = if ($env:CTF_SOLVE_TIMEOUT)       { $env:CTF_SOLVE_TIMEOUT }       else { "180" }
$env:CTF_MAX_CONCURRENCY     = if ($env:CTF_MAX_CONCURRENCY)     { $env:CTF_MAX_CONCURRENCY }     else { "4" }
$env:CTF_MAX_RETRY_SUBMIT    = if ($env:CTF_MAX_RETRY_SUBMIT)    { $env:CTF_MAX_RETRY_SUBMIT }    else { "2" }
$env:CTF_AUTO_BUILD_ENV      = if ($env:CTF_AUTO_BUILD_ENV)      { $env:CTF_AUTO_BUILD_ENV }      else { "true" }
$env:CTF_AUTO_FETCH_DETAIL   = if ($env:CTF_AUTO_FETCH_DETAIL)   { $env:CTF_AUTO_FETCH_DETAIL }   else { "true" }
$env:CTF_AUTO_FETCH_ATTACHMENT = if ($env:CTF_AUTO_FETCH_ATTACHMENT) { $env:CTF_AUTO_FETCH_ATTACHMENT } else { "true" }
$env:CTF_AUTO_RELEASE_ENV    = if ($env:CTF_AUTO_RELEASE_ENV)    { $env:CTF_AUTO_RELEASE_ENV }    else { "true" }
$env:CTF_AUTOSOLVE_SUBMIT    = if ($env:CTF_AUTOSOLVE_SUBMIT)    { $env:CTF_AUTOSOLVE_SUBMIT }    else { "true" }
$env:CTF_FIRST_BLOOD_WINDOW  = if ($env:CTF_FIRST_BLOOD_WINDOW)  { $env:CTF_FIRST_BLOOD_WINDOW }  else { "900" }
$env:CTF_FIRST_BLOOD_INTERVAL = if ($env:CTF_FIRST_BLOOD_INTERVAL) { $env:CTF_FIRST_BLOOD_INTERVAL } else { "10" }
$env:RUNNER_LLM_FALLBACK     = if ($env:RUNNER_LLM_FALLBACK)     { $env:RUNNER_LLM_FALLBACK }     else { "false" }

if ($DryRun) { $env:CTF_AUTOSOLVE_SUBMIT = "false" }

# ── runner 二进制探测 ────────────────────────────────────────
$RunnerBin = $env:RUNNER_BIN
if (-not $RunnerBin) {
  foreach ($cand in @(
    "$RepoRoot\runner_ctf.exe",
    "$HOME\ctf_run\runner_v2.exe",
    "$HOME\ctf_run\runner.exe",
    "$RepoRoot\cmd\runner\runner_ctf.exe"
  )) {
    if (Test-Path $cand) { $RunnerBin = $cand; break }
  }
}

if (-not $RunnerBin -and (Get-Command go -ErrorAction SilentlyContinue)) {
  $RunnerBin = "go run $RepoRoot\cmd\runner"
}

if (-not $RunnerBin) {
  Write-Host "❌ 找不到 runner 二进制" -ForegroundColor Red; exit 1
}

# ── preflight ────────────────────────────────────────────────
if ($CheckOnly) {
  Write-Host "=== Preflight ==="
  Write-Host "RUNNER_BIN       : $RunnerBin"
  Write-Host "CTF2_AGENT_TOKEN : $(if ($env:CTF2_AGENT_TOKEN) { '已设' } else { '未设' })"
  Write-Host "skills_dir       : $(if ($env:CTF_SKILLS_DIR) { $env:CTF_SKILLS_DIR } else { '未设（runner 自动探测）' })"
  Write-Host "angr/pwnlib      : $(try { & 'C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe' -c 'import angr, pwnlib' 2>$null; if ($LASTEXITCODE -eq 0) { '✅' } else { '⚠️ 未装' } } catch { '⚠️ 未装' })"
  exit 0
}

# ── 必须项 ────────────────────────────────────────────────
if (-not $env:CTF2_AGENT_TOKEN) {
  Write-Host "❌ CTF2_AGENT_TOKEN 未设" -ForegroundColor Red
  Write-Host '   用法: $env:CTF2_AGENT_TOKEN="xxx"; .\scripts\race_start.ps1'
  exit 1
}

# ── 日志 ────────────────────────────────────────────────
$LogDir = if ($env:LOG_DIR) { $env:LOG_DIR } else { "$RepoRoot\logs" }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir ("runner_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

Write-Host "=============================================="
Write-Host "SecAutoMind Runner 启动 (Windows)"
Write-Host "=============================================="
Write-Host "二进制    : $RunnerBin"
Write-Host "Dry-run   : $DryRun"
Write-Host "Max Conc  : $env:CTF_MAX_CONCURRENCY"
Write-Host "Auto Subm : $env:CTF_AUTOSOLVE_SUBMIT"
Write-Host "LLM Layer : $env:RUNNER_LLM_FALLBACK"
Write-Host "日志      : $LogFile"
Write-Host "=============================================="

# ── 启动 ────────────────────────────────────────────────
Set-Location $RepoRoot
if ($RunnerBin -match "^go run") {
  $proc = Start-Process -FilePath "go" -ArgumentList "run", "$RepoRoot\cmd\runner" `
    -RedirectStandardOutput $LogFile -RedirectStandardError $LogFile `
    -PassThru -NoNewWindow
} else {
  $proc = Start-Process -FilePath $RunnerBin `
    -RedirectStandardOutput $LogFile -RedirectStandardError $LogFile `
    -PassThru -NoNewWindow
}

Write-Host "✅ Runner 已启动，PID=$($proc.Id)"
Write-Host "实时日志（Ctrl+C 停止）..."

try {
  Get-Content -Path $LogFile -Wait -Tail 10
} finally {
  Write-Host "`n停止 runner PID=$($proc.Id)..."
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  Write-Host "已停止"
}
