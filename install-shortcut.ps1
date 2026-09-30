$ErrorActionPreference = 'Stop'
$batPath  = Join-Path $PSScriptRoot 'start.bat'
$iconPath = Join-Path $PSScriptRoot 'web\static\logo.png'
$desktop  = [Environment]::GetFolderPath('Desktop')

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $desktop 'SecAutoMind.lnk'))
$shortcut.TargetPath = $batPath
$shortcut.WorkingDirectory = $PSScriptRoot
$shortcut.WindowStyle = 1
$shortcut.Description = 'SecAutoMind - start the local server and open the web console'
if (Test-Path $iconPath) { $shortcut.IconLocation = "$iconPath,0" }
$shortcut.Save()

Write-Host "[OK] Desktop shortcut created: $desktop\SecAutoMind.lnk"

# Resolve the service port from config.yaml so the hint matches what the app really listens on.
$cfg = Join-Path $PSScriptRoot 'config.yaml'
if (-not (Test-Path -LiteralPath $cfg)) { $cfg = Join-Path $PSScriptRoot 'config.example.yaml' }
$port = 8080
if (Test-Path -LiteralPath $cfg) {
    $inServer = $false
    foreach ($line in Get-Content -LiteralPath $cfg) {
        if ($line -match '^server:\s*$') { $inServer = $true; continue }
        if ($inServer -and $line -match '^[^ \t]') { break }
        if ($inServer -and $line -match '^\s*port:\s*(\d+)') { $port = $matches[1]; break }
    }
}
Write-Host "    Double-click to start the server and open http://127.0.0.1:$port/"
