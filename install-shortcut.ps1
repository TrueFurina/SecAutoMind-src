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
Write-Host "    Double-click to start the server and open http://127.0.0.1:8080/"
