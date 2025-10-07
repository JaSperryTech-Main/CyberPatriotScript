# =========================
# Firefox Updater Script
# =========================
# Run as Administrator

# -----------------------
# Admin check
# -----------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
  exit 1
}

# -----------------------
# Logging
# -----------------------
$logPath = "$env:USERPROFILE\Downloads\Firefox_Update.log"
"=== Firefox Update Log - $(Get-Date) ===" | Out-File -FilePath $logPath -Encoding UTF8
function Write-Log {
  param([string]$Message)
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
}

Write-Host "Starting Firefox update..." -ForegroundColor Cyan
Write-Log "Script started."

# -----------------------
# Detect Firefox installation
# -----------------------
$firefoxPath = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
if (-not (Test-Path $firefoxPath)) {
  $firefoxPath = "$env:ProgramFiles(x86)\Mozilla Firefox\firefox.exe"
}

if (-not (Test-Path $firefoxPath)) {
  Write-Host "ERROR: Firefox is not installed on this system." -ForegroundColor Red
  Write-Log "Firefox not found."
  exit 1
}

$currentVersion = (& $firefoxPath -v) -replace 'Mozilla Firefox ', ''
Write-Host "Detected Firefox version: $currentVersion" -ForegroundColor Green
Write-Log "Detected Firefox version: $currentVersion"

# -----------------------
# Download latest Firefox installer
# -----------------------
$installerUrl = "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US"
$installerPath = "$env:TEMP\Firefox_Installer.exe"

Write-Host "Downloading latest Firefox installer..." -ForegroundColor Cyan
Write-Log "Downloading installer from $installerUrl"
try {
  Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
  Write-Host "Download complete: $installerPath" -ForegroundColor Green
  Write-Log "Installer downloaded successfully."
}
catch {
  Write-Host "ERROR: Failed to download installer: $_" -ForegroundColor Red
  Write-Log "Download failed: $_"
  exit 1
}

# -----------------------
# Run installer silently
# -----------------------
Write-Host "Running Firefox installer..." -ForegroundColor Cyan
Write-Log "Running installer silently."
try {
  Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait
  Write-Host "Firefox update completed successfully." -ForegroundColor Green
  Write-Log "Update completed successfully."
}
catch {
  Write-Host "ERROR: Failed to run installer: $_" -ForegroundColor Red
  Write-Log "Installer failed: $_"
  exit 1
}

# -----------------------
# Cleanup
# -----------------------
Remove-Item $installerPath -Force
Write-Host "Installer removed from TEMP folder." -ForegroundColor Cyan
Write-Log "Installer removed."

Write-Host "`nLog saved to $logPath" -ForegroundColor Yellow
Start-Process notepad.exe $logPath
