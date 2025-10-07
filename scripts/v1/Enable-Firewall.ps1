# ========================================
# Enable Windows Firewall Protection
# ========================================
# Run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
  exit 1
}

# -----------------------
# Logging
# -----------------------
$logPath = "$env:USERPROFILE\Downloads\EnableFirewall.log"
"=== Enable Firewall Log - $(Get-Date) ===" | Out-File -FilePath $logPath -Encoding UTF8

function Write-Log {
  param([string]$Message)
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
}

Write-Host "Enabling Windows Firewall for all profiles..." -ForegroundColor Cyan
Write-Log "Script started."

# -----------------------
# Enable Firewall
# -----------------------
try {
  Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
  Write-Host "Windows Firewall has been enabled for Domain, Private, and Public profiles." -ForegroundColor Green
  Write-Log "Firewall enabled: Domain=True, Private=True, Public=True"
}
catch {
  Write-Host "ERROR: Failed to enable firewall: $_" -ForegroundColor Red
  Write-Log "ERROR: Failed to enable firewall: $_"
  exit 1
}

# -----------------------
# Confirm Firewall Status
# -----------------------
try {
  $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled
  foreach ($p in $profiles) {
    Write-Host "$($p.Name) Firewall Enabled: $($p.Enabled)" -ForegroundColor Cyan
    Write-Log "$($p.Name) Firewall Enabled: $($p.Enabled)"
  }
}
catch {
  Write-Host "ERROR: Failed to get firewall status: $_" -ForegroundColor Red
  Write-Log "ERROR: Failed to get firewall status: $_"
}

Write-Host "`nLog saved to $logPath" -ForegroundColor Yellow
Start-Process notepad.exe $logPath
