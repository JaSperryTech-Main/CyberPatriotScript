# ========================================
# Enable "Do not allow anonymous enumeration of SAM accounts and shares"
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
$logPath = "$env:USERPROFILE\Downloads\RestrictAnonymous.log"
"=== Restrict Anonymous Log - $(Get-Date) ===" | Out-File -FilePath $logPath -Encoding UTF8

function Write-Log {
  param([string]$Message)
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
}

Write-Host "Enabling 'Do not allow anonymous enumeration of SAM accounts and shares'..." -ForegroundColor Cyan
Write-Log "Script started."

# -----------------------
# Set registry key
# -----------------------
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$regName = "RestrictAnonymous"
try {
  Set-ItemProperty -Path $regPath -Name $regName -Value 1 -Force
  Write-Host "Setting applied successfully." -ForegroundColor Green
  Write-Log "Registry key set: $regPath\$regName = 1"
}
catch {
  Write-Host "ERROR: Failed to set registry key: $_" -ForegroundColor Red
  Write-Log "ERROR: Failed to set registry key: $_"
  exit 1
}

# -----------------------
# Confirm setting
# -----------------------
$currentValue = Get-ItemPropertyValue -Path $regPath -Name $regName
Write-Host "Current value of RestrictAnonymous: $currentValue" -ForegroundColor Cyan
Write-Log "Current value: $currentValue"

Write-Host "`nLog saved to $logPath" -ForegroundColor Yellow
Start-Process notepad.exe $logPath
