# Script 2: Account Lockout Policy Configuration
# Windows Server 2019/2022
# This script must be run with Administrator privileges

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
  Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
  Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
  exit 1
}

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Account Lockout Policy Configuration" -ForegroundColor Cyan
Write-Host "======================================`n" -ForegroundColor Cyan

try {
  # Set lockout policies using secedit
  $secEditConfig = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
LockoutBadCount = 10
ResetLockoutCount = 30
LockoutDuration = 30
"@

  # Create temporary configuration file
  $tempFile = [System.IO.Path]::GetTempFileName()
  $secEditConfig | Out-File $tempFile -Encoding unicode

  # Apply the security policy
  Write-Host "Applying account lockout policy settings..." -ForegroundColor Yellow
  secedit /configure /db secedit.sdb /cfg $tempFile /areas SECURITYPOLICY | Out-Null

  # Clean up temporary file
  Remove-Item $tempFile -Force

  Write-Host "`nAccount Lockout Policy Configured Successfully!" -ForegroundColor Green
  Write-Host "`nApplied Settings:" -ForegroundColor Cyan
  Write-Host "  - Account lockout duration: 30 minutes" -ForegroundColor White
  Write-Host "  - Account lockout threshold: 10 invalid attempts" -ForegroundColor White
  Write-Host "  - Reset account lockout counter after: 30 minutes" -ForegroundColor White
    
  Write-Host "`n======================================" -ForegroundColor Cyan
  Write-Host "Note: Run 'gpupdate /force' to apply changes immediately." -ForegroundColor Yellow

}
catch {
  Write-Host "ERROR: Failed to configure account lockout policy" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit 1
}