# main.ps1

Write-Host "Running Script 1..."
. ".\scripts\Set-LockoutPolicy.ps1"

Write-Host "Running Script 2..."
. ".\scripts\Set-PasswordPolicy.ps1"

Write-Host "Running Script 3..."
. ".\scripts\Set-UserAccountSettings.ps1"

Write-Host "All scripts finished!"
