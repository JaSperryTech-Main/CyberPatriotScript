# main.ps1
Write-Host "Running CyberPatriot Scripts..." -ForegroundColor Cyan

& "$PSScriptRoot\scripts\Set-LockoutPolicy.ps1"
& "$PSScriptRoot\scripts\Set-PasswordPolicy.ps1"
& "$PSScriptRoot\scripts\Set-UserAccountSettings.ps1"

Write-Host "All scripts completed!" -ForegroundColor Green
