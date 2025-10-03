# main.ps1
Write-Host "Fetching and running CyberPatriot scripts..." -ForegroundColor Cyan

irm https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-LockoutPolicy.ps1 | iex
irm https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-PasswordPolicy.ps1 | iex
irm https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-UserAccountSettings.ps1 | iex

Write-Host "All remote scripts completed!" -ForegroundColor Green
