# main.ps1
Write-Host "Fetching and running CyberPatriot scripts... v2.4" -ForegroundColor Cyan

Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-LockoutPolicy.ps1 | Invoke-Expression
Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-PasswordPolicy.ps1 | Invoke-Expression
Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-UserAccountSettings.ps1 | Invoke-Expression

Write-Host "All remote scripts completed!" -ForegroundColor Green
