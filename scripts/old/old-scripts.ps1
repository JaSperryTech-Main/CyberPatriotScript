# main.ps1
Write-Host "Fetching and running CyberPatriot scripts..." -ForegroundColor Cyan

Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/old/index01.ps1 | Invoke-Expression
Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/old/index02.ps1 | Invoke-Expression
Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/old/index03.ps1 | Invoke-Expression
Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/old/index04.ps1 | Invoke-Expression
Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/old/index05.ps1 | Invoke-Expression
Invoke-RestMethod https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/old/index06.ps1 | Invoke-Expression

Write-Host "All remote scripts completed!" -ForegroundColor Green
