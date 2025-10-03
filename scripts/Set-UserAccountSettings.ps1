# Script 3: User Account Settings Configuration (Automated via README)
# Windows Server 2019/2022
# Must be run with Administrator privileges

# ===============================
# Check if running as Administrator
# ===============================
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
  exit 1
}

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  User Account Settings Configuration" -ForegroundColor Cyan
Write-Host "======================================`n" -ForegroundColor Cyan

# ===============================
# Setup Logging
# ===============================
$logPath = "$env:USERPROFILE\Downloads\CyberPatriot_UserConfig.log"
"=== CyberPatriot User Config Log - $(Get-Date) ===" | Out-File -FilePath $logPath -Encoding UTF8

function Write-Log {
  param([string]$Message)
  $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
}

# ===============================
# Locate CyberPatriot README
# ===============================
$desktopPaths = @(
  [Environment]::GetFolderPath("Desktop"),
  "$env:PUBLIC\Desktop"
)

$readmePath = $desktopPaths | ForEach-Object {
  Get-ChildItem -Path $_ -Filter "*CyberPatriot*README*" -ErrorAction SilentlyContinue
} | Select-Object -First 1

if (-not $readmePath) {
  Write-Host "ERROR: CyberPatriot README not found on Desktop!" -ForegroundColor Red
  Write-Log "ERROR: CyberPatriot README not found on Desktop!"
  exit 1
}

Write-Host "Found README: $($readmePath.FullName)" -ForegroundColor Green
Write-Log "Found README at path: $($readmePath.FullName)"

$readmeContent = Get-Content -Path $readmePath.FullName -Raw

# ===============================
# Log Critical Services section
# ===============================
$criticalServices = ($readmeContent -split "Critical Services:")[1]
Write-Host "`nLogging Critical Services section..." -ForegroundColor Cyan
Write-Log "=== Critical Services Section ==="
$criticalServices -split "`n" | ForEach-Object { Write-Log $_ }
Write-Log "=== End Critical Services ==="

# ===============================
# Parse Administrators and Users
# ===============================
$adminsBlock = [regex]::Match($criticalServices, "Authorized Administrators:(.+?)Authorized Users:", "Singleline").Groups[1].Value.Trim()
$usersBlock = [regex]::Match($criticalServices, "Authorized Users:(.+)", "Singleline").Groups[1].Value.Trim()

$authorizedAdmins = @()
$adminPasswordMap = @{}
$adminMatches = [regex]::Matches($adminsBlock, "(\w+)\s+password:\s+(\S+)")
foreach ($m in $adminMatches) {
  $username = $m.Groups[1].Value
  $password = $m.Groups[2].Value
  $authorizedAdmins += $username
  $adminPasswordMap[$username] = $password
}

$authorizedUsers = $usersBlock -split "\s+" | Where-Object { $_ -match "^\w+$" }

# Log what was parsed
Write-Log "`n=== Parsed Authorized Administrators ==="
foreach ($u in $authorizedAdmins) {
  Write-Log "Admin: $u - Password: $($adminPasswordMap[$u])"
}

Write-Log "`n=== Parsed Authorized Users ==="
foreach ($u in $authorizedUsers) {
  Write-Log "User: $u"
}

# Combine all authorized accounts
$allAuthorized = $authorizedAdmins + $authorizedUsers

# ===============================
# Process Local Users
# ===============================
$allUsers = Get-LocalUser | Where-Object {
  $_.Name -notlike "DefaultAccount" -and
  $_.Name -notlike "Guest" -and
  $_.Name -notlike "WDAGUtilityAccount"
}

Write-Host "`nProcessing User Accounts..." -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray
Write-Log "Processing Local Users..."

foreach ($user in $allUsers) {
  Write-Host "`nUser: $($user.Name)" -ForegroundColor Yellow
  Write-Log "User: $($user.Name)"

  if ($allAuthorized -contains $user.Name) {
    Write-Host "  Status: AUTHORIZED" -ForegroundColor Green
    Write-Log "  Status: AUTHORIZED (found in parsed README)"

    if (-not $user.Enabled) {
      Write-Host "  Action: Enabling account..." -ForegroundColor Cyan
      Write-Log "  Action: Enabling account..."
      Enable-LocalUser -Name $user.Name
    }

    if ($authorizedAdmins -contains $user.Name) {
      $plainPassword = $adminPasswordMap[$user.Name]
      if ($plainPassword) {
        $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
        Set-LocalUser -Name $user.Name -Password $securePassword
        Write-Host "  Action: Password reset for admin $($user.Name)" -ForegroundColor Cyan
        Write-Log "  Action: Password reset for admin $($user.Name)"
      }
    }

    net user $user.Name /logonpasswordchg:yes | Out-Null
    Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
    Write-Host "  Result: Password change required at next logon" -ForegroundColor Green
    Write-Log "  Result: Password change required at next logon"
  }
  else {
    Write-Host "  Status: UNAUTHORIZED" -ForegroundColor Red
    Write-Log "  Status: UNAUTHORIZED (not found in parsed README)"

    if ($user.Enabled) {
      Write-Host "  Action: Disabling account..." -ForegroundColor Cyan
      Write-Log "  Action: Disabling account..."
      Disable-LocalUser -Name $user.Name
      Write-Host "  Result: Account DISABLED" -ForegroundColor Red
      Write-Log "  Result: Account DISABLED"
    }
    else {
      Write-Host "  Result: Account already disabled" -ForegroundColor Gray
      Write-Log "  Result: Account already disabled"
    }
  }
}

# ===============================
# Final Report
# ===============================
Write-Host "`n" + "=" * 60 -ForegroundColor Gray
Write-Host "`nFinal Account Status Report:" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray
Write-Log "Final Account Status Report:"

foreach ($user in $allUsers) {
  $status = if ($user.Enabled) { "ENABLED" } else { "DISABLED" }
  $color = if ($user.Enabled) { "Green" } else { "Red" }
  $authorized = if ($allAuthorized -contains $user.Name) { "[AUTHORIZED]" } else { "[UNAUTHORIZED]" }

  Write-Host "$($user.Name.PadRight(20)) - $status $authorized" -ForegroundColor $color
  Write-Log "$($user.Name.PadRight(20)) - $status $authorized"
}

Write-Host "`nConfiguration Complete!" -ForegroundColor Green
Write-Log "Configuration Complete!"

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  - Authorized users: Enabled, password change required at next logon" -ForegroundColor White
Write-Host "  - Authorized admins: Passwords reset from README + change required" -ForegroundColor White
Write-Host "  - Unauthorized users: Accounts disabled" -ForegroundColor White

Write-Log "Summary:"
Write-Log "  - Authorized users: Enabled, password change required at next logon"
Write-Log "  - Authorized admins: Passwords reset from README + change required"
Write-Log "  - Unauthorized users: Accounts disabled"

Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "Log file saved to: $logPath" -ForegroundColor Yellow
Write-Log "Script execution complete. Log closed."

# Auto-open the log in Notepad
Start-Process notepad.exe $logPath
