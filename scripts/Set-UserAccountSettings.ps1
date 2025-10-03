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
  exit 1
}

Write-Host "Found README: $($readmePath.FullName)" -ForegroundColor Green
$readmeContent = Get-Content -Path $readmePath.FullName -Raw

# ===============================
# Parse Critical Services section
# ===============================
$criticalServices = ($readmeContent -split "Critical Services:")[1]

# Extract Administrators block
$adminsBlock = [regex]::Match($criticalServices, "Authorized Administrators:(.+?)Authorized Users:", "Singleline").Groups[1].Value.Trim()
# Extract Users block
$usersBlock = [regex]::Match($criticalServices, "Authorized Users:(.+)", "Singleline").Groups[1].Value.Trim()

# Parse administrators into dictionary of username → password
$authorizedAdmins = @()
$adminPasswordMap = @{}

$adminMatches = [regex]::Matches($adminsBlock, "(\w+)\s+password:\s+(\S+)")
foreach ($m in $adminMatches) {
  $username = $m.Groups[1].Value
  $password = $m.Groups[2].Value
  $authorizedAdmins += $username
  $adminPasswordMap[$username] = $password
}

# Parse users into array
$authorizedUsers = $usersBlock -split "\s+" | Where-Object { $_ -match "^\w+$" }

Write-Host "`nAuthorized Administrators:" -ForegroundColor Cyan
foreach ($u in $authorizedAdmins) {
  Write-Host " - $u (pw: $($adminPasswordMap[$u]))" -ForegroundColor White
}

Write-Host "`nAuthorized Users:" -ForegroundColor Yellow
foreach ($u in $authorizedUsers) {
  Write-Host " - $u" -ForegroundColor White
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

foreach ($user in $allUsers) {
  Write-Host "`nUser: $($user.Name)" -ForegroundColor Yellow

  if ($allAuthorized -contains $user.Name) {
    # AUTHORIZED
    Write-Host "  Status: AUTHORIZED" -ForegroundColor Green

    if (-not $user.Enabled) {
      Write-Host "  Action: Enabling account..." -ForegroundColor Cyan
      Enable-LocalUser -Name $user.Name
    }

    # If admin, reset password from README
    if ($authorizedAdmins -contains $user.Name) {
      $plainPassword = $adminPasswordMap[$user.Name]
      if ($plainPassword) {
        $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
        Set-LocalUser -Name $user.Name -Password $securePassword
        Write-Host "  Action: Password reset for admin $($user.Name)" -ForegroundColor Cyan
      }
    }

    # Force password change at next logon
    net user $user.Name /logonpasswordchg:yes | Out-Null
    Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
    Write-Host "  Result: Password change required at next logon" -ForegroundColor Green
  }
  else {
    # UNAUTHORIZED
    Write-Host "  Status: UNAUTHORIZED" -ForegroundColor Red
    if ($user.Enabled) {
      Write-Host "  Action: Disabling account..." -ForegroundColor Cyan
      Disable-LocalUser -Name $user.Name
      Write-Host "  Result: Account DISABLED" -ForegroundColor Red
    }
    else {
      Write-Host "  Result: Account already disabled" -ForegroundColor Gray
    }
  }
}

# ===============================
# Final Report
# ===============================
Write-Host "`n" + "=" * 60 -ForegroundColor Gray
Write-Host "`nFinal Account Status Report:" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$allUsers = Get-LocalUser | Where-Object {
  $_.Name -notlike "DefaultAccount" -and
  $_.Name -notlike "Guest" -and
  $_.Name -notlike "WDAGUtilityAccount"
}

foreach ($user in $allUsers) {
  $status = if ($user.Enabled) { "ENABLED" } else { "DISABLED" }
  $color = if ($user.Enabled) { "Green" } else { "Red" }
  $authorized = if ($allAuthorized -contains $user.Name) { "[AUTHORIZED]" } else { "[UNAUTHORIZED]" }

  Write-Host "$($user.Name.PadRight(20)) - $status $authorized" -ForegroundColor $color
}

Write-Host "`nConfiguration Complete!" -ForegroundColor Green
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  - Authorized users: Enabled, password change required at next logon" -ForegroundColor White
Write-Host "  - Authorized admins: Passwords reset from README + change required" -ForegroundColor White
Write-Host "  - Unauthorized users: Accounts disabled" -ForegroundColor White
Write-Host "`n======================================" -ForegroundColor Cyan
