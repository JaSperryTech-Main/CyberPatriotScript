# Script 3: User Account Settings Configuration
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
Write-Host "  User Account Settings Configuration" -ForegroundColor Cyan
Write-Host "======================================`n" -ForegroundColor Cyan

# Define authorized users (CUSTOMIZE THIS LIST)
$authorizedUsers = @(
  "dovahkiin",
  "delphine",
  "esbern",
  "arngeir",
  "paarthurnax"
  # Add your authorized usernames here
)

Write-Host "Authorized Users:" -ForegroundColor Yellow
$authorizedUsers | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
Write-Host ""

# Get all local users (exclude built-in system accounts)
$allUsers = Get-LocalUser | Where-Object { 
  $_.Name -notlike "DefaultAccount" -and 
  $_.Name -notlike "Guest" -and
  $_.Name -notlike "WDAGUtilityAccount"
}

Write-Host "Processing User Accounts..." -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

foreach ($user in $allUsers) {
  Write-Host "`nUser: $($user.Name)" -ForegroundColor Yellow
    
  if ($authorizedUsers -contains $user.Name) {
    # AUTHORIZED USER - Force password change at next logon
    Write-Host "  Status: AUTHORIZED" -ForegroundColor Green
        
    # Check if account is enabled
    if (-not $user.Enabled) {
      Write-Host "  Action: Enabling account..." -ForegroundColor Cyan
      Enable-LocalUser -Name $user.Name
    }
        
    # Set 'User must change password at next logon'
    Write-Host "  Action: Setting 'User must change password at next logon'" -ForegroundColor Cyan
        
    # Using net user command (works for local accounts)
    $result = net user $user.Name /logonpasswordchg:yes 2>&1
        
    # Also ensure password never expires is disabled
    Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
        
    Write-Host "  Result: Password change required at next logon" -ForegroundColor Green
        
  }
  else {
    # UNAUTHORIZED USER - Disable account
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
  $authorized = if ($authorizedUsers -contains $user.Name) { "[AUTHORIZED]" } else { "[UNAUTHORIZED]" }
    
  Write-Host "$($user.Name.PadRight(20)) - $status $authorized" -ForegroundColor $color
}

Write-Host "`n" + "=" * 60 -ForegroundColor Gray
Write-Host "Configuration Complete!" -ForegroundColor Green
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  - Authorized users: Required to change password at next logon" -ForegroundColor White
Write-Host "  - Unauthorized users: Accounts disabled" -ForegroundColor White
Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "Note: Users will be prompted to change password on next login" -ForegroundColor Yellow