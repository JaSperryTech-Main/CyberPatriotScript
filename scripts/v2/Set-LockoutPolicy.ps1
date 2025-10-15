<#
.SYNOPSIS
    Windows Server 2019/2022 Account Lockout Policy Management Script

.DESCRIPTION
    This script configures domain or local account lockout policies including:
    - Account lockout threshold
    - Account lockout duration
    - Reset account lockout counter after
    - Lockout policy viewing and management

.NOTES
    Requires Administrator privileges
    For Domain policies: Run on Domain Controller
    For Local policies: Run on local server
#>

# Requires -RunAsAdministrator

# Function to prompt for lockout policy parameters
function Get-LockoutParameters {
  Write-Host "`n=== Account Lockout Policy Parameters ===" -ForegroundColor Cyan
  Write-Host "Press Enter to accept default values shown in [brackets]`n" -ForegroundColor Yellow
    
  $threshold = Read-Host "Account lockout threshold (invalid logon attempts, 0 = never lock) [5]"
  $threshold = if ($threshold) { [int]$threshold } else { 10 }
    
  if ($threshold -gt 0) {
    $duration = Read-Host "Account lockout duration in minutes (0 = manual unlock required) [30]"
    $duration = if ($duration) { [int]$duration } else { 30 }
        
    $window = Read-Host "Reset account lockout counter after (minutes) [30]"
    $window = if ($window) { [int]$window } else { 30 }
  }
  else {
    Write-Host "Note: Account lockout threshold is 0, so duration and counter settings are not applicable" -ForegroundColor Yellow
    $duration = 0
    $window = 0
  }
    
  return @{
    LockoutThreshold         = $threshold
    LockoutDuration          = $duration
    LockoutObservationWindow = $window
  }
}

# Function to set Domain Lockout Policy
function Set-DomainLockoutPolicy {
  param(
    [hashtable]$Parameters
  )

  Write-Host "`n=== Configuring Domain Account Lockout Policy ===" -ForegroundColor Cyan
    
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
        
    $domain = Get-ADDomain
        
    # Set lockout threshold
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName `
      -LockoutThreshold $Parameters.LockoutThreshold
        
    if ($Parameters.LockoutThreshold -gt 0) {
      # Set lockout duration and observation window
      Set-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName `
        -LockoutDuration (New-TimeSpan -Minutes $Parameters.LockoutDuration) `
        -LockoutObservationWindow (New-TimeSpan -Minutes $Parameters.LockoutObservationWindow)
    }
        
    Write-Host "`nDomain lockout policy updated successfully!" -ForegroundColor Green
        
    # Display current settings
    Write-Host "`nCurrent Domain Lockout Policy:" -ForegroundColor Cyan
    Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow | Format-List
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Note: This requires Active Directory module and Domain Controller access" -ForegroundColor Yellow
  }
}

# Function to set Local Lockout Policy
function Set-LocalLockoutPolicy {
  param(
    [hashtable]$Parameters
  )

  Write-Host "`n=== Configuring Local Account Lockout Policy ===" -ForegroundColor Cyan
    
  $secEditConfig = @"
[Unicode]
Unicode=yes
[System Access]
LockoutBadCount = $($Parameters.LockoutThreshold)
LockoutDuration = $($Parameters.LockoutDuration)
ResetLockoutCount = $($Parameters.LockoutObservationWindow)
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

  try {
    $tempFile = "$env:TEMP\lockoutpol.cfg"
    $secEditConfig | Out-File $tempFile -Encoding ASCII
        
    secedit /configure /db secedit.sdb /cfg $tempFile /areas SECURITYPOLICY | Out-Null
        
    Remove-Item $tempFile -Force
        
    Write-Host "`nLocal lockout policy updated successfully!" -ForegroundColor Green
    Write-Host "`nVerifying settings with: net accounts" -ForegroundColor Yellow
    net accounts
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to view current lockout policy
function Get-CurrentLockoutPolicy {
  param(
    [switch]$Domain,
    [switch]$Local
  )

  if ($Domain) {
    Write-Host "`n=== Current Domain Lockout Policy ===" -ForegroundColor Cyan
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      Get-ADDefaultDomainPasswordPolicy | Select-Object `
        LockoutThreshold, 
      LockoutDuration, 
      LockoutObservationWindow | Format-List
    }
    catch {
      Write-Host "Error: Cannot retrieve domain policy. Ensure AD module is installed and you're on a DC." -ForegroundColor Red
    }
  }
    
  if ($Local) {
    Write-Host "`n=== Current Local Lockout Policy ===" -ForegroundColor Cyan
    net accounts | Select-String -Pattern "Lockout"
  }
}

# Function to unlock a locked account
function Unlock-UserAccount {
  param(
    [switch]$Domain,
    [switch]$Local
  )

  if ($Domain) {
    Write-Host "`n=== Unlock Domain User Account ===" -ForegroundColor Cyan
    $username = Read-Host "Enter the username to unlock"
        
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      Unlock-ADAccount -Identity $username
      Write-Host "Account '$username' has been unlocked successfully!" -ForegroundColor Green
    }
    catch {
      Write-Host "Error: $_" -ForegroundColor Red
    }
  }
    
  if ($Local) {
    Write-Host "`n=== Unlock Local User Account ===" -ForegroundColor Cyan
    $username = Read-Host "Enter the username to unlock"
        
    try {
      net user $username /active:yes
      Write-Host "Account '$username' has been unlocked successfully!" -ForegroundColor Green
    }
    catch {
      Write-Host "Error: $_" -ForegroundColor Red
    }
  }
}

# Function to view locked accounts
function Get-LockedAccounts {
  param(
    [switch]$Domain
  )

  if ($Domain) {
    Write-Host "`n=== Locked Domain User Accounts ===" -ForegroundColor Cyan
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      $lockedAccounts = Search-ADAccount -LockedOut
            
      if ($lockedAccounts) {
        $lockedAccounts | Select-Object Name, SamAccountName, LockedOut, LastBadPasswordAttempt | Format-Table -AutoSize
        Write-Host "Total locked accounts: $($lockedAccounts.Count)" -ForegroundColor Yellow
      }
      else {
        Write-Host "No locked accounts found." -ForegroundColor Green
      }
    }
    catch {
      Write-Host "Error: $_" -ForegroundColor Red
    }
  }
}

# Main Menu
Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║   Windows Server 2019/2022 Lockout Policy Manager       ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green

Write-Host "1. Set Domain Lockout Policy (Requires DC)"
Write-Host "2. Set Local Lockout Policy"
Write-Host "3. View Current Domain Lockout Policy"
Write-Host "4. View Current Local Lockout Policy"
Write-Host "5. View Locked Domain Accounts"
Write-Host "6. Unlock Domain User Account"
Write-Host "7. Unlock Local User Account"
Write-Host "8. Exit"
Write-Host ""

$choice = Read-Host "Select an option (1-8)"

switch ($choice) {
  "1" {
    $params = Get-LockoutParameters
    Write-Host "`nApplying settings..." -ForegroundColor Yellow
    Set-DomainLockoutPolicy -Parameters $params
  }
  "2" {
    $params = Get-LockoutParameters
    Write-Host "`nApplying settings..." -ForegroundColor Yellow
    Set-LocalLockoutPolicy -Parameters $params
  }
  "3" {
    Get-CurrentLockoutPolicy -Domain
  }
  "4" {
    Get-CurrentLockoutPolicy -Local
  }
  "5" {
    Get-LockedAccounts -Domain
  }
  "6" {
    Unlock-UserAccount -Domain
  }
  "7" {
    Unlock-UserAccount -Local
  }
  "8" {
    Write-Host "Exiting..." -ForegroundColor Yellow
    exit
  }
  default {
    Write-Host "Invalid selection" -ForegroundColor Red
  }
}

Write-Host "`nScript completed." -ForegroundColor Green