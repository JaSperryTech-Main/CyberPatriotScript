<#
.SYNOPSIS
    Windows Server 2019/2022 Password Policy Management Script

.DESCRIPTION
    This script configures domain or local password policies including:
    - Password complexity requirements
    - Password age limits
    - Password history
    - Account lockout settings

.NOTES
    Requires Administrator privileges
    For Domain policies: Run on Domain Controller
    For Local policies: Run on local server
#>

# Requires -RunAsAdministrator

# Function to prompt for password policy parameters
function Get-PolicyParameters {
  Write-Host "`n=== Password Policy Parameters ===" -ForegroundColor Cyan
  Write-Host "Press Enter to accept default values shown in [brackets]`n" -ForegroundColor Yellow
    
  $minLength = Read-Host "Minimum password length [14]"
  $minLength = if ($minLength) { [int]$minLength } else { 14 }
    
  $minAge = Read-Host "Minimum password age in days [1]"
  $minAge = if ($minAge) { [int]$minAge } else { 1 }
    
  $maxAge = Read-Host "Maximum password age in days [90]"
  $maxAge = if ($maxAge) { [int]$maxAge } else { 90 }
    
  $historyCount = Read-Host "Password history count [24]"
  $historyCount = if ($historyCount) { [int]$historyCount } else { 24 }
    
  $complexity = Read-Host "Enable password complexity? (Y/N) [Y]"
  $complexity = if ($complexity -eq 'N' -or $complexity -eq 'n') { $false } else { $true }
    
  $lockoutThreshold = Read-Host "Account lockout threshold (invalid attempts) [5]"
  $lockoutThreshold = if ($lockoutThreshold) { [int]$lockoutThreshold } else { 5 }
    
  $lockoutDuration = Read-Host "Account lockout duration in minutes [30]"
  $lockoutDuration = if ($lockoutDuration) { [int]$lockoutDuration } else { 30 }
    
  $lockoutWindow = Read-Host "Lockout observation window in minutes [30]"
  $lockoutWindow = if ($lockoutWindow) { [int]$lockoutWindow } else { 30 }
    
  return @{
    MinPasswordLength        = $minLength
    MinPasswordAge           = $minAge
    MaxPasswordAge           = $maxAge
    PasswordHistoryCount     = $historyCount
    ComplexityEnabled        = $complexity
    LockoutThreshold         = $lockoutThreshold
    LockoutDuration          = $lockoutDuration
    LockoutObservationWindow = $lockoutWindow
  }
}

# Function to set Domain Password Policy (requires Domain Controller)
function Set-DomainPasswordPolicy {
  param(
    [hashtable]$Parameters
  )

  Write-Host "`n=== Configuring Domain Password Policy ===" -ForegroundColor Cyan
    
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
        
    $policy = @{
      MinPasswordLength           = $Parameters.MinPasswordLength
      MinPasswordAge              = (New-TimeSpan -Days $Parameters.MinPasswordAge)
      MaxPasswordAge              = (New-TimeSpan -Days $Parameters.MaxPasswordAge)
      PasswordHistoryCount        = $Parameters.PasswordHistoryCount
      ComplexityEnabled           = $Parameters.ComplexityEnabled
      ReversibleEncryptionEnabled = $false
      LockoutThreshold            = $Parameters.LockoutThreshold
      LockoutDuration             = (New-TimeSpan -Minutes $Parameters.LockoutDuration)
      LockoutObservationWindow    = (New-TimeSpan -Minutes $Parameters.LockoutObservationWindow)
    }

    Set-ADDefaultDomainPasswordPolicy @policy -Identity (Get-ADDomain).DistinguishedName
        
    Write-Host "Domain password policy updated successfully!" -ForegroundColor Green
    Get-ADDefaultDomainPasswordPolicy | Format-List
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Note: This requires Active Directory module and Domain Controller access" -ForegroundColor Yellow
  }
}

# Function to set Local Password Policy
function Set-LocalPasswordPolicy {
  param(
    [hashtable]$Parameters
  )

  Write-Host "`n=== Configuring Local Password Policy ===" -ForegroundColor Cyan
    
  $complexityValue = if ($Parameters.ComplexityEnabled) { 1 } else { 0 }
    
  $secEditConfig = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = $($Parameters.MinPasswordLength)
MinimumPasswordAge = $($Parameters.MinPasswordAge)
MaximumPasswordAge = $($Parameters.MaxPasswordAge)
PasswordHistorySize = $($Parameters.PasswordHistoryCount)
PasswordComplexity = $complexityValue
ClearTextPassword = 0
LockoutBadCount = $($Parameters.LockoutThreshold)
LockoutDuration = $($Parameters.LockoutDuration)
ResetLockoutCount = $($Parameters.LockoutObservationWindow)
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

  try {
    $tempFile = "$env:TEMP\secpol.cfg"
    $secEditConfig | Out-File $tempFile -Encoding ASCII
        
    secedit /configure /db secedit.sdb /cfg $tempFile /areas SECURITYPOLICY | Out-Null
        
    Remove-Item $tempFile -Force
        
    Write-Host "Local password policy updated successfully!" -ForegroundColor Green
    Write-Host "`nVerifying with: net accounts" -ForegroundColor Yellow
    net accounts
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to view current password policy
function Get-CurrentPasswordPolicy {
  param(
    [switch]$Domain,
    [switch]$Local
  )

  if ($Domain) {
    Write-Host "`n=== Current Domain Password Policy ===" -ForegroundColor Cyan
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      Get-ADDefaultDomainPasswordPolicy | Format-List
    }
    catch {
      Write-Host "Error: Cannot retrieve domain policy. Ensure AD module is installed and you're on a DC." -ForegroundColor Red
    }
  }
    
  if ($Local) {
    Write-Host "`n=== Current Local Password Policy ===" -ForegroundColor Cyan
    net accounts
  }
}

# Main Menu
Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║   Windows Server 2019/2022 Password Policy Manager       ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green

Write-Host "1. Set Domain Password Policy (Requires DC)"
Write-Host "2. Set Local Password Policy"
Write-Host "3. View Current Domain Policy"
Write-Host "4. View Current Local Policy"
Write-Host "5. Exit"
Write-Host ""

$choice = Read-Host "Select an option (1-5)"

switch ($choice) {
  "1" {
    $params = Get-PolicyParameters
    Write-Host "`nApplying settings..." -ForegroundColor Yellow
    Set-DomainPasswordPolicy -Parameters $params
  }
  "2" {
    $params = Get-PolicyParameters
    Write-Host "`nApplying settings..." -ForegroundColor Yellow
    Set-LocalPasswordPolicy -Parameters $params
  }
  "3" {
    Get-CurrentPasswordPolicy -Domain
  }
  "4" {
    Get-CurrentPasswordPolicy -Local
  }
  "5" {
    Write-Host "Exiting..." -ForegroundColor Yellow
    exit
  }
  default {
    Write-Host "Invalid selection" -ForegroundColor Red
  }
}

Write-Host "`nScript completed." -ForegroundColor Green