<#
.SYNOPSIS
    Windows Server 2019/2022 Account Management Script

.DESCRIPTION
    This script manages domain or local user accounts including:
    - Create new user accounts
    - Delete user accounts
    - Reset passwords
    - Enable/Disable accounts
    - Modify account properties
    - View account information

.NOTES
    Requires Administrator privileges
    For Domain accounts: Run on Domain Controller or with AD module
    For Local accounts: Run on local server
#>

# Requires -RunAsAdministrator

# Function to create a new domain user
function New-DomainUserAccount {
  Write-Host "`n=== Create New Domain User Account ===" -ForegroundColor Cyan
    
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
        
    $firstName = Read-Host "First Name"
    $lastName = Read-Host "Last Name"
    $username = Read-Host "Username (SamAccountName)"
    $password = Read-Host "Password" -AsSecureString
    $ou = Read-Host "Organizational Unit (OU) Distinguished Name [Press Enter for default Users container]"
        
    $displayName = "$firstName $lastName"
    $upn = "$username@$((Get-ADDomain).DNSRoot)"
        
    $userParams = @{
      GivenName             = $firstName
      Surname               = $lastName
      Name                  = $displayName
      DisplayName           = $displayName
      SamAccountName        = $username
      UserPrincipalName     = $upn
      AccountPassword       = $password
      Enabled               = $true
      ChangePasswordAtLogon = $true
    }
        
    if ($ou) {
      $userParams.Path = $ou
    }
        
    New-ADUser @userParams
        
    Write-Host "`nUser account '$username' created successfully!" -ForegroundColor Green
    Write-Host "Display Name: $displayName" -ForegroundColor Yellow
    Write-Host "UPN: $upn" -ForegroundColor Yellow
    Write-Host "User must change password at next logon: Yes" -ForegroundColor Yellow
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to create a new local user
function New-LocalUserAccount {
  Write-Host "`n=== Create New Local User Account ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username"
  $fullName = Read-Host "Full Name"
  $description = Read-Host "Description [Optional]"
  $password = Read-Host "Password" -AsSecureString
    
  try {
    $userParams = @{
      Name                     = $username
      Password                 = $password
      FullName                 = $fullName
      Description              = $description
      UserMayNotChangePassword = $false
      PasswordNeverExpires     = $false
    }
        
    New-LocalUser @userParams
        
    Write-Host "`nLocal user account '$username' created successfully!" -ForegroundColor Green
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to delete a domain user
function Remove-DomainUserAccount {
  Write-Host "`n=== Delete Domain User Account ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username to delete"
  $confirm = Read-Host "Are you sure you want to delete '$username'? (Y/N)"
    
  if ($confirm -eq 'Y' -or $confirm -eq 'y') {
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      Remove-ADUser -Identity $username -Confirm:$false
      Write-Host "User account '$username' deleted successfully!" -ForegroundColor Green
    }
    catch {
      Write-Host "Error: $_" -ForegroundColor Red
    }
  }
  else {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
  }
}

# Function to delete a local user
function Remove-LocalUserAccount {
  Write-Host "`n=== Delete Local User Account ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username to delete"
  $confirm = Read-Host "Are you sure you want to delete '$username'? (Y/N)"
    
  if ($confirm -eq 'Y' -or $confirm -eq 'y') {
    try {
      Remove-LocalUser -Name $username
      Write-Host "Local user account '$username' deleted successfully!" -ForegroundColor Green
    }
    catch {
      Write-Host "Error: $_" -ForegroundColor Red
    }
  }
  else {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
  }
}

# Function to reset domain user password
function Reset-DomainUserPassword {
  Write-Host "`n=== Reset Domain User Password ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username"
  $newPassword = Read-Host "New Password" -AsSecureString
  $changeAtLogon = Read-Host "User must change password at next logon? (Y/N) [Y]"
  $changeAtLogon = if ($changeAtLogon -eq 'N' -or $changeAtLogon -eq 'n') { $false } else { $true }
    
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Set-ADAccountPassword -Identity $username -NewPassword $newPassword -Reset
    Set-ADUser -Identity $username -ChangePasswordAtLogon $changeAtLogon
    Write-Host "Password reset successfully for '$username'!" -ForegroundColor Green
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to reset local user password
function Reset-LocalUserPassword {
  Write-Host "`n=== Reset Local User Password ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username"
  $newPassword = Read-Host "New Password" -AsSecureString
    
  try {
    Set-LocalUser -Name $username -Password $newPassword
    Write-Host "Password reset successfully for '$username'!" -ForegroundColor Green
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to enable/disable domain user
function Set-DomainUserStatus {
  Write-Host "`n=== Enable/Disable Domain User Account ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username"
  $action = Read-Host "Action: (E)nable or (D)isable? [E/D]"
    
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
        
    if ($action -eq 'E' -or $action -eq 'e') {
      Enable-ADAccount -Identity $username
      Write-Host "Account '$username' enabled successfully!" -ForegroundColor Green
    }
    elseif ($action -eq 'D' -or $action -eq 'd') {
      Disable-ADAccount -Identity $username
      Write-Host "Account '$username' disabled successfully!" -ForegroundColor Green
    }
    else {
      Write-Host "Invalid action." -ForegroundColor Red
    }
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to enable/disable local user
function Set-LocalUserStatus {
  Write-Host "`n=== Enable/Disable Local User Account ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username"
  $action = Read-Host "Action: (E)nable or (D)isable? [E/D]"
    
  try {
    if ($action -eq 'E' -or $action -eq 'e') {
      Enable-LocalUser -Name $username
      Write-Host "Account '$username' enabled successfully!" -ForegroundColor Green
    }
    elseif ($action -eq 'D' -or $action -eq 'd') {
      Disable-LocalUser -Name $username
      Write-Host "Account '$username' disabled successfully!" -ForegroundColor Green
    }
    else {
      Write-Host "Invalid action." -ForegroundColor Red
    }
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to view domain user information
function Get-DomainUserInfo {
  Write-Host "`n=== View Domain User Information ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username (or press Enter to list all users)"
    
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
        
    if ($username) {
      $user = Get-ADUser -Identity $username -Properties *
            
      Write-Host "`n=== User Details for '$username' ===" -ForegroundColor Yellow
      Write-Host "Display Name: $($user.DisplayName)"
      Write-Host "Email: $($user.EmailAddress)"
      Write-Host "Enabled: $($user.Enabled)"
      Write-Host "Locked Out: $($user.LockedOut)"
      Write-Host "Password Never Expires: $($user.PasswordNeverExpires)"
      Write-Host "Last Logon: $($user.LastLogonDate)"
      Write-Host "Account Created: $($user.Created)"
      Write-Host "Description: $($user.Description)"
    }
    else {
      Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled | Format-Table -AutoSize
    }
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to view local user information
function Get-LocalUserInfo {
  Write-Host "`n=== View Local User Information ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username (or press Enter to list all users)"
    
  try {
    if ($username) {
      $user = Get-LocalUser -Name $username
            
      Write-Host "`n=== User Details for '$username' ===" -ForegroundColor Yellow
      Write-Host "Full Name: $($user.FullName)"
      Write-Host "Description: $($user.Description)"
      Write-Host "Enabled: $($user.Enabled)"
      Write-Host "Last Logon: $($user.LastLogon)"
      Write-Host "Password Changeable Date: $($user.PasswordChangeableDate)"
      Write-Host "Password Expires: $($user.PasswordExpires)"
      Write-Host "Account Expires: $($user.AccountExpires)"
    }
    else {
      Get-LocalUser | Select-Object Name, Enabled, Description | Format-Table -AutoSize
    }
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Function to modify domain user properties
function Set-DomainUserProperties {
  Write-Host "`n=== Modify Domain User Properties ===" -ForegroundColor Cyan
    
  $username = Read-Host "Username"
    
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
        
    Write-Host "`nLeave blank to skip any property" -ForegroundColor Yellow
        
    $email = Read-Host "Email Address"
    $phone = Read-Host "Phone Number"
    $title = Read-Host "Job Title"
    $department = Read-Host "Department"
    $description = Read-Host "Description"
        
    $properties = @{}
    if ($email) { $properties.EmailAddress = $email }
    if ($phone) { $properties.OfficePhone = $phone }
    if ($title) { $properties.Title = $title }
    if ($department) { $properties.Department = $department }
    if ($description) { $properties.Description = $description }
        
    if ($properties.Count -gt 0) {
      Set-ADUser -Identity $username @properties
      Write-Host "`nUser properties updated successfully for '$username'!" -ForegroundColor Green
    }
    else {
      Write-Host "No properties were modified." -ForegroundColor Yellow
    }
  }
  catch {
    Write-Host "Error: $_" -ForegroundColor Red
  }
}

# Main Menu
Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║   Windows Server 2019/2022 Account Manager              ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green

Write-Host "DOMAIN ACCOUNT MANAGEMENT (Requires DC/AD Module):"
Write-Host "  1. Create New Domain User"
Write-Host "  2. Delete Domain User"
Write-Host "  3. Reset Domain User Password"
Write-Host "  4. Enable/Disable Domain User"
Write-Host "  5. View Domain User Information"
Write-Host "  6. Modify Domain User Properties"
Write-Host ""
Write-Host "LOCAL ACCOUNT MANAGEMENT:"
Write-Host "  7. Create New Local User"
Write-Host "  8. Delete Local User"
Write-Host "  9. Reset Local User Password"
Write-Host " 10. Enable/Disable Local User"
Write-Host " 11. View Local User Information"
Write-Host ""
Write-Host " 12. Exit"
Write-Host ""

$choice = Read-Host "Select an option (1-12)"

switch ($choice) {
  "1" { New-DomainUserAccount }
  "2" { Remove-DomainUserAccount }
  "3" { Reset-DomainUserPassword }
  "4" { Set-DomainUserStatus }
  "5" { Get-DomainUserInfo }
  "6" { Set-DomainUserProperties }
  "7" { New-LocalUserAccount }
  "8" { Remove-LocalUserAccount }
  "9" { Reset-LocalUserPassword }
  "10" { Set-LocalUserStatus }
  "11" { Get-LocalUserInfo }
  "12" {
    Write-Host "Exiting..." -ForegroundColor Yellow
    exit
  }
  default {
    Write-Host "Invalid selection" -ForegroundColor Red
  }
}

Write-Host "`nScript completed." -ForegroundColor Green