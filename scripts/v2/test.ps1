# Windows Server 2019/2022 Security Hardening Script
# Run as Administrator

# Function to Write Log
function Write-Log {
  param([string]$message, [string]$type = "INFO")
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $logEntry = "[$timestamp] [$type] $message"
  Write-Host $logEntry
  Add-Content -Path "C:\Security_Hardening_Log.txt" -Value $logEntry
}

# Function to Test Registry Path
function Test-RegistryPath {
  param([string]$path)
  return Test-Path $path
}

# Function to Set Registry Value
function Set-RegistryValue {
  param([string]$path, [string]$name, [string]$type, [string]$value, [string]$description)
    
  if (-not (Test-RegistryPath $path)) {
    New-Item -Path $path -Force | Out-Null
    Write-Log "Created registry path: $path"
  }
    
  try {
    if (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue) {
      Set-ItemProperty -Path $path -Name $name -Value $value -Type $type
    }
    else {
      New-ItemProperty -Path $path -Name $name -PropertyType $type -Value $value | Out-Null
    }
    Write-Log "Set registry: $path\$name = $value - $description"
  }
  catch {
    Write-Log "Failed to set registry: $path\$name" -type "ERROR"
  }
}

Write-Log "Starting Windows Server Security Hardening..."

# 1. Password Policy
Write-Log "Configuring Password Policy..."
net accounts /maxpwage:60
net accounts /minpwage:1
net accounts /minpwlen:10
net accounts /uniquepw:24

Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "PasswordComplexity" "DWord" "1" "Password complexity enabled"
Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" "DWord" "1" "Do not store LAN Manager hash"

# 2. Account Lockout Policy
Write-Log "Configuring Account Lockout Policy..."
net accounts /lockoutthreshold:10
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

# 3. User Account Settings
Write-Log "Configuring User Account Settings..."
try {
  # Set all users to change password at next logon (except built-in accounts)
  Get-LocalUser | Where-Object {
    $_.Name -notin @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")
  } | ForEach-Object {
    Set-LocalUser -Name $_.Name -PasswordNeverExpires $false
    # Note: 'UserMustChangePasswordAtNextLogon' requires specific conditions
  }
  Write-Log "Configured local user password settings"
}
catch {
  Write-Log "Error configuring user accounts: $($_.Exception.Message)" -type "ERROR"
}

# 4. Group Membership Checks
Write-Log "Checking Group Memberships..."
try {
  # Ensure Guests group only contains Guest account
  $guestsGroup = Get-LocalGroupMember -Group "Guests" | Where-Object { $_.Name -notlike "*\Guest" }
  if ($guestsGroup) {
    $guestsGroup | ForEach-Object {
      Remove-LocalGroupMember -Group "Guests" -Member $_.Name -ErrorAction SilentlyContinue
      Write-Log "Removed $($_.Name) from Guests group"
    }
  }
}
catch {
  Write-Log "Error configuring group memberships" -type "ERROR"
}

# 5. SmartScreen and UAC Settings
Write-Log "Configuring SmartScreen and UAC..."
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "String" "RequireAdmin" "SmartScreen enabled"
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Security Center" "UacDisableNotify" "DWord" "0" "UAC notifications enabled"

# Set UAC to maximum
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "DWord" "2" "UAC Admin Prompt Behavior"
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" "DWord" "0" "UAC User Prompt Behavior"
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" "DWord" "1" "UAC Enabled"
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" "DWord" "1" "UAC Secure Desktop"

# 6. Network Adapter Configuration
Write-Log "Configuring Network Adapters..."
try {
  Get-NetAdapter | ForEach-Object {
    $adapter = $_
    # Disable IPv6
    Disable-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_tcpip6" -ErrorAction SilentlyContinue
        
    # Disable unnecessary services
    $servicesToDisable = @(
      "ms_client",
      "ms_server", 
      "ms_lltdio",
      "ms_rspndr",
      "ms_implat",
      "ms_pacer",
      "ms_lldp"
    )
        
    foreach ($service in $servicesToDisable) {
      Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $service -ErrorAction SilentlyContinue
    }
        
    Write-Log "Configured network adapter: $($adapter.Name)"
  }
}
catch {
  Write-Log "Error configuring network adapters" -type "ERROR"
}

# 7. Disable UPnP
Write-Log "Disabling UPnP..."
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\DirectplayNATHelp\DPNHUPnP" "UPnPMode" "DWord" "2" "UPnP disabled"

# 8. Windows Services Configuration
Write-Log "Configuring Windows Services..."
$servicesToDisable = @(
  @{Name = "upnphost"; Description = "UPnP Device Host" },
  @{Name = "Telnet"; Description = "Telnet" },
  @{Name = "SNMPTRAP"; Description = "SNMP Trap" },
  @{Name = "RemoteRegistry"; Description = "Remote Registry" }
)

foreach ($service in $servicesToDisable) {
  try {
    Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
    Write-Log "Disabled service: $($service.Description)"
  }
  catch {
    Write-Log "Could not configure service: $($service.Name)" -type "WARNING"
  }
}

# Enable required services
try {
  Set-Service -Name "Wecsvc" -StartupType Automatic -ErrorAction SilentlyContinue
  Start-Service -Name "Wecsvc" -ErrorAction SilentlyContinue
  Write-Log "Enabled Windows Event Collector service"
}
catch {
  Write-Log "Could not configure Windows Event Collector service" -type "WARNING"
}

# 9. Windows Features
Write-Log "Configuring Windows Features..."
$featuresToDisable = @(
  "TelnetClient",
  "TelnetServer",
  "SNMP",
  "RIP",
  "NFS",
  "Web-Server",
  "TFTP"
)

foreach ($feature in $featuresToDisable) {
  try {
    if (Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue | Where-Object InstallState -eq "Installed") {
      Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
      Write-Log "Disabled Windows feature: $feature"
    }
  }
  catch {
    Write-Log "Could not disable feature: $feature" -type "WARNING"
  }
}

# 10. Disable SMB v1
Write-Log "Disabling SMB v1..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# 11. Configure Shares (Only keep default shares)
Write-Log "Checking shares..."
try {
  Get-SmbShare | Where-Object {
    $_.Name -notin @("ADMIN$", "C$", "IPC$") -and $_.ScopeName -eq "*"
  } | ForEach-Object {
    Remove-SmbShare -Name $_.Name -Force -ErrorAction SilentlyContinue
    Write-Log "Removed share: $($_.Name)"
  }
}
catch {
  Write-Log "Error configuring shares" -type "ERROR"
}

# 12. Firewall Rules - Disable unnecessary inbound rules
Write-Log "Configuring Firewall Rules..."
$rulesToDisable = @(
  "MS Edge",
  "Search", 
  "MSN Money",
  "MSN Sports",
  "MSN News",
  "MSN Weather",
  "Microsoft Photos",
  "Xbox"
)

foreach ($ruleName in $rulesToDisable) {
  try {
    Get-NetFirewallRule | Where-Object {
      $_.DisplayName -like "*$ruleName*" -and $_.Direction -eq "Inbound"
    } | Disable-NetFirewallRule -ErrorAction SilentlyContinue
  }
  catch {
    # Continue if rule doesn't exist
  }
}

# 13. Screen Saver and AutoPlay
Write-Log "Configuring Screen Saver and AutoPlay..."
Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoChangingStartScreen" "DWord" "1" "Prevent tile changes"
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" "DisableAutoplay" "DWord" "1" "AutoPlay disabled"

# Screen saver settings
Set-RegistryValue "HKCU:\Control Panel\Desktop" "ScreenSaveActive" "String" "1" "Screen saver enabled"
Set-RegistryValue "HKCU:\Control Panel\Desktop" "ScreenSaveTimeOut" "String" "600" "Screen saver timeout 10 minutes"
Set-RegistryValue "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure" "String" "1" "Require password on resume"

# 14. Disable OneDrive on Startup
Write-Log "Disabling OneDrive..."
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "DWord" "1" "OneDrive disabled"

# 15. Windows Defender
Write-Log "Configuring Windows Defender..."
try {
  # Enable real-time protection
  Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
  Write-Log "Windows Defender real-time protection enabled"
}
catch {
  Write-Log "Could not configure Windows Defender" -type "WARNING"
}

# 16. User Rights Assignment (Key settings only)
Write-Log "Configuring User Rights Assignment..."
# Note: Full User Rights Assignment requires secedit or Group Policy

# 17. Local Security Policies (Key settings via registry)
Write-Log "Configuring Local Security Policies..."

# Disable Administrator and Guest accounts
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableAdminAccount" "DWord" "0" "Administrator account disabled"
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableGuestAccount" "DWord" "0" "Guest account disabled"

# Interactive logon settings
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName" "DWord" "1" "Do not display last user name"
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" "DWord" "0" "Require CTRL+ALT+DEL"

# Network security settings
Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" "DWord" "5" "Send NTLMv2 response only"
Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" "DWord" "1" "Restrict anonymous access"
Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal" "DWord" "1" "Require secure channel"

# 18. Enable Auditing
Write-Log "Configuring Auditing..."
# Enable success/failure auditing for key events
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

Write-Log "Auditing policies configured"

# 19. Additional Security Hardening
Write-Log "Applying Additional Security Hardening..."

# Disable LLMNR
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "DWord" "0" "LLMNR disabled"

# Disable NetBIOS
Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" "NetbiosOptions" "DWord" "2" "NetBIOS disabled"

# Disable WPAD
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" "WpadOverride" "DWord" "1" "WPAD disabled"

Write-Log "Windows Server Security Hardening completed!"
Write-Log "Some settings may require reboot to take effect."
Write-Log "Check C:\Security_Hardening_Log.txt for detailed log."

# Display completion message
Write-Host "`nSecurity hardening script completed!" -ForegroundColor Green
Write-Host "Please review the log file at C:\Security_Hardening_Log.txt" -ForegroundColor Yellow
Write-Host "Some settings may require a system reboot to take full effect." -ForegroundColor Yellow