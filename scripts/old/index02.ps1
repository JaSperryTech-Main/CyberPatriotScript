# This is the first in the set of scripts for Windows 10
# Ensure you read the README and complete forensic questions before running this script.
# YOU NEED TO RUN THIS AS ADMINISTRATOR.

# Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "This script must be run as administrator." -ForegroundColor Red
  exit
}

Write-Host "Starting Windows 10 configuration script."


# Enable NetTCPIP Module if Available
if (Get-Module -ListAvailable -Name NetTCPIP) {
  Import-Module NetTCPIP -ErrorAction SilentlyContinue
  Write-Host "NetTCPIP module loaded."
}
else {
  Write-Host "NetTCPIP module not found. Please ensure it’s available."
}

# Check Defender Service
try {
  $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
  if ($defenderService -and $defenderService.Status -eq 'Running') {
    Write-Host "Microsoft Defender service is running."
  }
  else {
    Write-Host "Microsoft Defender service not running; ensure it's enabled."
  }
}
catch {
  Write-Host "Error checking Defender service: $_"
}

# Firewall Profiles
$profiles = @("Private", "Public")
foreach ($profile in $profiles) {
  $firewall = Get-NetFirewallProfile -Profile $profile
  if ($firewall.Enabled -eq $true) {
    Write-Host "$profile firewall profile is enabled."
  }
  else {
    Write-Host "$profile firewall profile is disabled. Enabling."
    Set-NetFirewallProfile -Profile $profile -Enabled True
  }
}

# Enable Defender Preferences
Write-Host "Configuring Defender preferences"
Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableBlockAtFirstSeen $false -DisableIOAVProtection $false -DisableIntrusionPreventionSystem $false -DisableScriptScanning $false

# Disable OneDrive Startup Task 
Write-Host "Disabling OneDrive on Startup"
$onedriveTask = Get-ScheduledTask -TaskName "*OneDrive Standalone Update Task*" -ErrorAction SilentlyContinue
if ($onedriveTask) {
  $onedriveTask | Disable-ScheduledTask
  Write-Host "OneDrive disabled on startup."
}
else {
  Write-Host "OneDrive task not found."
}

# Password Complexity Requirements & Lockout Threshold
Write-Host "Configuring password complexity requirements and lockout settings"

# Set Password Complexity to True (Password must meet complexity requirements)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# Set Account Lockout Threshold
# 5 failed attempts
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg) -replace "LockoutBadCount = \d+", "LockoutBadCount = 5" | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg
Remove-Item C:\Windows\Temp\secpol.cfg

# Set Lockout Duration to 30 minutes
# Account lockout duration (in minutes)
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg) -replace "LockoutDuration = \d+", "LockoutDuration = 30" | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg
Remove-Item C:\Windows\Temp\secpol.cfg

# Reset Lockout Counter after 30 minutes
# Lockout counter reset duration (in minutes)
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg) -replace "ResetCount = \d+", "ResetCount = 30" | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg
Remove-Item C:\Windows\Temp\secpol.cfg

# Password Policies
Write-Host "Configuring password policies"
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg) -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 7" | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg
Remove-Item C:\Windows\Temp\secpol.cfg

net accounts /maxpwage:90 /minpwage:15 /minpwlen:12
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "PasswordComplexity" -Value 1

# Screen Saver Settings
Write-Host "Configuring screen saver settings"
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value 600 -PropertyType String -Force
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value 1 -PropertyType String -Force

# Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense features"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowed" -Value 0 -PropertyType DWord -Force

# Set UAC to Maximum
Write-Host "Setting UAC to maximum"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

# Path to the registry key that controls password complexity
$regKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Check if the registry key exists, if not create it
if (-not (Test-Path $regKeyPath)) {
  Write-Host "Creating registry key: $regKeyPath" -ForegroundColor Cyan
  New-Item -Path $regKeyPath -Force | Out-Null
}

# Set the "EnablePasswordComplexity" registry value to 1 to enable complexity requirements
$regValueName = "PasswordComplexity"
$regValue = 1

# Check if the value exists, then set it
if (Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue) {
  Write-Host "Setting $regValueName to $regValue" -ForegroundColor Green
  Set-ItemProperty -Path $regKeyPath -Name $regValueName -Value $regValue
}
else {
  Write-Host "Setting registry value $regValueName to $regValue" -ForegroundColor Green
  New-ItemProperty -Path $regKeyPath -Name $regValueName -Value $regValue -PropertyType DWord -Force
}

# Confirm that password complexity is enabled
$enabled = (Get-ItemProperty -Path $regKeyPath -Name $regValueName).PasswordComplexity
if ($enabled -eq 1) {
  Write-Host "Password complexity has been successfully enabled." -ForegroundColor Green
}
else {
  Write-Host "Failed to enable password complexity." -ForegroundColor Red
}

# Network Adapter Settings
Write-Host "Configuring network adapter settings"
$adapters = Get-NetAdapter -Physical
foreach ($adapter in $adapters) {
  Write-Host "Configuring adapter: $($adapter.Name)"
  Set-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -Enabled $false
  foreach ($component in @("ms_msclient", "ms_server", "ms_pacer", "ms_implat", "ms_lltdio", "ms_rspndr", "ms_lldp")) {
    Set-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Enabled $false
  }
}

# Disable Remote Desktop
Write-Host "Disabling Remote Desktop"
try {
  $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
  $regKey = "fDenyTSConnections"
  if (-not (Test-Path $regPath)) {
    Write-Host "Registry path not found: $regPath" -ForegroundColor Red
    exit
  }
  Set-ItemProperty -Path $regPath -Name $regKey -Value 1
  Write-Host "Remote Desktop has been disabled."
}
catch {
  Write-Host "An error occurred while disabling Remote Desktop: $_" -ForegroundColor Red
}

# Disable Autoplay for all drives
Write-Host "Disabling Autoplay for all drives"
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$registryName = "NoDriveTypeAutoRun"
$NoDriveTypeAutoRunValue = 255
if (!(Test-Path -Path $registryPath)) {
  New-Item -Path $registryPath -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name $registryName -Value $NoDriveTypeAutoRunValue
Write-Output "Autoplay disabled for all drives."

Write-Host "
 _____          _          __                 _       _                      
|  ___|        | |        / _|               (_)     | |                     
| |__ _ __   __| |   ___ | |_   ___  ___ _ __ _ _ __ | |_    ___  _ __   ___ 
|  __| '_ \ / _` |  / _ \|  _| / __|/ __| '__| | '_ \| __|  / _ \| '_ \ / _ \
| |__| | | | (_| | | (_) | |   \__ \ (__| |  | | |_) | |_  | (_) | | | |  __/
\____/_| |_|\__,_|  \___/|_|   |___/\___|_|  |_| .__/ \__|  \___/|_| |_|\___|
                                               | |                           
                                               |_|                           "

