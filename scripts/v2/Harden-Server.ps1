<#
Harden-Server.ps1
Run elevated. Tested conceptually for Windows Server 2019/2022.
This script:
 - for domain members: sets domain-wide password policy (calls AD cmdlets)
 - for all machines: applies local password/lockout via net accounts (if local), adjusts services, disables SMB1, sets firewall app-block rules, disables UPnP regkey, disables IPv6 binding on adapters, enforces local group membership, and forces local users to change password at next logon.

IMPORTANT: test on a lab server before mass deployment.
#>

# --- Helper / prerequisites ---
Function Test-Admin { 
  if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "Script must be run as Administrator."
    exit 1
  }
}
Test-Admin

# variables you should change
$AuthorizedAdmins = @("DOMAIN\Alice", "DOMAIN\Bob", ".\LocalAdmin")   # allowed admins (update)
$AuthorizedRemoteDesktopUsers = @("DOMAIN\rduser1", "DOMAIN\rduser2") # allowed RDP users (update)
$BlockAppList = @{
  "Block_MSEdge"  = "C:\Program Files\Microsoft\Edge\Application\msedge.exe";
  "Block_MSNNews" = "C:\Program Files\WindowsApps\*MSNNews*\*"; # example - wildcard supported in some rules
}

# detect domain
$inDomain = ($null -ne $env:USERDNSDOMAIN) -and ($null -ne [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()) 2>$null

# --- 1) Password & lockout policies ---
if ($inDomain) {
  Write-Host "Domain-joined: updating domain default password policy (requires RSAT / ActiveDirectory module)."
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    # convert days to Timespan strings where needed
    $maxAge = (New-TimeSpan -Days 60)
    $minAge = (New-TimeSpan -Days 1)
    Get-ADDefaultDomainPasswordPolicy -Current LoggedOnUser | 
    Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true -ReversibleEncryptionEnabled $false `
      -MinPasswordLength 10 -HistorySize 24 -MaxPasswordAge $maxAge -MinPasswordAge $minAge `
      -LockoutThreshold 10 -LockoutDuration (New-TimeSpan -Minutes 30) -LockoutObservationWindow (New-TimeSpan -Minutes 30)
    Write-Host "Domain password policy updated."
  }
  catch {
    Write-Warning "Could not set domain password policy: $_"
  }
}
else {
  Write-Host "Standalone: applying local account policy via net accounts."
  # Enforce password history = unique pw 24, max age 60, min age 1, min length 10, lockout threshold/duration
  net accounts /uniquepw:24 /maxpwage:60 /minpwage:1 /minpwlen:10 | Out-Null
  net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30 | Out-Null
  Write-Host "Local net accounts policy applied."
}

# Password complexity and reversible encryption are Local Security Policy items -> use secedit/LGPO on standalone.
# Create a small INF for secedit and apply it (example for Password must meet complexity and reversible encryption)
$infPath = "$env:TEMP\pwpolicy.inf"
@"
[Unicode]
Unicode=yes
[Version]
signature="\$CHICAGO\$"
Revision=1
[System Access]
PasswordComplexity = 1
ClearTextPassword = 0
"@ | Out-File -FilePath $infPath -Encoding Unicode

try {
  secedit /configure /db "$env:windir\security\local.sdb" /cfg $infPath /areas SECURITYPOLICY | Out-Null
  Write-Host "Applied local security INF (complexity/reversible encryption)."
}
catch {
  Write-Warning "secedit apply failed: $_"
}

# --- 2) Force 'User must change password at next logon' for all local users ---
Write-Host "Setting 'User must change password at next logon' for local users..."
Get-LocalUser | Where-Object { $_.SID -notlike "S-1-5-32-544" -and $_.Name -notlike "Guest" } | ForEach-Object {
  $uName = $_.Name
  try {
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$uName,user"
    $adsi.PasswordExpired = 1
    $adsi.SetInfo()
    Write-Host "Set PasswordExpired=1 for $uName"
  }
  catch {
    Write-Warning "Could not set PasswordExpired for ${uName}: $_"
  }
}

# For domain users you'd use Set-ADUser -ChangePasswordAtLogon $true (example below - DO NOT run domain-wide here)
# Set-ADUser -Identity 'someuser' -ChangePasswordAtLogon $true

# --- 3) Group membership: ensure only allowed admins ---
Write-Host "Checking Administrators group membership..."
Try {
  $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
  $admins | ForEach-Object {
    $member = $_.Name
    if ($AuthorizedAdmins -notcontains $member) {
      Write-Warning "Unauthorized admin found: $member — removing..."
      try { Remove-LocalGroupMember -Group "Administrators" -Member $member -Confirm:$false -ErrorAction Stop; Write-Host "Removed $member" } catch { Write-Warning "Failed to remove ${member}: $_" }
    }
    else {
      Write-Host "Allowed admin present: $member"
    }
  }
}
catch {
  Write-Warning "Could not enumerate Administrators group: $_"
}

# Ensure Guests group contains only Guest
Write-Host "Checking Guests group..."
try {
  $guests = Get-LocalGroupMember -Group "Guests"
  $guests | ForEach-Object {
    if ($_.Name -ne "Guest") {
      Write-Warning "Removing $_.Name from Guests..."
      Remove-LocalGroupMember -Group "Guests" -Member $_.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
  }
}
catch { Write-Warning "Guests group check failed: $_" }

# Remote Desktop Users: keep only approved users (if group exists)
if (Get-LocalGroup -Name "Remote Desktop Users" -ErrorAction SilentlyContinue) {
  Write-Host "Enforcing Remote Desktop Users membership..."
  $current = (Get-LocalGroupMember -Group "Remote Desktop Users").Name
  $current | ForEach-Object {
    if ($AuthorizedRemoteDesktopUsers -notcontains $_) {
      Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $_ -Confirm:$false -ErrorAction SilentlyContinue
      Write-Host "Removed $_ from Remote Desktop Users"
    }
  }
  foreach ($a in $AuthorizedRemoteDesktopUsers) {
    if ($null -eq (Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Where-Object Name -eq $a)) {
      Add-LocalGroupMember -Group "Remote Desktop Users" -Member $a -ErrorAction SilentlyContinue
      Write-Host "Added $a to Remote Desktop Users"
    }
  }
}

# --- 4) Services: stop & disable commonly undesired services if present ---
$svcList = @("upnphost", "TlntSvr", "SNMPTRAP", "RemoteRegistry") # check each exists first
foreach ($s in $svcList) {
  $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
  if ($svc) {
    Write-Host "Stopping & disabling service $s..."
    try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue } catch {}
    try { Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
  }
  else {
    Write-Host "Service $s not present on this host."
  }
}

# --- 5) Disable SMBv1 ---
try {
  $smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
  if ($smb -and $smb.State -ne "Disabled") {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
    Write-Host "Requested SMB1 disable (restart required)."
  }
  else { Write-Host "SMB1 already disabled or not present." }
}
catch { Write-Warning "SMB1 disable failed: $_" }

# --- 6) Firewall: block inbound for specified apps (example) ---
foreach ($k in $BlockAppList.Keys) {
  $p = $BlockAppList[$k]
  try {
    New-NetFirewallRule -DisplayName $k -Direction Inbound -Program $p -Action Block -Profile Any -Enabled True -ErrorAction Stop
    Write-Host "Created firewall rule $k to block $p"
  }
  catch {
    Write-Warning "Could not create firewall rule ${k}: $_"
  }
}

# --- 7) Turn off AutoPlay, OneDrive on startup, set screensaver lock (local UI items) ---
# AutoPlay (registry)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
# Prevent OneDrive from starting (per-machine)
if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive") {
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
}
else {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
}

# Screensaver: 10 minutes + require logon on resume
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "1" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "600" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value "1" -Type String -Force

# --- 8) Registry: disable UPnP broadcasts (port 1900) per your checklist ---
$upnppath = "HKLM:\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP"
if (-not (Test-Path $upnppath)) { New-Item -Path $upnppath -Force | Out-Null }
Set-ItemProperty -Path $upnppath -Name "UPnPMode" -Value 2 -Type DWord -Force
Write-Host "Set UPnPMode=2 in $upnppath"

# --- 9) Disable IPv6 bindings on adapters (if you really want to) ---
Write-Host "Disabling IPv6 binding on network adapters (component ms_tcpip6) — caution: some roles require IPv6."
Get-NetAdapter | ForEach-Object {
  $name = $_.Name
  try {
    Disable-NetAdapterBinding -Name $name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    Write-Host "Disabled IPv6 binding on adapter: $name"
  }
  catch { Write-Warning "Could not change adapter ${name}: $_" }
}

# --- 10) Auditing: enable advanced auditing — use auditpol to set categories to success+failure if desired ---
Write-Host "Setting some audit categories to success+failure (example - modify per your audit plan)"
$auditTargets = @("Logon", "Account Logon", "Object Access")
foreach ($t in $auditTargets) {
  try { auditpol /set /category:"$t" /success:enable /failure:enable } catch { Write-Warning "auditpol change failed for ${t}: $_" }
}

Write-Host "HARDENING SCRIPT COMPLETE. Review output and reboot if required (SMB1 disable, etc.)."
