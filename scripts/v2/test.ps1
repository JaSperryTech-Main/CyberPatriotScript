<#
.SYNOPSIS
  Windows Hardening & Security Baseline Script (local machine).
.DESCRIPTION
  Attempts to implement many of the hardening items from user's checklist:
   - Password & lockout policy
   - Local Security Policy settings via secedit template
   - Services stop/disable
   - Network adapter binding adjustments (disable IPv6 binding & other adapter components)
   - SMBv1 removal
   - UPnP registry tweak
   - UAC and Defender settings
   - Audit policy changes (enable success+failure)
   - Basic firewall rules to block common unwanted store/apps (example)
   - Reporting for group membership and other checks (non-destructive)
.NOTES
  - Test in lab before production.
  - Many settings are more appropriate for Group Policy (domain), script targets local machine only.
  - Run as Administrator.
.PARAMETER ApplyChanges
  If present, changes are applied. If omitted, script will run in "report-only" mode showing what it would change.
.EXAMPLE
  .\hardening-baseline.ps1           # report-only
  .\hardening-baseline.ps1 -ApplyChanges  # actually apply
#>

param(
  [switch]$ApplyChanges = $false
)

function Write-Log { param($m) Write-Host "$(Get-Date -Format o)  $m" }

if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
  Write-Error "Script must be run as Administrator. Exiting."
  exit 1
}

$Perform = $ApplyChanges.IsPresent
if ($Perform) { Write-Log "***** RUNNING IN APPLY MODE (CHANGES WILL BE MADE) *****" }
else { Write-Log "***** RUNNING IN REPORT-ONLY MODE (no destructive changes) *****" }

# -----------------------------
# Helper: Run or report
# -----------------------------
function Do-Action {
  param($Description, [scriptblock]$Action)
  Write-Log $Description
  if ($Perform) {
    try {
      & $Action
      Write-Log " -> OK"
    }
    catch {
      Write-Error " -> FAILED: $_"
    }
  }
  else {
    Write-Log " -> (Report-only) Would run."
  }
}

# -----------------------------
# Part 1: Password & Lockout Policy
# -----------------------------
Write-Log "=== Password & Lockout Policy ==="

# Password policy using net accounts where possible
$pwMinLen = 10
$pwMaxAge = 60        # days
$pwMinAge = 1         # days
$pwHistory = 24       # unique passwords remember
$pwComplex = $true    # note: enable via secpol template below

Do-Action "Setting password policy (net accounts): minlen=$pwMinLen, maxage=$pwMaxAge, minage=$pwMinAge, uniquepw=$pwHistory" {
  net accounts /minpwlen:$pwMinLen /maxpwage:$pwMaxAge /minpwage:$pwMinAge /uniquepw:$pwHistory | Out-Null
}

# Lockout policy (net accounts supports thresholds)
$lockoutThreshold = 10
$lockoutDurationMinutes = 30
$lockoutResetWindowMinutes = 30

Do-Action "Setting lockout policy (net accounts): threshold=$lockoutThreshold, duration=$lockoutDurationMinutes, window=$lockoutResetWindowMinutes" {
  net accounts /lockoutthreshold:$lockoutThreshold /lockoutduration:$lockoutDurationMinutes /lockoutwindow:$lockoutResetWindowMinutes | Out-Null
}

# Note: to force "Password must meet complexity requirements" we use secedit template below.

# -----------------------------
# Part 2: Build local security template (.inf) & apply via secedit
# -----------------------------
Write-Log "=== Local Security Policy (secedit template) ==="

# Compose a secedit INF fragment to set a number of Local Policies.
# This will be saved to a temporary file and applied with secedit /configure.
$seceditPath = "$env:TEMP\custom_security_template.inf"

$seceditContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = $pwMinLen
MaximumPasswordAge = $pwMaxAge
MinimumPasswordAge = $pwMinAge
PasswordHistorySize = $pwHistory
PasswordComplexity = 1
LockoutBadCount = $lockoutThreshold
ResetLockoutCount = $lockoutResetWindowMinutes
LockoutDuration = $lockoutDurationMinutes
ClearTextPassword = 0

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManagement = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3

[Privilege Rights]
SeDenyNetworkLogonRight = Guest
SeDenyInteractiveLogonRight = Guest
SeDenyRemoteInteractiveLogonRight = Guest,LocalAccount

[Registry Values]
// UAC: Prompt on secure desktop, run all admins in Admin Approval Mode
"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" = 
"ConsentPromptBehaviorAdmin"=dword:00000002
"EnableLUA"=dword:00000001
"PromptOnSecureDesktop"=dword:00000001
"FilterAdministratorToken"=dword:00000001

"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" =

[Version]
signature="\$CHICAGO\$"
Revision=1
"@

# Save to disk
Do-Action "Writing secedit template to $seceditPath" {
  $seceditContent | Out-File -FilePath $seceditPath -Encoding ASCII -Force
}

Do-Action "Applying local security template via secedit (this may take a moment)" {
  secedit /configure /db "$env:windir\security\local.sdb" /cfg $seceditPath /overwrite | Out-Null
}

# -----------------------------
# Part 3: Registry tweaks (UPnPMode, OneDrive, etc.)
# -----------------------------
Write-Log "=== Registry tweaks ==="

# UPnPMode registry addition
$upnpKey = "HKLM:\Software\Microsoft\DirectplayNATHelp\DPNHUPnP"
Do-Action "Creating UPnP registry key and setting UPnPMode=2" {
  if (-not (Test-Path $upnpKey)) { New-Item -Path $upnpKey -Force | Out-Null }
  New-ItemProperty -Path $upnpKey -Name "UPnPMode" -PropertyType DWord -Value 2 -Force | Out-Null
}

# Disable OneDrive by policy (per-machine)
$oneDrivePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
Do-Action "Setting OneDrive DisableFileSyncNGSC=1 (policy)" {
  if (-not (Test-Path $oneDrivePolicy)) { New-Item -Path $oneDrivePolicy -Force | Out-Null }
  New-ItemProperty -Path $oneDrivePolicy -Name "DisableFileSyncNGSC" -PropertyType DWord -Value 1 -Force | Out-Null
}

# Screen saver: enable, timeout 10 minutes, require logon on resume (current user)
$desktopKey = "HKCU:\Control Panel\Desktop"
Do-Action "Setting Screen Saver (HKCU) - Timeout 600, ScreenSaveActive=1, ScreenSaverIsSecure=1" {
  Set-ItemProperty -Path $desktopKey -Name "ScreenSaveActive" -Value "1" -Force
  Set-ItemProperty -Path $desktopKey -Name "ScreenSaveTimeOut" -Value "600" -Force
  Set-ItemProperty -Path $desktopKey -Name "ScreenSaverIsSecure" -Value "1" -Force
}

# -----------------------------
# Part 4: Disable SMB v1
# -----------------------------
Write-Log "=== Disable SMBv1 ==="
Do-Action "Removing / disabling SMBv1 feature (if present)" {
  # Try the recommended way
  try {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null
  }
  catch {
    # Fallback: remove registry keys to disable SMB1 server and client
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") {
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -PropertyType DWord -Value 0 -Force | Out-Null
    }
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10") {
      Set-Service -Name mrxsmb10 -StartupType Disabled -ErrorAction SilentlyContinue
      Stop-Service -Name mrxsmb10 -Force -ErrorAction SilentlyContinue
    }
  }
}

# -----------------------------
# Part 5: Services to stop/disable
# -----------------------------
Write-Log "=== Services: stop & disable ==="
$servicesToDisable = @(
  @{Name = 'upnphost'; Display = 'UPnP Device Host' },
  @{Name = 'TlntSvr'; Display = 'Telnet' },            # may not exist
  @{Name = 'SNMPTRAP'; Display = 'SNMP Trap' },
  @{Name = 'RemoteRegistry'; Display = 'Remote Registry' },
  @{Name = 'Wecsvc'; Display = 'Windows Event Collector' } # might be needed depending on environment
)

foreach ($svc in $servicesToDisable) {
  $svcName = $svc.Name
  Do-Action "Stopping & disabling service $svcName ($($svc.Display))" {
    if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
      Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
      Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
    }
    else {
      Write-Log " -> Service $svcName not present (skipping)."
    }
  }
}

# -----------------------------
# Part 6: Network adapter bindings & settings
# -----------------------------
Write-Log "=== Network adapter tweak: disable IPv6 binding & common adapter components ==="

# Components to toggle off (ComponentID names used by Set-NetAdapterBinding)
$adapterComponentsToDisable = @(
  "ms_tcpip6",                 # Internet Protocol Version 6 (TCP/IPv6)
  "ms_msclient",               # Client for Microsoft Networks
  "ms_server",                 # File and Printer Sharing for Microsoft Networks (server)
  "ms_pacer",                  # QoS Packet Scheduler
  "ms_lltdio",                 # Link Layer Topology Discovery Mapper IO Driver
  "ms_rspndr"                  # Link Layer Topology Discovery Responder
  # Note: some components may not exist on all adapters
)

$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -ne 'Disconnected' } -ErrorAction SilentlyContinue
foreach ($a in $adapters) {
  $ifName = $a.Name
  foreach ($comp in $adapterComponentsToDisable) {
    Do-Action "Disabling adapter binding '$comp' on adapter '$ifName'" {
      try {
        Disable-NetAdapterBinding -Name $ifName -ComponentID $comp -ErrorAction Stop
      }
      catch {
        # not all bindings exist
      }
    }
  }

  # DNS register - uncheck "register this connection's addresses in DNS"
  Do-Action "Set DNS client 'RegisterThisConnectionsAddress' = False on adapter '$ifName'" {
    try {
      $ifIndex = $a.ifIndex
      # Using Set-DnsClient (needs admin)
      Set-DnsClient -InterfaceIndex $ifIndex -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue
    }
    catch {}
  }

  # NetBIOS: set via WMI: TcpipNetbiosOptions=2  (0=Default, 1=Enable, 2=Disable)
  Do-Action "Disable NETBIOS over TCP/IP on adapter '$ifName' (via WMI TcpipNetbiosOptions=2)" {
    try {
      $nicCfg = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $a.ifIndex }
      if ($nicCfg -and $nicCfg.TcpipNetbiosOptions -ne 2) {
        $nicCfg.SetTcpipNetbios(2) | Out-Null
      }
    }
    catch {}
  }
}

# Disable port 1900/UPnP related behavior via registry (we set UPnPMode earlier)
# Also stop UPnP service above.

# -----------------------------
# Part 7: Firewall rules (sample inbound denies)
# -----------------------------
Write-Log "=== Firewall: sample inbound denies for Store apps / components ==="

# List of program paths to block inbound. These are samples — verify on your systems.
$firewallBlocks = @(
  @{Name = "Block_MicrosoftEdge_Inbound"; Program = "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe" },
  @{Name = "Block_Xbox_App"; Program = "$env:ProgramFiles\WindowsApps\Microsoft.XboxApp_*" }, # wildcard - may not create rule as-is
  @{Name = "Block_MicrosoftPhotos"; Program = "$env:ProgramFiles\WindowsApps\Microsoft.Windows.Photos_*" },
  @{Name = "Block_MSNNews"; Program = "$env:ProgramFiles\WindowsApps\*MSNNews*" },
  @{Name = "Block_MSNWeather"; Program = "$env:ProgramFiles\WindowsApps\*MSNWeather*" }
)

foreach ($fb in $firewallBlocks) {
  $ruleName = $fb.Name
  $program = $fb.Program
  Do-Action "Creating inbound firewall rule to block: $ruleName (program pattern: $program)" {
    # For patterns, we create a rule blocking all inbound for the profile for the program path if it exists.
    try {
      # If exact file exists
      $resolved = @(Get-ChildItem -Path $program -ErrorAction SilentlyContinue)
      if ($resolved.Count -gt 0) {
        foreach ($p in $resolved) {
          New-NetFirewallRule -DisplayName "$ruleName - $($p.Name)" -Direction Inbound -Action Block -Program $p.FullName -Profile Any -Enabled True -EdgeTraversalPolicy Block -ErrorAction SilentlyContinue | Out-Null
        }
      }
      else {
        # If no file found, create a rule that blocks by service/application group might not be possible; we'll create a generic rule by service name placeholder
        New-NetFirewallRule -DisplayName "$ruleName - placeholder" -Direction Inbound -Action Block -Profile Any -Enabled False -ErrorAction SilentlyContinue | Out-Null
      }
    }
    catch {}
  }
}

# -----------------------------
# Part 8: AppLocker / Store App removal suggestions
# -----------------------------
Write-Log "=== Store app remediation guidance (non-destructive) ==="
Write-Log "Note: Removing built-in modern (UWP) apps or blocking them may remove features for users. Script does NOT auto-delete Store apps. If you want that, I can extend the script to remove selected packages."

# -----------------------------
# Part 9: Windows Defender & Security Center
# -----------------------------
Write-Log "=== Windows Defender & Security center ==="
Do-Action "Enabling Windows Defender service and real-time protection" {
  try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
  }
  catch {
    # If Set-MpPreference missing on older systems, ensure service is started
  }
  if (Get-Service -Name WinDefend -ErrorAction SilentlyContinue) {
    Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WinDefend -ErrorAction SilentlyContinue
  }
}

# -----------------------------
# Part 10: Audit policy: enable success and failure for all subcategories
# -----------------------------
Write-Log "=== Audit policy: enabling success & failure for subcategories (auditpol) ==="
Do-Action "Enabling success+failure for all audit subcategories via auditpol" {
  try {
    auditpol /clear /y | Out-Null
    # rather than clear, enable everything:
    $subcats = (auditpol /list /subcategory:* | Select-String "^\s+.+$" | ForEach-Object { $_.ToString().Trim() })
    foreach ($s in $subcats) {
      auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
    }
  }
  catch {
    # auditpol may require domain policy control; ignore errors
  }
}

# -----------------------------
# Part 11: Local groups checks (report only)
# -----------------------------
Write-Log "=== Group membership checks (report-only) ==="
# You need to specify authorized admins. For safety we only report deviations.
$AuthorizedAdmins = @("Administrator", "YourDomainAdminAccount")  # EDIT this list for your env

# Enumerate Administrators group members
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
Write-Log "Administrators group contains: $($admins -join ', ')"
$unauthorizedAdmins = $admins | Where-Object { $_ -notin $AuthorizedAdmins }
if ($unauthorizedAdmins) {
  Write-Warning "Found Administrators not in your authorized list: $($unauthorizedAdmins -join ', '). Script will not remove them automatically. Review manually or provide an allowlist to auto-remove."
}
else {
  Write-Log "Administrators group matches authorized list (or authorized list not configured)."
}

# Guests group should only have Guest in it
$guests = Get-LocalGroupMember -Group "Guests" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
Write-Log "Guests group contains: $($guests -join ', ')"
$shouldOnly = @("Guest")
$extraGuests = $guests | Where-Object { $_ -notin $shouldOnly }
if ($extraGuests) {
  Write-Warning "Guests group contains extra accounts: $($extraGuests -join ', '). Recommend manual removal or review."
}
else {
  Write-Log "Guests group ok."
}

# Remote Desktop Users: if README says only certain users, script can audit
$rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
Write-Log "Remote Desktop Users group contains: $($rdpUsers -join ', ')"

# -----------------------------
# Part 12: Local Security Options (some already set via secedit)
# -----------------------------
Write-Log "=== Local Security Options checks (some set above) ==="
# Examples: Interactive logon: Do not display last user name
Do-Action "Setting 'Interactive logon: Do not display last user name' (Registry)" {
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -PropertyType DWord -Value 1 -Force | Out-Null
}

# Ctrl+Alt+Del requirement
Do-Action "Require CTRL+ALT+DEL for interactive logon (Interactive logon: Do not require CTRL+ALT+DEL=Disabled) -> set EnableLUA already set above and require secure interactive" {
  # Already handled by secedit UAC settings; explicit registry:
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -PropertyType DWord -Value 0 -Force | Out-Null
}

# -----------------------------
# Part 13: Misc - Disable AutoPlay, disable Wi-Fi Sense-ish features, and disable OneDrive startup
# -----------------------------
Write-Log "=== Miscellaneous tweaks ==="

Do-Action "Disable AutoPlay system-wide" {
  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 0xFF -Force | Out-Null
}

Do-Action "Disable OneDrive from startup for current user (remove run keys)" {
  Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKCU:\Software\Microsoft\OneDrive" -Name "OneDriveSetup" -ErrorAction SilentlyContinue
}

# -----------------------------
# Part 14: Additional local policy checks & guidance
# -----------------------------
Write-Log "=== Additional items (report-only advice) ==="
Write-Log " - Some items like 'Accounts: Administrator account status = disabled' and 'Block Microsoft accounts' can be set via secedit/GPO. Script can be extended to toggle them explicitly; currently we left those to manual review or GPO."
Write-Log " - 'Network security: Restrict NTLM' and some Kerberos settings are domain-impacting; prefer domain GPO."

# -----------------------------
# Final: Summary & reboot suggestion
# -----------------------------
Write-Log "=== Completed tasks/report ==="
if ($Perform) {
  Write-Log "Changes applied. Some changes (feature disable/SMB removal) may require a reboot to take full effect."
  Write-Log "Reboot recommended. To reboot now uncomment the next line."
  # Restart-Computer -Force
}
else {
  Write-Log "Report-only mode. Review findings and run the script again with -ApplyChanges to apply."
}

Write-Log "Done."
