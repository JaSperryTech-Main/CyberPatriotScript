# =========================
# CyberPatriot User Account Enforcer
# =========================
# Windows Server 2019/2022
# Run as Administrator

# -----------------------
# Admin check
# -----------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
  exit 1
}

# -----------------------
# Logging
# -----------------------
$logPath = "$env:USERPROFILE\Downloads\CyberPatriot_UserConfig.log"
"=== CyberPatriot User Config Log - $(Get-Date) ===" | Out-File -FilePath $logPath -Encoding UTF8

function Write-Log {
  param([string]$Message) 
  $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
}

Write-Host "CyberPatriot User Account Enforcer starting..." -ForegroundColor Cyan
Write-Log "Script started."

# -----------------------
# Prompt for README URL
# -----------------------
$url = Read-Host "Enter the full URL to the CyberPatriot README"

# -----------------------
# Download README
# -----------------------
try {
  Write-Host "Downloading README from $url..." -ForegroundColor Cyan
  Write-Log "Downloading README from $url"
  $web = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
  $html = $web.Content
  Write-Log "Download success; HTML length: $($html.Length)"
}
catch {
  Write-Host "ERROR: Failed to download page: $_" -ForegroundColor Red
  Write-Log "ERROR: Failed to download page: $_"
  exit 1
}

# -----------------------
# Extract and clean content
# -----------------------
try {
  # Strip <pre> or fallback to headings
  $preMatch = [regex]::Match($html, "(?is)<pre\b[^>]*>([\s\S]*?)</pre>")
  if ($preMatch.Success) { $raw = $preMatch.Groups[1].Value }
  else {
    $marker = [regex]::Match($html, "(?is)(Authorized Administrators:.*?)(Authorized Users:.*|$)")
    if ($marker.Success) { $raw = $marker.Value }
    else {
      $dumpPath = "$env:USERPROFILE\Downloads\README_debug.html"
      $html | Out-File -FilePath $dumpPath -Encoding UTF8
      Write-Host "ERROR: Could not find Admin/User content. Saved HTML to $dumpPath" -ForegroundColor Red
      Write-Log "ERROR: Admin/User block not found. Saved HTML to $dumpPath"
      exit 1
    }
  }

  $cleanPre = $raw -replace "<br\s*/?>", "`n" -replace "<.*?>", "" -replace "`r`n", "`n"
  $cleanPre = $cleanPre.Trim()
  Write-Log "Cleaned README content."
}
catch {
  Write-Host "ERROR while cleaning README: $_" -ForegroundColor Red
  Write-Log "ERROR while cleaning README: $_"
  exit 1
}

# -----------------------
# Parse Authorized Administrators
# -----------------------
$authorizedAdmins = @()
$adminPasswordMap = @{}
$lines = $cleanPre -split "`n" | ForEach-Object { $_.Trim() }

for ($i = 0; $i -lt $lines.Count; $i++) {
  $line = $lines[$i]
  if ($line -match '(?i)^Authorized Administrators:') {
    $j = $i + 1
    while ($j -lt $lines.Count) {
      $ln = $lines[$j]
      if ($ln -match '(?i)^Authorized Users:') { break }
      if ($ln -eq "") { $j++; continue }

      # Multi-line: username then password line
      if ($ln -match '^(?<user>\w+)(?:\s*\(you\))?$') {
        $u = $matches['user']
        $pwd = $null
        for ($k = 1; $k -le 2; $k++) {
          if ($j + $k -ge $lines.Count) { break }
          $next = $lines[$j + $k]
          if ($next -match '(?i)^password:\s*(?<p>.+)$') {
            $pwd = $matches['p'].Trim()
            $j = $j + $k
            break
          }
        }
        $authorizedAdmins += $u
        if ($pwd) { $adminPasswordMap[$u] = $pwd }
      }
      elseif ($ln -match '^(?<user>\w+)\s+password:\s*(?<p>.+)$') {
        $authorizedAdmins += $matches['user']
        $adminPasswordMap[$matches['user']] = $matches['p'].Trim()
      }
      $j++
    }
    break
  }
}

Write-Log ("Parsed admins: " + ($authorizedAdmins -join ', '))

# -----------------------
# Parse Authorized Users
# -----------------------
$authorizedUsers = @()
if ($cleanPre -match '(?is)Authorized Users:(.*)') {
  $block = $matches[1]
  $usersClean = ($block -replace '[^A-Za-z0-9\-_\.`n]', ' ') -replace "`n", " "
  $authorizedUsers = ($usersClean -split '\s+') | Where-Object { $_ -ne '' -and $_ -notmatch '(?i)^password$' }
  Write-Log ("Parsed users: " + ($authorizedUsers -join ', '))
}

$allAuthorized = $authorizedAdmins + $authorizedUsers

# -----------------------
# PROMPT: Ask for single password to apply to all authorized accounts
# -----------------------
function Convert-SecureStringToPlain {
  param([System.Security.SecureString]$s)
  if (-not $s) { return $null }
  $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try { return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
  finally { if ($bstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
}

# Read & confirm password (secure)
while ($true) {
  $pw1 = Read-Host "Enter the password to set for ALL authorized accounts (input hidden)" -AsSecureString
  $pw2 = Read-Host "Confirm password" -AsSecureString

  $plain1 = Convert-SecureStringToPlain $pw1
  $plain2 = Convert-SecureStringToPlain $pw2

  if ($plain1 -eq $plain2 -and $plain1 -ne $null -and $plain1.Length -gt 0) {
    # store secure string for later use, but avoid logging the plaintext
    $Global:UniformPasswordSecure = $pw1
    # clear plaintext copies from memory ASAP
    $plain1 = $null
    $plain2 = $null
    break
  }
  else {
    Write-Host "Passwords did not match or were empty — try again." -ForegroundColor Yellow
  }
}

Write-Log "Uniform password captured for application to authorized accounts."

# -----------------------
# Process Local Users (apply uniform password to authorized accounts)
# -----------------------
$allUsers = Get-LocalUser | Where-Object { $_.Name -notlike "DefaultAccount" -and $_.Name -notlike "Guest" -and $_.Name -notlike "WDAGUtilityAccount" }

Write-Host "`nProcessing local users..." -ForegroundColor Cyan
Write-Log ("Processing local users, count: " + $allUsers.Count)

foreach ($user in $allUsers) {
  $uname = $user.Name
  $unameBraced = "{" + $uname + "}"
  $isAuth = $allAuthorized -contains $uname
  Write-Host "`nUser: $unameBraced" -ForegroundColor Yellow
  Write-Log ("User: " + $unameBraced + ", Enabled=" + $user.Enabled)

  if ($isAuth) {
    Write-Host "  Status: AUTHORIZED" -ForegroundColor Green
    Write-Log ("Authorized: " + $unameBraced)

    if (-not $user.Enabled) {
      Enable-LocalUser -Name $uname
      Write-Host ("  Enabled account " + $unameBraced) -ForegroundColor Cyan
      Write-Log ("Enabled account " + $unameBraced)
    }

    # Set the uniform password for all authorized accounts (admins + users)
    try {
      Set-LocalUser -Name $uname -Password $Global:UniformPasswordSecure
      Write-Host ("  Password set for " + $unameBraced) -ForegroundColor Cyan
      Write-Log ("Password set for " + $unameBraced)
    }
    catch {
      Write-Host ("  Failed to set password for " + $unameBraced + ": $_") -ForegroundColor Red
      Write-Log ("Failed to set password for " + $unameBraced + ": $_")
    }

    # Enforce change at next logon and disable password never expires
    try {
      net user $uname /logonpasswordchg:yes | Out-Null
      Set-LocalUser -Name $uname -PasswordNeverExpires $false
      Write-Host ("  Require password change at next logon for " + $unameBraced) -ForegroundColor Green
      Write-Log ("Require password change at next logon for " + $unameBraced)
    }
    catch {
      Write-Host ("  Could not enforce password change for " + $unameBraced + ": $_") -ForegroundColor Yellow
      Write-Log ("Could not enforce password change for " + $unameBraced + ": $_")
    }
  }
  else {
    Write-Host "  Status: UNAUTHORIZED" -ForegroundColor Red
    Write-Log ("Unauthorized: " + $unameBraced)

    if ($user.Enabled) {
      Disable-LocalUser -Name $uname
      Write-Host ("  Disabled account " + $unameBraced) -ForegroundColor Red
      Write-Log ("Disabled account " + $unameBraced)
    }
    else { Write-Log ("Account already disabled: " + $unameBraced) }
  }
}

# -----------------------
# Final report
# -----------------------
Write-Host "`nFinal Account Status Report:" -ForegroundColor Cyan
Write-Log "Final Report:"
foreach ($user in $allUsers) {
  $displayName = "{" + $user.Name + "}"
  $status = if ($user.Enabled) { "ENABLED" } else { "DISABLED" }
  $authorized = if ($allAuthorized -contains $user.Name) { "[AUTHORIZED]" } else { "[UNAUTHORIZED]" }
  $line = "{0,-25} - {1} {2}" -f $displayName, $status, $authorized
  Write-Host $line -ForegroundColor (if ($user.Enabled) { "Green" } else { "Red" })
  Write-Log $line
}

Write-Log "Script complete."
Write-Host "`nLog saved to $logPath"
Start-Process notepad.exe $logPath
