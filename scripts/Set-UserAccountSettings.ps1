# Script: CyberPatriot User Account Configuration (cleaned for VSCode/PSScriptAnalyzer)
# Windows Server 2019/2022
# Run as Administrator

# -----------------------
# Admin check
# -----------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
  exit 1
}

# -----------------------
# Logging setup (Downloads)
# -----------------------
$logPath = "$env:USERPROFILE\Downloads\CyberPatriot_UserConfig.log"
"=== CyberPatriot User Config Log - $(Get-Date) ===" | Out-File -FilePath $logPath -Encoding UTF8

function Write-Log {
  param([string]$Message)
  $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
}

Write-Host "Starting CyberPatriot README parse + user enforcement..." -ForegroundColor Cyan
Write-Log "Start run."

# -----------------------
# Find .lnk (if present) or fallback URL
# -----------------------
$desktopPaths = @(
  [Environment]::GetFolderPath("Desktop"),
  "$env:PUBLIC\Desktop"
)

$readmeShortcut = $desktopPaths | ForEach-Object {
  Get-ChildItem -Path $_ -Filter "*CyberPatriot*README*.lnk" -ErrorAction SilentlyContinue
} | Select-Object -First 1

$fallbackUrl = "https://www.uscyberpatriot.org/Pages/Readme/cp18_tr_e_server2019_readme_43wk0c7220pu1.aspx"

if ($readmeShortcut) {
  try {
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($readmeShortcut.FullName)
    $targetUrl = $shortcut.TargetPath
    if (-not $targetUrl) { $targetUrl = $shortcut.Arguments }
    Write-Host "Found README shortcut -> $($readmeShortcut.FullName)" -ForegroundColor Green
    Write-Log "Found README shortcut: $($readmeShortcut.FullName)"
    Write-Log "Extracted target: $targetUrl"
  }
  catch {
    Write-Host "Warning: failed to read .lnk, will use fallback URL." -ForegroundColor Yellow
    Write-Log "Failed to read .lnk: $_"
    $targetUrl = $fallbackUrl
  }
}
else {
  Write-Host "README shortcut not found; using fallback URL." -ForegroundColor Yellow
  Write-Log "README shortcut not found."
  $targetUrl = $fallbackUrl
}

# -----------------------
# Download README page HTML
# -----------------------
try {
  Write-Host "Downloading README from: $targetUrl" -ForegroundColor Cyan
  Write-Log "Downloading README from: $targetUrl"
  $webPage = Invoke-WebRequest -Uri $targetUrl -UseBasicParsing -ErrorAction Stop
  $pageHtml = $webPage.Content
  Write-Log "Download success; HTML length: $($pageHtml.Length)"
}
catch {
  Write-Host "ERROR: Failed to download page: $_" -ForegroundColor Red
  Write-Log "ERROR: Failed to download page: $_"
  exit 1
}

# -----------------------
# Extract <pre> block
# -----------------------
$preMatch = [regex]::Match($pageHtml, "<pre\b[^>]*>([\s\S]*?)</pre>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
if ($preMatch.Success) {
  $preContent = $preMatch.Groups[1].Value.Trim()
  Write-Log "Extracted <pre> block from HTML."
}
else {
  $idx = $pageHtml.IndexOf("Authorized Administrators", [System.StringComparison]::InvariantCultureIgnoreCase)
  if ($idx -ge 0) {
    $start = [Math]::Max(0, $idx - 200)
    $len = [Math]::Min($pageHtml.Length - $start, 1000)
    $preContent = $pageHtml.Substring($start, $len)
  }
  else {
    Write-Host "ERROR: Could not find the Admins/Users content on the page." -ForegroundColor Red
    Write-Log "ERROR: Admins/Users block not found in page."
    exit 1
  }
}

# Clean HTML tags
$cleanPre = $preContent -replace '<.*?>', ''
$cleanPre = $cleanPre -replace "[`r`n]+", " "
$cleanPre = $cleanPre.Trim()
Write-Log "=== Extracted and cleaned PRE content ==="
Write-Log $cleanPre
Write-Log "=== End PRE content ==="

# -----------------------
# Parse Authorized Administrators
# -----------------------
$adminPattern = '(?i)(\w+)(?:\s*\(you\))?\s*password:\s*([^\s<>]+?)(?=(?:\w+(?:\s*\(you\))?\s+password:)|Authorized Users:|$)'

$authorizedAdmins = @()
$adminPasswordMap = @{}

$adminMatches = [regex]::Matches($cleanPre, $adminPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
foreach ($m in $adminMatches) {
  $user = $m.Groups[1].Value
  $plainPassword = $m.Groups[2].Value.Trim()
  $authorizedAdmins += $user
  $adminPasswordMap[$user] = $plainPassword
}

Write-Log "Parsed authorized admins count: $($authorizedAdmins.Count)"
foreach ($a in $authorizedAdmins) { Write-Log "Admin: $a / pwd: $($adminPasswordMap[$a])" }

# -----------------------
# Parse Authorized Users
# -----------------------
$usersMatch = [regex]::Match($cleanPre, 'Authorized Users:(.+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$authorizedUsers = @()
if ($usersMatch.Success) {
  $rawUsers = $usersMatch.Groups[1].Value
  $usersClean = $rawUsers -replace '[^A-Za-z0-9]', ' '
  $authorizedUsers = ($usersClean -split '\s+') | Where-Object { $_ -match '^\w+$' }
  Write-Log "Parsed authorized users count: $($authorizedUsers.Count)"
  foreach ($u in $authorizedUsers) { Write-Log "User: $u" }
}
else {
  Write-Log "No 'Authorized Users:' block found in extracted content."
}

$allAuthorized = $authorizedAdmins + $authorizedUsers

# -----------------------
# Process Local Users
# -----------------------
$allUsers = Get-LocalUser | Where-Object {
  $_.Name -notlike "DefaultAccount" -and $_.Name -notlike "Guest" -and $_.Name -notlike "WDAGUtilityAccount"
}

Write-Host "`nProcessing local user accounts..." -ForegroundColor Cyan
Write-Log "Processing local user accounts - total found: $($allUsers.Count)"

foreach ($user in $allUsers) {
  $uname = $user.Name
  $isAuthorized = $allAuthorized -contains $uname
  Write-Host "`nUser: $uname" -ForegroundColor Yellow
  Write-Log "User encountered: $uname (Enabled: $($user.Enabled))"

  if ($isAuthorized) {
    Write-Host "  Status: AUTHORIZED" -ForegroundColor Green
    Write-Log "  Status: AUTHORIZED (found in parsed README)"

    if (-not $user.Enabled) {
      Write-Host "  Enabling account..." -ForegroundColor Cyan
      Write-Log "  Action: Enabling account"
      Enable-LocalUser -Name $uname
    }

    if ($authorizedAdmins -contains $uname) {
      $plainPassword = $adminPasswordMap[$uname]
      if ($plainPassword) {
        try {
          $securePwd = ConvertTo-SecureString $plainPassword -AsPlainText -Force
          Set-LocalUser -Name $uname -Password $securePwd
          Write-Host "  Password reset for admin $uname" -ForegroundColor Cyan
          Write-Log "  Action: Password reset for admin $uname"
        }
        catch {
          Write-Host "  Failed to reset password for $uname: $_" -ForegroundColor Red
          Write-Log "  ERROR: Failed to reset password for $uname: $_"
        }
      }
      else {
        Write-Log "  No password found in README for admin $uname"
      }
    }

    try {
      net user $uname /logonpasswordchg:yes | Out-Null
      Set-LocalUser -Name $uname -PasswordNeverExpires $false
      Write-Host "  Password change required at next logon" -ForegroundColor Green
      Write-Log "  Result: Password change required at next logon"
    }
    catch {
      Write-Log "  ERROR applying password flags for $uname: $_"
    }
  }
  else {
    Write-Host "  Status: UNAUTHORIZED" -ForegroundColor Red
    Write-Log "  Status: UNAUTHORIZED (not found in README)"

    if ($user.Enabled) {
      Write-Host "  Disabling account..." -ForegroundColor Cyan
      Write-Log "  Action: Disabling account"
      Disable-LocalUser -Name $uname
      Write-Host "  Account disabled" -ForegroundColor Red
      Write-Log "  Result: Account DISABLED"
    }
    else {
      Write-Log "  Account already disabled"
    }
  }
}

# -----------------------
# Final report
# -----------------------
Write-Host "`nFinal Account Status Report:" -ForegroundColor Cyan
Write-Log "Final Account Status Report:"
foreach ($user in $allUsers) {
  $status = if ($user.Enabled) { "ENABLED" } else { "DISABLED" }
  $authorized = if ($allAuthorized -contains $user.Name) { "[AUTHORIZED]" } else { "[UNAUTHORIZED]" }
  $line = "{0,-20} - {1} {2}" -f $user.Name, $status, $authorized
  Write-Host $line -ForegroundColor (if ($user.Enabled) { "Green" } else { "Red" })
  Write-Log $line
}

Write-Log "Script execution complete."
Write-Host "`nLog file saved to: $logPath" -ForegroundColor Yellow
Start-Process notepad.exe $logPath
