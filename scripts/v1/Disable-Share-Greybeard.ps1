<#
.SYNOPSIS
  Disable (remove) SMB file shares named "greybeard" (case-insensitive).
.DESCRIPTION
  Backs up share metadata and permissions, then removes the share(s).
.PARAMETER ShareName
  Share name or substring to match. Default: "greybeard"
.PARAMETER Force
  Skip interactive confirmation and force removal.
.EXAMPLE
  .\Disable-Share-Greybeard.ps1
  Finds shares with "greybeard" in the name, backs them up, and prompts before removal.
.EXAMPLE
  .\Disable-Share-Greybeard.ps1 -Force
  Runs non-interactively and removes matching shares.
#>

param(
  [string]$ShareName = 'greybeard',
  [switch]$Force
)

# Admin check
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
  exit 1
}

# Paths & logging
$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$download = [IO.Path]::Combine($env:USERPROFILE, 'Downloads')
$logPath = Join-Path $download "Disable-Share-$($ShareName)-$ts.log"
$backupDir = Join-Path $download "ShareBackups"
if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory | Out-Null }

function Write-Log {
  param([string]$Message)
  $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
  $entry | Out-File -FilePath $logPath -Append -Encoding UTF8
  Write-Host $Message
}

Write-Log "Script started. Target share pattern: '$ShareName'"

# Get matching SMB shares
try {
  $matches = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -imatch [regex]::Escape($ShareName) -or $_.Name -ilike "*$ShareName*" }
}
catch {
  Write-Log "ERROR: Unable to query SMB shares: $_"
  exit 1
}

if (-not $matches -or $matches.Count -eq 0) {
  Write-Log "No SMB shares found matching '$ShareName'. Nothing to do."
  Write-Host "`nNo matching SMB shares found." -ForegroundColor Yellow
  Write-Log "Script finished."
  Start-Process notepad.exe $logPath
  exit 0
}

Write-Log "Found $($matches.Count) matching share(s): $($matches.Name -join ', ')"
Write-Host "`nFound matching shares:`n" -ForegroundColor Cyan
$matches | ForEach-Object {
  Write-Host (" - {0}  (Path: {1})" -f $_.Name, $_.Path) -ForegroundColor Green
}

# Confirm unless forced
if (-not $Force) {
  $confirm = Read-Host "`nProceed to backup and remove these shares? Type 'YES' to continue"
  if ($confirm -ne 'YES') {
    Write-Log "User declined to proceed. Exiting."
    Write-Host "Aborted by user." -ForegroundColor Yellow
    Start-Process notepad.exe $logPath
    exit 0
  }
}

# Backup metadata + ACLs
foreach ($s in $matches) {
  $shareName = $s.Name
  $sharePath = $s.Path
  $desc = $s.Description
  $backupFile = Join-Path $backupDir ("ShareBackup_{0}_{1}.json" -f $shareName, $ts)

  Write-Log "Backing up share: $shareName (Path: $sharePath)"
  try {
    # Collect share info and access entries
    $access = Get-SmbShareAccess -Name $shareName -ErrorAction SilentlyContinue | Select-Object AccountName, AccessControlType, AccessRight
    $info = [ordered]@{
      Name                  = $shareName
      Path                  = $sharePath
      Description           = $desc
      ScopeName             = $s.ScopeName
      FolderEnumerationMode = $s.FolderEnumerationMode.ToString()
      ConcurrentUserLimit   = $s.ConcurrentUserLimit
      Access                = $access
      RawSmbShareObject     = $s | Select-Object *
    }
    $info | ConvertTo-Json -Depth 5 | Out-File -FilePath $backupFile -Encoding UTF8
    Write-Log "Backup written to $backupFile"
  }
  catch {
    Write-Log "WARNING: Failed to back up share ${shareName}: $_"
  }

  # Attempt removal
  try {
    Remove-SmbShare -Name $shareName -Force -ErrorAction Stop
    Write-Log "Removed SMB share: $shareName"
  }
  catch {
    Write-Log "ERROR: Failed to remove SMB share ${shareName}: $_"
  }
}

# Extra check: ensure no matching shares remain
try {
  $remaining = Get-SmbShare | Where-Object { $_.Name -imatch [regex]::Escape($ShareName) -or $_.Name -ilike "*$ShareName*" }
  if ($remaining.Count -eq 0) {
    Write-Log "All matching shares removed."
  }
  else {
    Write-Log "Some matching shares remain: $($remaining.Name -join ', ')"
  }
}
catch {
  Write-Log "ERROR checking remaining shares: $_"
}

Write-Log "Script finished."
Write-Host "`nLog saved to: $logPath" -ForegroundColor Yellow
Start-Process notepad.exe $logPath
