# main.ps1
# ------------------------
# CyberPatriot Script Runner (GUI)
# ------------------------
Write-Host "Detecting available CyberPatriot scripts..." -ForegroundColor Cyan

# ------------------------
# Self-elevate script if not running as Administrator
# ------------------------
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Script is not running as Administrator. Attempting to relaunch with admin rights..." -ForegroundColor Yellow

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = "powershell.exe"
  $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
  $psi.Verb = "runas"
  try {
    [System.Diagnostics.Process]::Start($psi) | Out-Null
    exit
  }
  catch {
    Write-Host "Failed to run as Administrator: $_" -ForegroundColor Red
    exit 1
  }
}

# ------------------------
# Define scripts folder
# ------------------------
$scriptFolder = Join-Path -Path $PSScriptRoot -ChildPath "scripts"

if (-not (Test-Path $scriptFolder)) {
  Write-Host "Scripts folder not found at $scriptFolder" -ForegroundColor Red
  exit 1
}

# ------------------------
# Find all .ps1 scripts
# ------------------------
$scripts = Get-ChildItem -Path $scriptFolder -Filter *.ps1 | Sort-Object Name

if ($scripts.Count -eq 0) {
  Write-Host "No scripts found in $scriptFolder" -ForegroundColor Yellow
  exit 1
}

# ------------------------
# GUI checkbox selection
# ------------------------
$selected = $scripts | Select-Object Name, FullName |
Out-GridView -Title "Select scripts to run (CTRL+Click for multiple)" -PassThru

if (-not $selected) {
  Write-Host "No scripts selected. Exiting..." -ForegroundColor Yellow
  exit 0
}

# ------------------------
# Run selected scripts
# ------------------------
foreach ($script in $selected) {
  Write-Host "`nRunning $($script.Name)..." -ForegroundColor Cyan
  try {
    & $script.FullName
    Write-Host "$($script.Name) completed successfully!" -ForegroundColor Green
  }
  catch {
    Write-Host "Error running $($script.Name): $_" -ForegroundColor Red
  }
}

Write-Host "`nAll selected scripts completed!" -ForegroundColor Green
