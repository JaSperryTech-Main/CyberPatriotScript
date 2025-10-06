# main.ps1
# ------------------------
# CyberPatriot Script Runner
# ------------------------
Write-Host "Detecting available CyberPatriot scripts..." -ForegroundColor Cyan

# Self-elevate script if not running as Administrator
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Script is not running as Administrator. Attempting to relaunch with admin rights..." -ForegroundColor Yellow

  # Relaunch the script as admin
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


# -----------------------
# Default GitHub repo & local folder
# -----------------------
$defaultRepo = "https://github.com/JaSperryTech-Main/CyberPatriotScript.git"
$defaultDestination = "$env:USERPROFILE\Downloads\CyberPatriotScripts"

# -----------------------
# Prompt for repo info with defaults
# -----------------------
$repoUrl = Read-Host "Enter GitHub repo URL (Press Enter for default: $defaultRepo)"
if ([string]::IsNullOrWhiteSpace($repoUrl)) { $repoUrl = $defaultRepo }

$destination = Read-Host "Enter local folder path (Press Enter for default: $defaultDestination)"
if ([string]::IsNullOrWhiteSpace($destination)) { $destination = $defaultDestination }

Write-Host "Using repo URL: $repoUrl"
Write-Host "Using destination folder: $destination"

# -----------------------
# Check if git is installed
# -----------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Write-Host "Git is not installed. Please install Git before running this script." -ForegroundColor Red
  exit 1
}

# -----------------------
# Clone repo if not exists
# -----------------------
try {
  if (-not (Test-Path $destination)) {
    New-Item -Path $destination -ItemType Directory | Out-Null
  }

  if (-not (Test-Path (Join-Path $destination ".git"))) {
    Write-Host "Cloning repository..." -ForegroundColor Cyan
    git clone $repoUrl $destination
    Write-Host "Repository cloned successfully!" -ForegroundColor Green
  }
  else {
    Write-Host "Repository already exists. Skipping clone." -ForegroundColor Yellow
  }
}
catch {
  Write-Host "Failed to clone repository: $_" -ForegroundColor Red
  exit 1
}

# -----------------------
# Define scripts folder
# -----------------------
$scriptFolder = Join-Path -Path $destination -ChildPath "scripts"

if (-not (Test-Path $scriptFolder)) {
  Write-Host "Scripts folder not found at $scriptFolder" -ForegroundColor Red
  exit 1
}

# -----------------------
# Find all .ps1 scripts
# -----------------------
$scripts = Get-ChildItem -Path $scriptFolder -Filter *.ps1 | Sort-Object Name

if ($scripts.Count -eq 0) {
  Write-Host "No scripts found in $scriptFolder" -ForegroundColor Yellow
  exit 1
}

# -----------------------
# GUI checkbox selection
# -----------------------
$selected = $scripts | Select-Object Name, FullName |
Out-GridView -Title "Select scripts to run (CTRL+Click for multiple)" -PassThru

if (-not $selected) {
  Write-Host "No scripts selected. Exiting..." -ForegroundColor Yellow
  exit 0
}

# -----------------------
# Run selected scripts
# -----------------------
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
