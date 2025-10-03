# Run this before any other script

# List of required modules
$requiredModules = @(
  "NetTCPIP",
  "Defender",
  "PSWindowsUpdate",
  "ScheduledTasks",
  "Security",
  "PowerShellGet",
  "CimCmdlets",
  "GroupPolicy",
  "Microsoft.PowerShell.Management",
  "Microsoft.PowerShell.Utility"
)

# Initialize arrays to track found and not found modules
$foundModules = @()
$notFoundModules = @()

# Function to check and install missing modules
foreach ($module in $requiredModules) {
  try {
    # Check if the module is installed
    $existingModule = Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue
    if ($existingModule) {
      $foundModules += $module
      Write-Host "$module is already installed." -ForegroundColor Green
    }
    else {
      $notFoundModules += $module
      Write-Host "$module not found. Installing" -ForegroundColor Yellow
            
      # Attempt to install the module
      try {
        Install-Module -Name $module -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        Write-Host "$module installed successfully." -ForegroundColor Green
      }
      catch {
        Write-Host "Error installing ${module}: ${$_}" -ForegroundColor Red
      }
    }
  }
  catch {
    Write-Host "Error checking ${module}: ${$_}" -ForegroundColor Red
  }
}

# Summary of modules found and not found
Write-Host "`nSummary:" -ForegroundColor Cyan

if ($foundModules.Count -gt 0) {
  Write-Host "Found Modules:" -ForegroundColor Cyan
  $foundModules | ForEach-Object { Write-Host $_ -ForegroundColor Green }
}
else {
  Write-Host "No modules found." -ForegroundColor Red
}

if ($notFoundModules.Count -gt 0) {
  Write-Host "Not Found Modules (installed during the process):" -ForegroundColor Cyan
  $notFoundModules | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
}
else {
  Write-Host "All required modules were already installed." -ForegroundColor Green
}

# Summary of modules found and not found
Write-Host "`nSummary:" -ForegroundColor Cyan

if ($foundModules.Count -gt 0) {
  Write-Host "Found Modules:" -ForegroundColor Cyan
  $foundModules | ForEach-Object { Write-Host $_ -ForegroundColor Green }
}
else {
  Write-Host "No modules found." -ForegroundColor Red
}

if ($notFoundModules.Count -gt 0) {
  Write-Host "Not Found Modules (installed during the process):" -ForegroundColor Cyan
  $notFoundModules | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
}
else {
  Write-Host "All required modules were already installed." -ForegroundColor Green
}