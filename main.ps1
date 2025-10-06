# main.ps1
# ------------------------
# CyberPatriot Script Runner
# ------------------------
Write-Host "Detecting available CyberPatriot scripts..." -ForegroundColor Cyan

# Define the scripts folder (relative to this script)
$scriptFolder = Join-Path -Path $PSScriptRoot -ChildPath "scripts"

if (-not (Test-Path $scriptFolder)) {
  Write-Host "Scripts folder not found at $scriptFolder" -ForegroundColor Red
  exit 1
}

# Find all .ps1 scripts in the folder
$scripts = Get-ChildItem -Path $scriptFolder -Filter *.ps1 | Sort-Object Name

if ($scripts.Count -eq 0) {
  Write-Host "No scripts found in $scriptFolder" -ForegroundColor Yellow
  exit 1
}

# Show GUI checkbox menu using Out-GridView
$selected = $scripts | Select-Object Name, FullName | Out-GridView -Title "Select scripts to run (CTRL+Click for multiple)" -PassThru

if (-not $selected) {
  Write-Host "No scripts selected. Exiting..." -ForegroundColor Yellow
  exit 0
}

# Run selected scripts
foreach ($script in $selected) {
  Write-Host "`nRunning $($script.Name)..." -ForegroundColor Cyan
  try {
    # Run the script
    & $script.FullName
    Write-Host "$($script.Name) completed successfully!" -ForegroundColor Green
  }
  catch {
    Write-Host "Error running $($script.Name): $_" -ForegroundColor Red
  }
}

Write-Host "`nAll selected scripts completed!" -ForegroundColor Green
