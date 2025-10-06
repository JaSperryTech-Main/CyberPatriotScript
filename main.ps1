# main.ps1 - Console version
Write-Host "Detecting available CyberPatriot scripts..." -ForegroundColor Cyan

# Define scripts folder (relative to this script)
$scriptFolder = Join-Path -Path $PSScriptRoot -ChildPath "scripts"

if (-not (Test-Path $scriptFolder)) {
  Write-Host "Scripts folder not found at $scriptFolder" -ForegroundColor Red
  exit 1
}

# Get all scripts
$scripts = Get-ChildItem -Path $scriptFolder -Filter *.ps1 | Sort-Object Name

if ($scripts.Count -eq 0) {
  Write-Host "No scripts found in $scriptFolder" -ForegroundColor Yellow
  exit 1
}

# Show numbered menu
Write-Host "`nAvailable scripts:" -ForegroundColor Yellow
for ($i = 0; $i -lt $scripts.Count; $i++) {
  Write-Host "[$($i+1)] $($scripts[$i].Name)"
}

# Ask user which scripts to run
$choice = Read-Host "`nEnter the numbers of the scripts to run (comma-separated, or 'all')"

if ($choice -eq 'all') {
  $selected = $scripts
}
else {
  $indices = $choice -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
  $selected = @()
  foreach ($i in $indices) {
    if ($i -gt 0 -and $i -le $scripts.Count) {
      $selected += $scripts[$i - 1]
    }
    else {
      Write-Host "Invalid selection: $i" -ForegroundColor Red
    }
  }
}

if ($selected.Count -eq 0) {
  Write-Host "No scripts selected. Exiting..." -ForegroundColor Yellow
  exit 0
}

# Run the selected scripts
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
