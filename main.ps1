# main.ps1 - Auto-download and run CyberPatriot scripts

Write-Host "Fetching CyberPatriot scripts from GitHub..." -ForegroundColor Cyan

# -----------------------
# GitHub repo details
# -----------------------
# Change these to your repo/user/path
$githubUser = "JaSperryTech-Main"
$repo = "CyberPatriotScript"
$branch = "main"
$scriptsPath = "scripts"

# Base URL for raw scripts
$baseUrl = "https://raw.githubusercontent.com/$githubUser/$repo/$branch/$scriptsPath"

# Temp folder to store downloaded scripts
$tempFolder = Join-Path $env:TEMP "CyberPatriotScripts"
if (-not (Test-Path $tempFolder)) { New-Item -Path $tempFolder -ItemType Directory | Out-Null }

# -----------------------
# Get list of scripts from GitHub
# -----------------------
try {
  # GitHub API to list files in scripts folder
  $apiUrl = "https://api.github.com/repos/$githubUser/$repo/contents/$scriptsPath?ref=$branch"
  $fileList = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -ErrorAction Stop
  $psScripts = $fileList | Where-Object { $_.name -like "*.ps1" }
  if ($psScripts.Count -eq 0) {
    Write-Host "No scripts found in the GitHub repository." -ForegroundColor Red
    exit 1
  }
}
catch {
  Write-Host "Failed to list scripts from GitHub: $_" -ForegroundColor Red
  exit 1
}

# -----------------------
# Download scripts
# -----------------------
$localScripts = @()
foreach ($script in $psScripts) {
  $url = $script.download_url
  $localPath = Join-Path $tempFolder $script.name
  try {
    Invoke-WebRequest -Uri $url -OutFile $localPath -UseBasicParsing -ErrorAction Stop
    $localScripts += $localPath
    Write-Host "Downloaded $($script.name)" -ForegroundColor Green
  }
  catch {
    Write-Host "Failed to download $($script.name): $_" -ForegroundColor Red
  }
}

# -----------------------
# Show menu for selection
# -----------------------
Write-Host "`nAvailable scripts:" -ForegroundColor Yellow
for ($i = 0; $i -lt $localScripts.Count; $i++) {
  Write-Host "[$($i+1)] $(Split-Path $localScripts[$i] -Leaf)"
}

$choice = Read-Host "`nEnter the numbers of the scripts to run (comma-separated, or 'all')"

if ($choice -eq 'all') {
  $selected = $localScripts
}
else {
  $indices = $choice -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
  $selected = @()
  foreach ($i in $indices) {
    if ($i -gt 0 -and $i -le $localScripts.Count) {
      $selected += $localScripts[$i - 1]
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

# -----------------------
# Run the selected scripts
# -----------------------
foreach ($scriptPath in $selected) {
  Write-Host "`nRunning $(Split-Path $scriptPath -Leaf)..." -ForegroundColor Cyan
  try {
    & $scriptPath
    Write-Host "Completed successfully!" -ForegroundColor Green
  }
  catch {
    Write-Host "Error running $(Split-Path $scriptPath -Leaf): $_" -ForegroundColor Red
  }
}

Write-Host "`nAll selected scripts completed!" -ForegroundColor Green
