# main.ps1 - Auto-download and run all CyberPatriot scripts automatically

Write-Host "Fetching and running all CyberPatriot scripts from GitHub..." -ForegroundColor Cyan

# -----------------------
# GitHub repo details
# -----------------------
$githubUser = "JaSperryTech-Main"
$repo = "CyberPatriotScript"
$branch = "main"
$scriptsPath = "scripts"

# Temp folder to store downloaded scripts
$tempFolder = Join-Path $env:TEMP "CyberPatriotScripts"
if (-not (Test-Path $tempFolder)) { New-Item -Path $tempFolder -ItemType Directory | Out-Null }

# -----------------------
# Get list of scripts from GitHub
# -----------------------
try {
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
# Download and run scripts
# -----------------------
foreach ($script in $psScripts) {
  $url = $script.download_url
  $localPath = Join-Path $tempFolder $script.name

  try {
    # Download
    Invoke-WebRequest -Uri $url -OutFile $localPath -UseBasicParsing -ErrorAction Stop
    Write-Host "Downloaded $($script.name)" -ForegroundColor Green

    # Run
    Write-Host "Running $($script.name)..." -ForegroundColor Cyan
    & $localPath
    Write-Host "$($script.name) completed successfully!" -ForegroundColor Green
  }
  catch {
    Write-Host "Error with $($script.name): $_" -ForegroundColor Red
  }
}

Write-Host "`nAll scripts have been downloaded and executed!" -ForegroundColor Green
