# main.ps1
Write-Host "Fetching and running CyberPatriot scripts..." -ForegroundColor Cyan

# Define your scripts in a list for easier scaling
$scripts = @(
  @{ Name = "Set-LockoutPolicy"; Url = "https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-LockoutPolicy.ps1" },
  @{ Name = "Set-PasswordPolicy"; Url = "https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-PasswordPolicy.ps1" },
  @{ Name = "Set-UserAccountSettings"; Url = "https://raw.githubusercontent.com/JaSperryTech-Main/CyberPatriotScript/main/scripts/Set-UserAccountSettings.ps1" }
)

# Show a menu
Write-Host "`nAvailable scripts:" -ForegroundColor Yellow
for ($i = 0; $i -lt $scripts.Count; $i++) {
  Write-Host "[$($i+1)] $($scripts[$i].Name)"
}

# Ask user which scripts to run
$choice = Read-Host "`nEnter the numbers of the scripts you want to run (comma-separated, or 'all' to run all)"

if ($choice -eq "all") {
  $selected = $scripts
}
else {
  $indices = $choice -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
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

# Run the selected scripts
foreach ($script in $selected) {
  Write-Host "`nRunning $($script.Name)..." -ForegroundColor Cyan
  try {
    Invoke-RestMethod $script.Url | Invoke-Expression
    Write-Host "$($script.Name) completed successfully!" -ForegroundColor Green
  }
  catch {
    Write-Host "Error running $($script.Name): $_" -ForegroundColor Red
  }
}

Write-Host "`nAll selected scripts completed!" -ForegroundColor Green
