Powershell Script2:#RUN IN ADMIN 
#Make sure to do your questions first this script does disable network shares
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "This script must be run as administrator." -ForegroundColor Red
  exit
}

Write-Host "Starting script"

# Disable all guest user accounts
$users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"

foreach ($user in $users) {
  if ($user.SID -like "*-501" -or $user.Name -eq "Guest") {
    Write-Host "Disabling guest account: $($user.Name)"
    try {
      Disable-LocalUser -Name $user.Name
      Write-Host "$($user.Name) has been disabled."
    }
    catch {
      Write-Host "Failed to disable $($user.Name): $_"
    }
  }
  else {
    Write-Host "User $($user.Name) is not a guest account."
  }
}

Write-Host "Checking for file shares"

# List of allowed standard shares
$allowedShares = @("ADMIN$", "C$", "IPC$")

# Get all shared folders on the system
$shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Name -notin $allowedShares }

# Check if there are any non-standard shares
if ($shares.Count -eq 0) {
  Write-Host "Only standard shares (ADMIN$, C$, IPC$) are present. No action needed."
}
else {
  Write-Host "Non-standard shares found:"
  $shares | ForEach-Object { Write-Host " - $($_.Name)" }

  # Prompt user for confirmation to delete non-standard shares
  $response = Read-Host "Do you want to delete the non-standard shares? (y/n)"

  if ($response -eq "y") {
    # Delete each non-standard share
    foreach ($share in $shares) {
      try {
        $share.Delete() | Out-Null
        Write-Host "Deleted share: $($share.Name)"
      }
      catch {
        Write-Host "Failed to delete share: $($share.Name)" -ForegroundColor Red
      }
    }
    Write-Host "Non-standard shares have been deleted."
  }
  else {
    Write-Host "No shares were deleted. Continuing."
  }
}

# Define the registry path and name for Windows SmartScreen
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$registryName = "EnableSmartScreen"

# Set the value for Windows SmartScreen (Warn = "Prompt"; Block = "Block"; Disabled = "Off")
$SmartScreenSetting = "Prompt"

# Check if the key exists, create if it does not
if (!(Test-Path -Path $registryPath)) {
  New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry key to configure SmartScreen
Set-ItemProperty -Path $registryPath -Name $registryName -Value $SmartScreenSetting

# Output result
Write-Output "Windows Defender SmartScreen configured to Warn (Prompt) setting."

# Firewall rules - Disabling inbound rules for specified applications
$applications = @(
  "MicrosoftEdge",
  "Search",
  "Microsoft.MSN.Money",
  "Microsoft.MSN.Sports",
  "Microsoft.MSN.News",
  "Microsoft.MSN.Weather",
  "Microsoft.Photos",
  "Microsoft.XboxApp"
)

foreach ($app in $applications) {
  Write-Host "Disabling inbound firewall rule for $app"
  New-NetFirewallRule -DisplayName "$app Inbound Block" -Direction Inbound -Action Block -Program "C:\Program Files\WindowsApps\$app" -Profile Any -Enabled True -ErrorAction SilentlyContinue
}

# Function to enable auditing for success and failure for all options
function Enable-Auditing {
  Write-Host "Enabling auditing for success and failure for all options" -ForegroundColor Cyan

  # Enable auditing for all categories using AuditPol
  $auditCategories = @(
    "Logon/Logoff",
    "Account Logon",
    "Account Management",
    "Directory Service Access",
    "Object Access",
    "Privilege Use",
    "Process Tracking",
    "System Events",
    "Detailed Tracking",
    "Policy Change",
    "Account Lockout",
    "Special Logon",
    "Other Logon/Logoff Events"
  )

  foreach ($category in $auditCategories) {
    try {
      Write-Host "Checking available subcategories for: $category" -ForegroundColor Yellow
      # Verify available subcategories for the category
      $availableSubcategories = auditpol /list /subcategory:$category
            
      # Enable Success and Failure auditing for each category
      Write-Host "Enabling auditing for: $category" -ForegroundColor Green
      auditpol /set /subcategory:"$category" /success:enable /failure:enable
      Write-Host "Successfully enabled auditing for: $category" -ForegroundColor Green
    }
    catch {
      Write-Host "Failed to enable auditing for: $category" -ForegroundColor Red
    }
  }
}

# Call the function to enable auditing
Enable-Auditing

Write-Host "Auditing for success and failure has been enabled for all available categories." -ForegroundColor Green

# Function to enable Strict Windows Search mode
function Enable-StrictWindowsSearchMode {
  try {
    Write-Host "Enabling Strict Windows Search Mode" -ForegroundColor Cyan

    # Define the registry path for Windows Search settings
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"

    # Set Windows Search to "Strict" mode (restrict indexing locations)
    Set-ItemProperty -Path $registryPath -Name "BingSearchEnabled" -Value 0 # Disable Bing search integration
    Set-ItemProperty -Path $registryPath -Name "CortanaEnabled" -Value 0 # Disable Cortana
    Set-ItemProperty -Path $registryPath -Name "AllowSearchToUseLocation" -Value 0 # Disable location-based search results

    # Disable indexing of file contents and user profile
    Set-ItemProperty -Path $registryPath -Name "EnableIndexer" -Value 0 # Disable the indexing service
    Set-ItemProperty -Path $registryPath -Name "DisableSearchBoxSuggestions" -Value 1 # Disable search suggestions

    # Disable indexing of user profiles and certain sensitive areas
    Set-ItemProperty -Path $registryPath -Name "ExcludeFromIndexing" -Value 1 # Exclude certain file types from indexing

    # Restart Windows Search service to apply changes
    Write-Host "Restarting Windows Search service" -ForegroundColor Cyan
    Restart-Service -Name "WSearch" -Force

    Write-Host "Strict Windows Search Mode enabled successfully." -ForegroundColor Green
  }
  catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
  }
}

# Call the function to enable strict Windows search mode
Enable-StrictWindowsSearchMode

Write-Host "Script execution completed." -ForegroundColor Green