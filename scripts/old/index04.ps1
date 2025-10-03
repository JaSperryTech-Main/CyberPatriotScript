# This is the second Windows 10 script. This is to be run at the end.
# YOU NEED TO RUN IN ADMIN

# Check if the script is run as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "This script must be run as administrator." -ForegroundColor Red
  exit
}

Write-Host "Starting script"

# Function to get Microsoft Defender exclusions and output to a file
function Get-MsDefenderExclusions {
  # Define output file path (ensure it's a valid path)
  $outputFile = "C:\Users\$env:USERNAME\Desktop\ms_defender_exclusions.txt"

  # Get current date and time
  $currentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
  # Start writing to the output file
  try {
    # Write date to file
    Add-Content -Path $outputFile -Value "MS Defender Exclusions - $currentDate"
    Add-Content -Path $outputFile -Value "----------------------------------------"
        
    # Get the exclusions from Defender
    $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess, ExclusionExtension, ExclusionPath

    # Check if exclusions exist
    if ($exclusions) {
      # Write exclusions to file
      Add-Content -Path $outputFile -Value "Exclusions List:"
      $exclusions | ForEach-Object {
        Add-Content -Path $outputFile -Value $_
      }
    }
    else {
      Add-Content -Path $outputFile -Value "No exclusions found."
    }

    Write-Host "Exclusions saved to $outputFile"
  }
  catch {
    Write-Host "Error occurred: $_" -ForegroundColor Red
  }
}

# Call the function to get exclusions
Get-MsDefenderExclusions

# Function to check and install required module
function Install-ModuleIfNotExists {
  param (
    [string]$ModuleName
  )

  if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
    Write-Host "Module '$ModuleName' not found. Installing" -ForegroundColor Yellow
    try {
      Install-Module -Name $ModuleName -Force -Scope CurrentUser
      Write-Host "Module '$ModuleName' installed successfully." -ForegroundColor Green
    }
    catch {
      Write-Host "Failed to install module '$ModuleName': $_" -ForegroundColor Red
      exit
    }
  }
  else {
    Write-Host "Module '$ModuleName' is already installed." -ForegroundColor Green
  }
}

# Check for and install required modules (if needed)
Install-ModuleIfNotExists -ModuleName "PSWindowsUpdate"

# Run Windows Update
Write-Host "Starting Windows Update" -ForegroundColor Cyan
try {
  Import-Module PSWindowsUpdate
  Get-WindowsUpdate -AcceptAll -Install -AutoReboot
  Write-Host "Windows Update completed successfully." -ForegroundColor Green
}
catch {
  Write-Host "Failed to run Windows Update: $_" -ForegroundColor Red
  exit
}

# Run Microsoft Defender Full Scan
Write-Host "Starting Microsoft Defender Full Scan" -ForegroundColor Cyan
try {
  Start-MpScan -ScanType FullScan
  Write-Host "Microsoft Defender Full Scan started successfully." -ForegroundColor Green
}
catch {
  Write-Host "Failed to start Microsoft Defender scan: $_" -ForegroundColor Red
  exit
}

# List of services to disable
$insecureServices = @(
  "RemoteRegistry",  # Allows remote access to the registry
  "Telnet",          # Unsecured remote command-line
  "TrkWks",          # Distributed Link Tracking Client
  "W3SVC",           # Web Publishing Service
  "SMB1Protocol",    # SMBv1 Protocol, vulnerable to attacks
  "TermService",     # Remote Desktop Services
  "WinRM",           # Windows Remote Management
  "Winmgmt",         # Windows Management Instrumentation (WMI)
  "LanmanServer",    # SMB/Server Service
  "FTPSVC",          # File Transfer Protocol (FTP)
  "POP3SVC",         # Post Office Protocol (POPv1/v2)
  "FTP",             # FTP Service (alternative name)
  "RpcSs",           # Remote Procedure Call (RPC)
  "SNMP",            # Simple Network Management Protocol (SNMP)
  "HTTP",            # HTTP service (Commonly used in various attacks, such as web-based RCE)
  "RasMan",          # Remote Access Connection Manager (Exploited in certain remote access attacks)
  "ADWS",            # Active Directory Web Services
  "DNS",             # DNS Server
  "DHCPServer",      # DHCP Server
  "Fax",             # Fax Service
  "VMMS",            # Hyper-V Virtual Machine Management
  "WDS",             # Windows Deployment Services
  "IISAdmin",        # IIS Admin Service
  "DFS",             # Distributed File System
  "NPS",             # Network Policy Server
  "WSS",             # Windows Server Backup
  "WSUS"             # Windows Server Update Services
)

# Loop through each service and disable it
foreach ($service in $insecureServices) {
  try {
    # Get the current status of the service
    $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue

    if ($serviceStatus -and $serviceStatus.Status -eq "Running") {
      Write-Host "Stopping and disabling $service"
      Stop-Service -Name $service -Force
    }

    # Set the service to Disabled startup type
    Set-Service -Name $service -StartupType Disabled
    Write-Host "$service has been disabled."
  }
  catch {
    Write-Host "Service $service could not be found or modified. It may not be installed on this system." -ForegroundColor Yellow
  }
}

Write-Host "All specified services have been processed." -ForegroundColor Green