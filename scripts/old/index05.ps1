# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if (-not $isAdmin) {
  Clear-Host
  Write-Host ""
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "                !!! NOT RUNNING AS ADMINISTRATOR !!!          " -ForegroundColor Red -BackgroundColor Black
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host ""
  Write-Host " Please restart this script with Administrator privileges." -ForegroundColor Pink
  Write-Host ""
  Pause
  exit
}
else {
  Write-Host "Running as Administrator." -ForegroundColor Green
}

# Ensure LocalAccounts module is available
if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.LocalAccounts)) {
  Write-Host "LocalAccounts module not found. Attempting to install" -ForegroundColor Yellow
    
  try {
    Install-WindowsFeature RSAT:ActiveDirectory-Domain-Services -ErrorAction Stop
    Import-Module Microsoft.PowerShell.LocalAccounts
    Write-Host "Module installed successfully." -ForegroundColor Green
  }
  catch {
    Write-Host "Failed to install LocalAccounts module. Falling back to 'net user'." -ForegroundColor Red
  }
}
else {
  Write-Host "LocalAccounts module found, importing." -ForegroundColor Cyan
  Import-Module Microsoft.PowerShell.LocalAccounts
  Write-Host "LocalAccounts module imported successfully." -ForegroundColor Green
}



# Allowed users list 
#add the user in the read me to allowedUsers 
$allowedUsers = @("Administrator", "Guest", "ServiceAccount", "Guest", "WDAGUtilityAccount")

# Get all local users on Windows
$localUsers = Get-LocalUser | Select-Object -ExpandProperty Name

# Compare lists
$unapprovedUsers = $localUsers | Where-Object { $_ -notin $allowedUsers }

# Make Sure that you double check the read me to verfiy that all of the user that you are going to delete are not aproved.
if ($unapprovedUsers.Count -eq 0) {
  Write-Host " All users match the approved list"
}
else {
  Write-Host "`n Unapproved Users Found:`n"
  $unapprovedUsers | ForEach-Object { Write-Host " - $_" }

  foreach ($user in $unapprovedUsers) {
    Write-Host "`n=============================="
    Write-Host "!!!   CHECK THE README   !!!"
    Write-Host "=============================="
    $response = Read-Host "Do you want to DELETE user '$user'? (Y/N)"
        
    if ($response -eq "Y") {
      try {
        Remove-LocalUser -Name $user -ErrorAction Stop
        Write-Host " User '$user' deleted."
      }
      catch {
        Write-Host " Failed to delete '$user': $_"
      }
    }
    else {
      Write-Host " Skipped '$user'."
    }
  }
}