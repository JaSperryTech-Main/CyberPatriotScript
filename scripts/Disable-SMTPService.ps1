# Admin check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run as Administrator!" -ForegroundColor Red
  exit 1
}

$serviceName = "SMTPSVC"  # Standard SMTP service name

try {
  $svc = Get-Service -Name $serviceName -ErrorAction Stop
  Write-Host "Stopping and disabling service: $serviceName" -ForegroundColor Cyan
  Stop-Service -Name $serviceName -Force
  Set-Service -Name $serviceName -StartupType Disabled
  Write-Host "SMTP service disabled successfully" -ForegroundColor Green
}
catch {
  Write-Host "SMTP service not found or could not be modified: $_" -ForegroundColor Yellow
}
