# Admin check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run as Administrator!" -ForegroundColor Red
  exit 1
}

$ws = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Wireshark*" }
if ($ws) {
  foreach ($app in $ws) {
    Write-Host "Uninstalling $($app.Name)..." -ForegroundColor Cyan
    $app.Uninstall() | Out-Null
    Write-Host "$($app.Name) removed." -ForegroundColor Green
  }
}
else {
  Write-Host "Wireshark not installed." -ForegroundColor Yellow
}
