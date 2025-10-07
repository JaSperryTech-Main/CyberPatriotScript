# Admin check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run as Administrator!" -ForegroundColor Red
  exit 1
}

$path = "$env:PUBLIC\Downloads\brutus-aet2-darknet.zip"

if (Test-Path $path) {
  Remove-Item -Path $path -Force
  Write-Host "Brutus archive removed: $path" -ForegroundColor Green
}
else {
  Write-Host "Brutus archive not found." -ForegroundColor Yellow
}
