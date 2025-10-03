# Windows Server 2019/2022 Password Policy Configuration Script
# This script must be run with Administrator privileges

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

Write-Host "Configuring Domain Password Policy..." -ForegroundColor Cyan

try {
    # Set password policies using secedit
    $secEditConfig = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
PasswordHistorySize = 24
MaximumPasswordAge = 60
MinimumPasswordAge = 1
MinimumPasswordLength = 10
PasswordComplexity = 1
ClearTextPassword = 0
"@

    # Create temporary configuration file
    $tempFile = [System.IO.Path]::GetTempFileName()
    $secEditConfig | Out-File $tempFile -Encoding unicode

    # Apply the security policy
    Write-Host "Applying password policy settings..." -ForegroundColor Yellow
    secedit /configure /db secedit.sdb /cfg $tempFile /areas SECURITYPOLICY

    # Clean up temporary file
    Remove-Item $tempFile -Force

    Write-Host "`nPassword Policy configured successfully!" -ForegroundColor Green
    Write-Host "`nApplied Settings:" -ForegroundColor Cyan
    Write-Host "  - Enforce password history: 24 passwords" -ForegroundColor White
    Write-Host "  - Maximum password age: 60 days" -ForegroundColor White
    Write-Host "  - Minimum password age: 1 day" -ForegroundColor White
    Write-Host "  - Minimum password length: 10 characters" -ForegroundColor White
    Write-Host "  - Password complexity: Enabled" -ForegroundColor White
    Write-Host "  - Store password using reversible encryption: Disabled" -ForegroundColor White
    
    Write-Host "`nNote: Run 'gpupdate /force' to apply changes immediately." -ForegroundColor Yellow

}
catch {
    Write-Host "ERROR: Failed to configure password policy" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}