$ErrorActionPreference = "Stop"

$TaskName = "CertShield PKI Monitoring Agent"
$InstallRoot = (
    "C:\ProgramData\CertShield\MonitoringAgent"
)

Stop-ScheduledTask `
    -TaskName $TaskName `
    -ErrorAction SilentlyContinue

Unregister-ScheduledTask `
    -TaskName $TaskName `
    -Confirm:$false `
    -ErrorAction SilentlyContinue

Remove-Item `
    -Path $InstallRoot `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host "CertShield Monitoring Agent removed."
