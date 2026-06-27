#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ServerUrl,

    [Parameter(Mandatory)]
    [string]$Token,

    [string]$EnvironmentName = "",

    [ValidateRange(5, 300)]
    [int]$PollSeconds = 10,

    [switch]$EnableAuditing,

    [switch]$AllowInsecureHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (
    -not $AllowInsecureHttp -and
    -not $ServerUrl.StartsWith(
        "https://",
        [System.StringComparison]::OrdinalIgnoreCase
    )
) {
    throw "HTTPS is required. Use -AllowInsecureHttp only for an isolated lab."
}

$installRoot = "$env:ProgramData\CertShield\MonitoringAgent"
$scriptPath = Join-Path $installRoot "CertShieldMonitoringAgent.ps1"
$configPath = Join-Path $installRoot "config.json"
$taskName = "CertShield Monitoring Agent"

New-Item -ItemType Directory -Path $installRoot -Force |
    Out-Null

$sourceScript = Join-Path $PSScriptRoot "CertShieldMonitoringAgent.ps1"

if (-not (Test-Path -LiteralPath $sourceScript)) {
    throw "Agent script was not found beside the installer."
}

Copy-Item -LiteralPath $sourceScript -Destination $scriptPath -Force

$config = [ordered]@{
    server_url                = $ServerUrl.TrimEnd("/")
    token                     = $Token
    poll_seconds              = $PollSeconds
    environment_name_override = $EnvironmentName.Trim()
}

$config |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $configPath -Encoding UTF8

$acl = Get-Acl -LiteralPath $configPath
$acl.SetAccessRuleProtection($true, $false)

foreach ($identity in @(
    "NT AUTHORITY\SYSTEM",
    "BUILTIN\Administrators"
)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity,
        "FullControl",
        "Allow"
    )
    $acl.AddAccessRule($rule)
}

Set-Acl -LiteralPath $configPath -AclObject $acl

$arguments = @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$scriptPath`"",
    "-ConfigPath", "`"$configPath`""
) -join " "

$action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument $arguments

$trigger = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Force |
    Out-Null

if ($EnableAuditing) {
    & auditpol.exe /set /subcategory:"Certification Services" /success:enable /failure:enable |
        Out-Null

    & certutil.exe -setreg CA\AuditFilter 127 |
        Out-Null

    Restart-Service CertSvc -Force
}

Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3

& PowerShell.exe `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $scriptPath `
    -ConfigPath $configPath `
    -RunOnce

Write-Host ""
Write-Host "CertShield Monitoring Agent installed." -ForegroundColor Green
Write-Host "Task: $taskName"
Write-Host "Config: $configPath"
Write-Host "Environment identity: detected automatically"
if ($EnvironmentName) {
    Write-Host "Environment override: $EnvironmentName"
}
Write-Host ""
Write-Host "Open CertShield > PKI Monitoring to confirm the heartbeat."
