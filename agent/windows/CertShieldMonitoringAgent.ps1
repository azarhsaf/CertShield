#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfigPath = "$env:ProgramData\CertShield\MonitoringAgent\config.json",
    [switch]$RunOnce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-AgentConfig {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "CertShield monitoring config was not found: $ConfigPath"
    }

    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

    foreach ($required in @("server_url", "token")) {
        if (-not $config.$required) {
            throw "Missing required config value: $required"
        }
    }

    return $config
}

function Invoke-AgentApi {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("GET", "POST")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Path,

        [object]$Body
    )

    $uri = ($script:Config.server_url.TrimEnd("/") + $Path)

    $headers = @{
        Authorization = "Bearer $($script:Config.token)"
        Accept        = "application/json"
    }

    $parameters = @{
        Uri         = $uri
        Method      = $Method
        Headers     = $headers
        TimeoutSec  = 30
        ErrorAction = "Stop"
    }

    if ($Method -eq "POST") {
        $parameters.ContentType = "application/json"
        $parameters.Body = ($Body | ConvertTo-Json -Depth 12 -Compress)
    }

    return Invoke-RestMethod @parameters
}

function Get-ActiveCaName {
    $configurationRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"

    if (-not (Test-Path -LiteralPath $configurationRoot)) {
        return ""
    }

    try {
        $active = (Get-ItemProperty -LiteralPath $configurationRoot -Name Active -ErrorAction Stop).Active
        if ($active) {
            return [string]$active
        }
    }
    catch {
        # Older systems may not expose the Active value.
    }

    $first = Get-ChildItem -LiteralPath $configurationRoot -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -notin @("Configuration") } |
        Select-Object -First 1

    if ($first) {
        return [string]$first.PSChildName
    }

    return ""
}

function Get-CertificationAuditPolicy {
    $result = [ordered]@{
        policy_enabled     = $false
        raw_setting        = ""
        gpo_managed        = $false
    }

    try {
        $csvText = & auditpol.exe /get /subcategory:"Certification Services" /r 2>&1
        $csvRows = $csvText | ConvertFrom-Csv
        $row = $csvRows | Select-Object -First 1

        if ($row) {
            $settingProperty = $row.PSObject.Properties |
                Where-Object {
                    $_.Name -match "Inclusion|Setting"
                } |
                Select-Object -First 1

            if ($settingProperty) {
                $setting = [string]$settingProperty.Value
                $result.raw_setting = $setting
                $result.policy_enabled = (
                    $setting -match "Success" -and
                    $setting -match "Failure"
                )
            }
        }

        if (-not $result.raw_setting) {
            $plain = (& auditpol.exe /get /subcategory:"Certification Services" 2>&1) -join "`n"
            $result.raw_setting = $plain
            $result.policy_enabled = (
                $plain -match "Success and Failure"
            )
        }
    }
    catch {
        $result.raw_setting = $_.Exception.Message
    }

    return $result
}

function Get-CaAuditFilter {
    param(
        [string]$CaName
    )

    if (-not $CaName) {
        return 0
    }

    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName"

    try {
        $value = (Get-ItemProperty -LiteralPath $path -Name AuditFilter -ErrorAction Stop).AuditFilter
        return [int]$value
    }
    catch {
        return 0
    }
}

function Test-SecurityLogAccess {
    try {
        $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-NamedServiceState {
    param(
        [string]$Name
    )

    try {
        return [string](Get-Service -Name $Name -ErrorAction Stop).Status
    }
    catch {
        return "NotInstalled"
    }
}

function Get-ResourceState {
    $cpu = $null
    $memory = $null
    $disk = $null

    try {
        $processors = Get-CimInstance Win32_Processor -ErrorAction Stop
        $cpu = [math]::Round(
            (
                $processors |
                Measure-Object -Property LoadPercentage -Average
            ).Average
        )
    }
    catch {}

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($os.TotalVisibleMemorySize -gt 0) {
            $used = $os.TotalVisibleMemorySize - $os.FreePhysicalMemory
            $memory = [math]::Round(
                ($used / $os.TotalVisibleMemorySize) * 100
            )
        }
    }
    catch {}

    try {
        $systemDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop
        if ($systemDrive.Size -gt 0) {
            $disk = [math]::Round(
                ($systemDrive.FreeSpace / $systemDrive.Size) * 100
            )
        }
    }
    catch {}

    return [ordered]@{
        cpu_percent       = $cpu
        memory_percent    = $memory
        disk_free_percent = $disk
    }
}

function Get-InteractiveSessions {
    $sessions = @()

    try {
        $lines = & quser.exe 2>$null

        foreach ($line in ($lines | Select-Object -Skip 1)) {
            $clean = ([string]$line).Trim()
            if (-not $clean) {
                continue
            }

            $parts = $clean -split "\s+"
            if ($parts.Count -lt 3) {
                continue
            }

            $sessions += [ordered]@{
                username = $parts[0].TrimStart(">")
                state    = $parts[-3]
                idle     = $parts[-2]
                logon    = $parts[-1]
                raw      = $clean
            }
        }
    }
    catch {}

    return @($sessions)
}

function Get-WebEnrollmentActivity {
    $activity = @()
    $root = "$env:SystemDrive\inetpub\logs\LogFiles"

    if (-not (Test-Path -LiteralPath $root)) {
        return @()
    }

    try {
        $latest = Get-ChildItem -LiteralPath $root -Recurse -Filter *.log -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1

        if (-not $latest) {
            return @()
        }

        $lines = Get-Content -LiteralPath $latest.FullName -Tail 250 -ErrorAction Stop |
            Where-Object {
                $_ -notmatch "^#" -and
                $_ -match "/certsrv"
            }

        foreach ($line in ($lines | Select-Object -Last 25)) {
            $activity += [ordered]@{
                username  = ""
                source_ip = ""
                raw       = [string]$line
            }
        }
    }
    catch {}

    return @($activity)
}


function Get-WindowsEnvironmentIdentity {
    param(
        [string]$CaName = ""
    )

    $computerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem `
        -ErrorAction Stop

    $partOfDomain = [bool]$computerSystem.PartOfDomain
    $domainName = ""
    $forestName = ""

    if ($partOfDomain) {
        try {
            $domainObject = (
                [System.DirectoryServices.ActiveDirectory.Domain]::
                    GetComputerDomain()
            )
            $domainName = [string]$domainObject.Name
        }
        catch {
            $domainName = [string]$computerSystem.Domain
        }

        try {
            $forestObject = (
                [System.DirectoryServices.ActiveDirectory.Forest]::
                    GetCurrentForest()
            )
            $forestName = [string]$forestObject.Name
        }
        catch {
            $forestName = $domainName
        }
    }

    $environmentName = ""

    if (
        $script:Config.PSObject.Properties.Name -contains
        "environment_name_override"
    ) {
        $environmentName = [string](
            $script:Config.environment_name_override
        )
    }

    if (-not $environmentName -and $domainName) {
        $environmentName = (
            $domainName.Split(".")[0]
        ).ToUpperInvariant()
    }

    if (-not $environmentName -and $forestName) {
        $environmentName = (
            $forestName.Split(".")[0]
        ).ToUpperInvariant()
    }

    if (-not $environmentName -and $CaName) {
        $environmentName = $CaName
    }

    if (-not $environmentName) {
        $environmentName = $env:COMPUTERNAME
    }

    return [ordered]@{
        environment_name = $environmentName
        domain_name      = $domainName
        forest_name      = $forestName
        collector_type   = "adcs"
        part_of_domain   = $partOfDomain
    }
}


function ConvertTo-AgentKeyPart {
    param(
        [string]$Value
    )

    $normalized = (
        [string]$Value
    ).Trim().ToLowerInvariant()

    $normalized = [regex]::Replace(
        $normalized,
        "[^a-z0-9._-]",
        "-"
    )

    $normalized = [regex]::Replace(
        $normalized,
        "-+",
        "-"
    ).Trim("-")

    if (-not $normalized) {
        return "unknown"
    }

    return $normalized
}


function Initialize-AgentIdentity {
    $caName = Get-ActiveCaName
    $identity = Get-WindowsEnvironmentIdentity `
        -CaName $caName

    $environmentIdentity = (
        [string]$identity.domain_name
    )

    if (-not $environmentIdentity) {
        $environmentIdentity = (
            [string]$identity.forest_name
        )
    }

    if (-not $environmentIdentity) {
        $environmentIdentity = (
            [string]$identity.environment_name
        )
    }

    $agentKey = "adcs:{0}:{1}" -f (
        ConvertTo-AgentKeyPart `
            -Value $environmentIdentity
    ), (
        ConvertTo-AgentKeyPart `
            -Value $env:COMPUTERNAME
    )

    $script:Config |
        Add-Member `
            -NotePropertyName agent_key `
            -NotePropertyValue $agentKey `
            -Force

    $script:Config |
        Add-Member `
            -NotePropertyName environment_name `
            -NotePropertyValue (
                [string]$identity.environment_name
            ) `
            -Force

    $script:Config |
        Add-Member `
            -NotePropertyName domain_name `
            -NotePropertyValue (
                [string]$identity.domain_name
            ) `
            -Force

    $script:Config |
        Add-Member `
            -NotePropertyName forest_name `
            -NotePropertyValue (
                [string]$identity.forest_name
            ) `
            -Force

    $script:Config |
        Add-Member `
            -NotePropertyName collector_type `
            -NotePropertyValue "adcs" `
            -Force
}



function Get-AgentState {
    $caName = Get-ActiveCaName
    $policy = Get-CertificationAuditPolicy
    $auditFilter = Get-CaAuditFilter -CaName $caName
    $securityAccess = Test-SecurityLogAccess

    $message = if (
        $policy.policy_enabled -and
        $auditFilter -eq 127 -and
        $securityAccess
    ) {
        "Certification Services auditing is ready."
    }
    else {
        "Certification Services auditing is not fully enabled."
    }

    return [ordered]@{
        collected_at = (Get-Date).ToUniversalTime().ToString("o")

        auditing = [ordered]@{
            policy_enabled     = [bool]$policy.policy_enabled
            raw_setting        = [string]$policy.raw_setting
            audit_filter       = [int]$auditFilter
            security_log_access = [bool]$securityAccess
            gpo_managed        = [bool]$policy.gpo_managed
            message            = $message
        }

        services = [ordered]@{
            certsvc = Get-NamedServiceState -Name "CertSvc"
            w3svc   = Get-NamedServiceState -Name "W3SVC"
        }

        resources = Get-ResourceState
        sessions = @(Get-InteractiveSessions)
        web_activity = @(Get-WebEnrollmentActivity)
    }
}

function Enable-CertificationServicesAuditing {
    $caName = Get-ActiveCaName

    if (-not $caName) {
        throw "No local AD CS Certification Authority configuration was found."
    }

    $before = Get-AgentState

    & auditpol.exe /set /subcategory:"Certification Services" /success:enable /failure:enable |
        Out-Null

    & certutil.exe -setreg CA\AuditFilter 127 |
        Out-Null

    $service = Get-Service -Name CertSvc -ErrorAction Stop
    Restart-Service -Name CertSvc -Force -ErrorAction Stop
    $service.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(45)
    )

    Start-Sleep -Seconds 3

    $after = Get-AgentState
    $ready = (
        $after.auditing.policy_enabled -and
        $after.auditing.audit_filter -eq 127 -and
        $after.auditing.security_log_access
    )

    return [ordered]@{
        success = [bool]$ready
        ca_name = $caName
        before  = $before.auditing
        after   = $after.auditing
        certsvc = $after.services.certsvc
        message = if ($ready) {
            "Certification Services auditing was enabled successfully."
        }
        else {
            "The settings were applied, but the final audit readiness check did not pass. Group Policy may be overriding the configuration."
        }
    }
}


function ConvertTo-CertShieldUtcString {
    param(
        [Parameter(Mandatory)]
        [datetime]$Value
    )

    return $Value.ToUniversalTime().ToString("o")
}


function Get-AgentRuntimeStatePath {
    $directory = Split-Path -Parent $ConfigPath

    return Join-Path `
        $directory `
        "runtime-state.json"
}


function Read-AgentRuntimeState {
    $path = Get-AgentRuntimeStatePath

    if (-not (Test-Path -LiteralPath $path)) {
        return [ordered]@{
            security_last_record_id = 0
        }
    }

    try {
        $state = Get-Content `
            -LiteralPath $path `
            -Raw |
            ConvertFrom-Json

        if (
            -not (
                $state.PSObject.Properties.Name -contains
                "security_last_record_id"
            )
        ) {
            $state |
                Add-Member `
                    -NotePropertyName security_last_record_id `
                    -NotePropertyValue 0 `
                    -Force
        }

        return $state
    }
    catch {
        return [ordered]@{
            security_last_record_id = 0
        }
    }
}


function Write-AgentRuntimeState {
    param(
        [Parameter(Mandatory)]
        [object]$State
    )

    $path = Get-AgentRuntimeStatePath
    $directory = Split-Path -Parent $path

    New-Item `
        -ItemType Directory `
        -Path $directory `
        -Force |
        Out-Null

    $State |
        ConvertTo-Json -Depth 10 |
        Set-Content `
            -LiteralPath $path `
            -Encoding UTF8
}


function Get-CertShieldServiceState {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        $service = Get-Service `
            -Name $Name `
            -ErrorAction Stop

        return [string]$service.Status
    }
    catch {
        return ""
    }
}


function Get-CertShieldMetrics {
    $cpuPercent = $null
    $memoryPercent = $null
    $diskFreePercent = $null

    try {
        $processors = @(
            Get-CimInstance `
                -ClassName Win32_Processor `
                -ErrorAction Stop
        )

        $loads = @(
            $processors |
                Where-Object {
                    $null -ne $_.LoadPercentage
                } |
                ForEach-Object {
                    [double]$_.LoadPercentage
                }
        )

        if ($loads.Count -gt 0) {
            $cpuPercent = [math]::Round(
                (
                    $loads |
                    Measure-Object -Average
                ).Average,
                2
            )
        }
    }
    catch {
        $cpuPercent = $null
    }

    try {
        $os = Get-CimInstance `
            -ClassName Win32_OperatingSystem `
            -ErrorAction Stop

        if (
            $os.TotalVisibleMemorySize -and
            $os.TotalVisibleMemorySize -gt 0
        ) {
            $used = (
                [double]$os.TotalVisibleMemorySize -
                [double]$os.FreePhysicalMemory
            )

            $memoryPercent = [math]::Round(
                (
                    $used /
                    [double]$os.TotalVisibleMemorySize
                ) * 100,
                2
            )
        }
    }
    catch {
        $memoryPercent = $null
    }

    try {
        $disks = @(
            Get-CimInstance `
                -ClassName Win32_LogicalDisk `
                -Filter "DriveType=3" `
                -ErrorAction Stop |
            Where-Object {
                $_.Size -and $_.Size -gt 0
            }
        )

        $freeValues = @(
            $disks |
                ForEach-Object {
                    [math]::Round(
                        (
                            [double]$_.FreeSpace /
                            [double]$_.Size
                        ) * 100,
                        2
                    )
                }
        )

        if ($freeValues.Count -gt 0) {
            $diskFreePercent = (
                $freeValues |
                Measure-Object -Minimum
            ).Minimum
        }
    }
    catch {
        $diskFreePercent = $null
    }

    return [ordered]@{
        agent_key         = [string]$script:Config.agent_key
        occurred_at       = ConvertTo-CertShieldUtcString `
            -Value (Get-Date)
        cpu_percent       = $cpuPercent
        memory_percent    = $memoryPercent
        disk_free_percent = $diskFreePercent
        certsvc_state     = Get-CertShieldServiceState `
            -Name "CertSvc"
        iis_state         = Get-CertShieldServiceState `
            -Name "W3SVC"
        details           = [ordered]@{
            hostname = $env:COMPUTERNAME
            ca_name  = Get-ActiveCaName
            domain   = [string]$script:Config.domain_name
            forest   = [string]$script:Config.forest_name
        }
    }
}


function Send-MonitoringMetrics {
    $payload = Get-CertShieldMetrics

    return Invoke-AgentApi `
        -Method POST `
        -Path "/api/v1/monitoring/agents/metrics" `
        -Body $payload
}


function New-CertShieldAuditEventItem {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $message = ""

    try {
        $message = [string]$Event.FormatDescription()
    }
    catch {
        $message = ""
    }

    if (-not $message) {
        $message = "Certification Services security audit event."
    }

    $summary = $message

    if ($summary.Length -gt 600) {
        $summary = $summary.Substring(0, 600)
    }

    $severity = "info"

    if ($Event.LevelDisplayName -match "Error|Critical") {
        $severity = "critical"
    }
    elseif ($Event.LevelDisplayName -match "Warning") {
        $severity = "warning"
    }

    return [ordered]@{
        event_key   = "windows-security:{0}:{1}" -f (
            $Event.MachineName
        ), (
            $Event.RecordId
        )
        category    = "adcs_audit"
        event_type  = "windows_event_{0}" -f $Event.Id
        severity    = $severity
        title       = "AD CS audit event {0}" -f $Event.Id
        summary     = $summary
        actor       = ""
        source_ip   = ""
        occurred_at = ConvertTo-CertShieldUtcString `
            -Value $Event.TimeCreated
        details     = [ordered]@{
            record_id          = [int64]$Event.RecordId
            event_id           = [int]$Event.Id
            provider_name      = [string]$Event.ProviderName
            log_name           = [string]$Event.LogName
            machine_name       = [string]$Event.MachineName
            level_display_name = [string]$Event.LevelDisplayName
            message            = $message
        }
    }
}


function Get-CertShieldAuditEvents {
    $runtimeState = Read-AgentRuntimeState
    $lastRecordId = 0

    try {
        $lastRecordId = [int64]$runtimeState.security_last_record_id
    }
    catch {
        $lastRecordId = 0
    }

    $eventIds = @(
        4880, 4881, 4882, 4883, 4884,
        4885, 4886, 4887, 4888, 4889,
        4890, 4891, 4892, 4893, 4894,
        4895, 4896, 4897, 4898, 4899
    )

    $events = @()

    try {
        $filter = @{
            LogName = "Security"
            Id      = $eventIds
        }

        $events = @(
            Get-WinEvent `
                -FilterHashtable $filter `
                -MaxEvents 100 `
                -ErrorAction Stop |
            Where-Object {
                [int64]$_.RecordId -gt $lastRecordId
            } |
            Sort-Object RecordId
        )
    }
    catch {
        return @()
    }

    if ($events.Count -eq 0) {
        return @()
    }

    $items = @(
        $events |
            ForEach-Object {
                New-CertShieldAuditEventItem `
                    -Event $_
            }
    )

    $maxRecordId = (
        $events |
        Measure-Object -Property RecordId -Maximum
    ).Maximum

    if ($maxRecordId) {
        $runtimeState.security_last_record_id = [int64]$maxRecordId
        Write-AgentRuntimeState `
            -State $runtimeState
    }

    return $items
}


function Send-MonitoringEvents {
    $events = @(
        Get-CertShieldAuditEvents
    )

    if ($events.Count -eq 0) {
        return
    }

    $payload = [ordered]@{
        agent_key = [string]$script:Config.agent_key
        events    = $events
    }

    return Invoke-AgentApi `
        -Method POST `
        -Path "/api/v1/monitoring/agents/events" `
        -Body $payload
}

function Send-Heartbeat {
    $caName = Get-ActiveCaName
    $state = Get-AgentState

    $payload = [ordered]@{
        agent_key        = [string]$script:Config.agent_key
        hostname         = $env:COMPUTERNAME
        ca_name          = $caName
        agent_version    = "0.3.0"
        environment_name = [string]$script:Config.environment_name
        domain_name      = [string]$script:Config.domain_name
        forest_name      = [string]$script:Config.forest_name
        collector_type   = [string]$script:Config.collector_type
        state            = $state
    }

    return Invoke-AgentApi -Method POST -Path "/api/v1/monitoring/agent/heartbeat" -Body $payload
}

function Invoke-PendingCommand {
    $agentKey = [uri]::EscapeDataString(
        [string]$script:Config.agent_key
    )

    $command = Invoke-AgentApi -Method GET -Path "/api/v1/monitoring/agent/commands?agent_key=$agentKey"

    $hasCommandId = (
        $command -and
        (
            $command.PSObject.Properties.Name -contains "id"
        ) -and
        $command.id
    )

    if (-not $hasCommandId) {
        return
    }

    $success = $false
    $result = [ordered]@{}

    try {
        switch ([string]$command.command_type) {
            "enable_ca_auditing" {
                $result = Enable-CertificationServicesAuditing
                $success = [bool]$result.success
            }

            default {
                throw "Unsupported monitoring command: $($command.command_type)"
            }
        }
    }
    catch {
        $result = [ordered]@{
            success = $false
            message = $_.Exception.Message
        }
    }

    $completion = [ordered]@{
        agent_key = [string]$script:Config.agent_key
        success   = [bool]$success
        result    = $result
    }

    Invoke-AgentApi `
        -Method POST `
        -Path "/api/v1/monitoring/agent/commands/$($command.id)/complete" `
        -Body $completion |
        Out-Null
}

$script:Config = Read-AgentConfig
Initialize-AgentIdentity

do {
    try {
        Send-Heartbeat | Out-Null
        Send-MonitoringMetrics | Out-Null
        Send-MonitoringEvents | Out-Null
        Invoke-PendingCommand
    }
    catch {
        $logDirectory = Split-Path -Parent $ConfigPath
        New-Item -ItemType Directory -Path $logDirectory -Force |
            Out-Null

        $message = "{0} {1}" -f (
            (Get-Date).ToUniversalTime().ToString("o")
        ), $_.Exception.Message

        Add-Content `
            -LiteralPath (Join-Path $logDirectory "agent-error.log") `
            -Value $message
    }

    if ($RunOnce) {
        break
    }

    $interval = [int](
        $script:Config.poll_seconds |
        ForEach-Object {
            if ($_ -ge 5) { $_ } else { 10 }
        }
    )

    Start-Sleep -Seconds $interval
}
while ($true)
