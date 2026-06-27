[CmdletBinding()]
param(
    [string]$ConfigPath = (
        "C:\ProgramData\CertShield\MonitoringAgent\agent.json"
    )
)

$ErrorActionPreference = "Stop"

$InstallRoot = Split-Path -Parent $ConfigPath
$LogPath = Join-Path $InstallRoot "agent.log"
$StatePath = Join-Path $InstallRoot "state.json"

function Write-AgentLog {
    param([string]$Message)

    $line = "{0:o} {1}" -f (Get-Date), $Message

    Add-Content `
        -Path $LogPath `
        -Value $line `
        -Encoding UTF8
}

if (-not (Test-Path $ConfigPath)) {
    throw "Configuration not found: $ConfigPath"
}

$Config = Get-Content `
    -Path $ConfigPath `
    -Raw |
    ConvertFrom-Json

$Headers = @{
    Authorization = "Bearer $($Config.token)"
}

function Invoke-AgentApi {
    param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Path,

        $Body = $null
    )

    $uri = (
        $Config.server_url.TrimEnd("/") + $Path
    )

    $parameters = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $Headers
        ContentType = "application/json"
        TimeoutSec  = 20
    }

    if ($null -ne $Body) {
        $parameters.Body = (
            $Body |
            ConvertTo-Json -Depth 12 -Compress
        )
    }

    Invoke-RestMethod @parameters
}

function Get-CaName {
    try {
        $configurationPath = (
            "HKLM:\SYSTEM\CurrentControlSet\Services\" +
            "CertSvc\Configuration"
        )

        return (
            Get-ItemProperty `
                -Path $configurationPath `
                -Name Active `
                -ErrorAction Stop
        ).Active
    }
    catch {
        return ""
    }
}

function Get-CaAuditStatus {
    $policyText = (
        & auditpol.exe `
            /get `
            /subcategory:"Certification Services" `
            2>&1 |
        Out-String
    )

    $successEnabled = (
        $policyText -match "Success"
        -and
        $policyText -notmatch "No Auditing"
    )

    $failureEnabled = (
        $policyText -match "Failure"
        -and
        $policyText -notmatch "No Auditing"
    )

    $auditFilter = $null

    try {
        $filterText = (
            & certutil.exe `
                -getreg `
                CA\AuditFilter `
                2>&1 |
            Out-String
        )

        if (
            $filterText -match
            "REG_DWORD\s*=\s*([0-9a-fA-F]+)"
        ) {
            $auditFilter = (
                [Convert]::ToInt32(
                    $Matches[1],
                    16
                )
            )
        }
    }
    catch {
        $auditFilter = $null
    }

    [pscustomobject]@{
        success_enabled = $successEnabled
        failure_enabled = $failureEnabled
        audit_filter    = $auditFilter
        audit_ready     = (
            $successEnabled
            -and
            $failureEnabled
            -and
            $auditFilter -eq 127
        )
        raw_policy      = $policyText.Trim()
    }
}

function Enable-CaAuditing {
    $auditPolicyOutput = (
        & auditpol.exe `
            /set `
            /subcategory:"Certification Services" `
            /success:enable `
            /failure:enable `
            2>&1 |
        Out-String
    )

    if ($LASTEXITCODE -ne 0) {
        throw (
            "auditpol failed: " +
            $auditPolicyOutput
        )
    }

    $certutilOutput = (
        & certutil.exe `
            -setreg `
            CA\AuditFilter `
            127 `
            2>&1 |
        Out-String
    )

    if ($LASTEXITCODE -ne 0) {
        throw (
            "certutil failed: " +
            $certutilOutput
        )
    }

    Restart-Service `
        -Name CertSvc `
        -Force `
        -ErrorAction Stop

    Start-Sleep -Seconds 4

    Get-CaAuditStatus
}

function Get-ServiceState {
    param([string]$Name)

    try {
        return (
            Get-Service `
                -Name $Name `
                -ErrorAction Stop
        ).Status.ToString().ToLowerInvariant()
    }
    catch {
        return "not installed"
    }
}

function Get-ActiveSessionCount {
    try {
        $rows = @(
            & quser.exe 2>$null |
            Select-Object -Skip 1 |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }
        )

        return $rows.Count
    }
    catch {
        return $null
    }
}

function Get-WebEnrollmentUserCount {
    $root = (
        "$env:SystemDrive\inetpub\logs\LogFiles"
    )

    if (-not (Test-Path $root)) {
        return $null
    }

    $file = (
        Get-ChildItem `
            -Path $root `
            -Filter *.log `
            -Recurse `
            -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    )

    if (-not $file) {
        return $null
    }

    $lines = @(
        Get-Content `
            -Path $file.FullName `
            -Tail 1500 `
            -ErrorAction SilentlyContinue
    )

    $fieldLine = (
        $lines |
        Where-Object {
            $_ -like "#Fields:*"
        } |
        Select-Object -Last 1
    )

    if (-not $fieldLine) {
        return $null
    }

    $fields = (
        $fieldLine.Substring(8).Trim() -split "\s+"
    )

    $dateIndex = [Array]::IndexOf(
        $fields,
        "date"
    )
    $timeIndex = [Array]::IndexOf(
        $fields,
        "time"
    )
    $uriIndex = [Array]::IndexOf(
        $fields,
        "cs-uri-stem"
    )
    $userIndex = [Array]::IndexOf(
        $fields,
        "cs-username"
    )

    if (
        $dateIndex -lt 0
        -or
        $timeIndex -lt 0
        -or
        $uriIndex -lt 0
        -or
        $userIndex -lt 0
    ) {
        return $null
    }

    $cutoff = (
        (Get-Date).ToUniversalTime().AddMinutes(-10)
    )

    $users = (
        [System.Collections.Generic.HashSet[string]]::new()
    )

    foreach ($line in $lines) {
        if (
            [string]::IsNullOrWhiteSpace($line)
            -or
            $line.StartsWith("#")
        ) {
            continue
        }

        $parts = $line -split "\s+"

        if ($parts.Count -le $userIndex) {
            continue
        }

        $uri = $parts[$uriIndex]
        $username = $parts[$userIndex]

        if (
            -not $uri.StartsWith(
                "/certsrv",
                [StringComparison]::OrdinalIgnoreCase
            )
            -or
            $username -eq "-"
        ) {
            continue
        }

        try {
            $timestamp = [datetime]::ParseExact(
                (
                    $parts[$dateIndex] +
                    " " +
                    $parts[$timeIndex]
                ),
                "yyyy-MM-dd HH:mm:ss",
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal
            )

            if ($timestamp -ge $cutoff) {
                [void]$users.Add($username)
            }
        }
        catch {
            continue
        }
    }

    return $users.Count
}

function Get-ServerMetrics {
    $cpu = $null
    $memory = $null
    $diskFree = $null

    try {
        $cpu = [math]::Round(
            (
                Get-Counter `
                    '\Processor(_Total)\% Processor Time'
            ).CounterSamples[0].CookedValue,
            2
        )
    }
    catch {}

    try {
        $os = Get-CimInstance Win32_OperatingSystem

        $memory = [math]::Round(
            (
                (
                    $os.TotalVisibleMemorySize -
                    $os.FreePhysicalMemory
                )
                /
                $os.TotalVisibleMemorySize
            ) * 100,
            2
        )
    }
    catch {}

    try {
        $disk = Get-CimInstance `
            Win32_LogicalDisk `
            -Filter "DeviceID='C:'"

        $diskFree = [math]::Round(
            ($disk.FreeSpace / $disk.Size) * 100,
            2
        )
    }
    catch {}

    [pscustomobject]@{
        agent_key        = $Config.agent_key
        occurred_at      = (
            (Get-Date).ToUniversalTime().ToString("o")
        )
        cpu_percent      = $cpu
        memory_percent   = $memory
        disk_free_percent = $diskFree
        certsvc_state    = Get-ServiceState "CertSvc"
        iis_state        = Get-ServiceState "W3SVC"
        details          = @{
            computer_name = $env:COMPUTERNAME
        }
    }
}

function Get-EventActor {
    param([string]$Message)

    $patterns = @(
        "(?im)^Requester:\s*(.+)$",
        "(?im)^Requester Name:\s*(.+)$",
        "(?im)^Account Name:\s*(.+)$",
        "(?im)^User:\s*(.+)$"
    )

    foreach ($pattern in $patterns) {
        if ($Message -match $pattern) {
            return $Matches[1].Trim()
        }
    }

    return ""
}

function Get-EventSourceIp {
    param([string]$Message)

    if (
        $Message -match
        "(?im)^Source Network Address:\s*(.+)$"
    ) {
        return $Matches[1].Trim()
    }

    return ""
}

function Get-EventTemplate {
    param([string]$Message)

    if (
        $Message -match
        "(?im)^Certificate Template:\s*(.+)$"
    ) {
        return $Matches[1].Trim()
    }

    return ""
}

function Convert-MonitoringEvent {
    param(
        $Event,
        [string]$Category
    )

    $eventType = "event"
    $severity = "info"
    $title = "PKI activity recorded"

    switch ($Event.Id) {
        4886 {
            $eventType = "certificate_received"
            $title = "Certificate request received"
        }
        4887 {
            $eventType = "certificate_issued"
            $severity = "success"
            $title = "Certificate issued"
        }
        4888 {
            $eventType = "certificate_denied"
            $severity = "warning"
            $title = "Certificate request denied"
        }
        4889 {
            $eventType = "certificate_pending"
            $severity = "warning"
            $title = "Certificate request pending approval"
        }
        21 {
            $eventType = "admin_logon"
            $title = "Administrator session connected"
        }
        23 {
            $eventType = "admin_logoff"
            $title = "Administrator session ended"
        }
        24 {
            $eventType = "admin_disconnect"
            $severity = "warning"
            $title = "Administrator session disconnected"
        }
        25 {
            $eventType = "admin_reconnect"
            $title = "Administrator session reconnected"
        }
    }

    $message = [string]$Event.Message
    $template = Get-EventTemplate $message
    $actor = Get-EventActor $message
    $sourceIp = Get-EventSourceIp $message

    $summary = (
        $message `
            -replace "\r?\n", " " `
            -replace "\s+", " "
    ).Trim()

    if ($summary.Length -gt 1000) {
        $summary = $summary.Substring(0, 1000)
    }

    [pscustomobject]@{
        event_key = (
            "{0}|{1}|{2}" -f
            $env:COMPUTERNAME,
            $Event.LogName,
            $Event.RecordId
        )
        category = $Category
        event_type = $eventType
        severity = $severity
        title = $title
        summary = $summary
        actor = $actor
        source_ip = $sourceIp
        occurred_at = (
            $Event.TimeCreated
                .ToUniversalTime()
                .ToString("o")
        )
        details = @{
            event_id  = $Event.Id
            record_id = $Event.RecordId
            log_name  = $Event.LogName
            template  = $template
            computer  = $Event.MachineName
        }
    }
}

function Get-NewLogEvents {
    param(
        [string]$LogName,
        [int[]]$Ids,
        [long]$LastRecordId
    )

    try {
        @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName   = $LogName
                    Id        = $Ids
                    StartTime = (
                        Get-Date
                    ).AddMinutes(-20)
                } `
                -ErrorAction Stop |
            Where-Object {
                $_.RecordId -gt $LastRecordId
            } |
            Sort-Object RecordId
        )
    }
    catch {
        @()
    }
}

if (Test-Path $StatePath) {
    try {
        $State = Get-Content `
            -Path $StatePath `
            -Raw |
            ConvertFrom-Json
    }
    catch {
        $State = $null
    }
}

if (-not $State) {
    $State = [pscustomobject]@{
        security_record_id = 0
        rdp_record_id      = 0
    }
}

$lastMetricSent = [datetime]::MinValue

Write-AgentLog (
    "CertShield Monitoring Agent starting"
)

while ($true) {
    try {
        $audit = Get-CaAuditStatus
        $activeSessions = Get-ActiveSessionCount
        $webUsers = Get-WebEnrollmentUserCount

        $heartbeat = @{
            agent_key = $Config.agent_key
            environment_id = (
                [int]$Config.environment_id
            )
            hostname = $env:COMPUTERNAME
            ca_name = Get-CaName
            version = "1.0.0"
            audit = $audit
            capabilities = @(
                "certificate_events",
                "rdp_sessions",
                "web_enrollment",
                "server_metrics",
                "service_state",
                "enable_ca_auditing"
            )
            active_session_count = $activeSessions
            web_enrollment_user_count = $webUsers
            metadata = @{
                certsvc_state = (
                    Get-ServiceState "CertSvc"
                )
                iis_state = (
                    Get-ServiceState "W3SVC"
                )
            }
        }

        [void](
            Invoke-AgentApi `
                -Method POST `
                -Path (
                    "/api/v1/monitoring/" +
                    "agents/heartbeat"
                ) `
                -Body $heartbeat
        )
    }
    catch {
        Write-AgentLog (
            "Heartbeat failed: " +
            $_.Exception.Message
        )
    }

    try {
        $securityEvents = Get-NewLogEvents `
            -LogName "Security" `
            -Ids @(4886, 4887, 4888, 4889) `
            -LastRecordId (
                [long]$State.security_record_id
            )

        $rdpEvents = Get-NewLogEvents `
            -LogName (
                "Microsoft-Windows-" +
                "TerminalServices-" +
                "LocalSessionManager/Operational"
            ) `
            -Ids @(21, 23, 24, 25) `
            -LastRecordId (
                [long]$State.rdp_record_id
            )

        $normalisedEvents = @()

        foreach ($event in $securityEvents) {
            $normalisedEvents += (
                Convert-MonitoringEvent `
                    -Event $event `
                    -Category "certificate"
            )
        }

        foreach ($event in $rdpEvents) {
            $normalisedEvents += (
                Convert-MonitoringEvent `
                    -Event $event `
                    -Category "access"
            )
        }

        if ($normalisedEvents.Count -gt 0) {
            $batch = @{
                agent_key = $Config.agent_key
                events = $normalisedEvents
            }

            [void](
                Invoke-AgentApi `
                    -Method POST `
                    -Path (
                        "/api/v1/monitoring/" +
                        "agents/events"
                    ) `
                    -Body $batch
            )

            if ($securityEvents.Count -gt 0) {
                $State.security_record_id = (
                    $securityEvents[-1].RecordId
                )
            }

            if ($rdpEvents.Count -gt 0) {
                $State.rdp_record_id = (
                    $rdpEvents[-1].RecordId
                )
            }

            $State |
                ConvertTo-Json |
                Set-Content `
                    -Path $StatePath `
                    -Encoding UTF8
        }
    }
    catch {
        Write-AgentLog (
            "Event collection failed: " +
            $_.Exception.Message
        )
    }

    if (
        (Get-Date) -ge
        $lastMetricSent.AddSeconds(30)
    ) {
        try {
            $metrics = Get-ServerMetrics

            [void](
                Invoke-AgentApi `
                    -Method POST `
                    -Path (
                        "/api/v1/monitoring/" +
                        "agents/metrics"
                    ) `
                    -Body $metrics
            )

            $lastMetricSent = Get-Date
        }
        catch {
            Write-AgentLog (
                "Metric collection failed: " +
                $_.Exception.Message
            )
        }
    }

    try {
        $commandResponse = Invoke-AgentApi `
            -Method GET `
            -Path (
                "/api/v1/monitoring/agents/" +
                $Config.agent_key +
                "/commands/next"
            )

        if ($commandResponse.command) {
            $command = $commandResponse.command
            $success = $false
            $message = ""
            $resultAudit = $null

            try {
                switch ($command.type) {
                    "enable_ca_auditing" {
                        $resultAudit = Enable-CaAuditing
                        $success = (
                            $resultAudit.audit_ready
                        )
                        $message = (
                            "Certification Services auditing " +
                            "was enabled and CertSvc restarted."
                        )
                    }
                    default {
                        throw (
                            "Unsupported command: " +
                            $command.type
                        )
                    }
                }
            }
            catch {
                $success = $false
                $message = $_.Exception.Message
            }

            $result = @{
                success = $success
                message = $message
                audit = $resultAudit
                details = @{
                    hostname = $env:COMPUTERNAME
                }
            }

            [void](
                Invoke-AgentApi `
                    -Method POST `
                    -Path (
                        "/api/v1/monitoring/agents/" +
                        $Config.agent_key +
                        "/commands/" +
                        $command.id +
                        "/result"
                    ) `
                    -Body $result
            )
        }
    }
    catch {
        Write-AgentLog (
            "Command polling failed: " +
            $_.Exception.Message
        )
    }

    Start-Sleep -Seconds (
        [int]$Config.poll_seconds
    )
}
