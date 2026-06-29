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
    $cpuPercent = $null
    $memoryPercent = $null
    $diskFreePercent = $null
    $diskUsedPercent = $null

    try {
        $cpuCounter = Get-Counter `
            -Counter "\Processor(_Total)\% Processor Time" `
            -SampleInterval 1 `
            -MaxSamples 2 `
            -ErrorAction Stop

        $cpuPercent = [math]::Round(
            [double](($cpuCounter.CounterSamples | Select-Object -Last 1).CookedValue),
            1
        )
    }
    catch {
        try {
            $cpu = Get-CimInstance Win32_Processor |
                Measure-Object -Property LoadPercentage -Average

            $cpuPercent = [math]::Round([double]$cpu.Average, 1)
        }
        catch {
            $cpuPercent = $null
        }
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $totalKb = [double]$os.TotalVisibleMemorySize
        $freeKb = [double]$os.FreePhysicalMemory

        if ($totalKb -gt 0) {
            $memoryPercent = [math]::Round(
                (($totalKb - $freeKb) / $totalKb) * 100,
                1
            )
        }
    }
    catch {
        $memoryPercent = $null
    }

    try {
        $systemDrive = $env:SystemDrive
        if (-not $systemDrive) {
            $systemDrive = "C:"
        }

        $disk = Get-CimInstance `
            -ClassName Win32_LogicalDisk `
            -Filter "DeviceID='$systemDrive'" `
            -ErrorAction Stop

        if ([double]$disk.Size -gt 0) {
            $diskFreePercent = [math]::Round(
                ([double]$disk.FreeSpace / [double]$disk.Size) * 100,
                1
            )

            $diskUsedPercent = [math]::Round(
                100 - $diskFreePercent,
                1
            )
        }
    }
    catch {
        $diskFreePercent = $null
        $diskUsedPercent = $null
    }

    $network = [ordered]@{
        interface_name = ""
        interface_description = ""
        link_speed = ""
        mac_address = ""
        ipv4_address = ""
        gateway = ""
        dns_servers = @()
        send_kbps = $null
        receive_kbps = $null
        total_kbps = $null
        adapter_count = 0
        sample_type = "adapter_statistics_delta"
    }

    try {
        $activeAdapters = @(
            Get-NetAdapter -ErrorAction Stop |
                Where-Object {
                    $_.Status -eq "Up" -and
                    $_.Name -notmatch "Loopback|isatap|Teredo|Bluetooth"
                } |
                Sort-Object ifIndex
        )

        $network.adapter_count = $activeAdapters.Count

        $primary = $activeAdapters | Select-Object -First 1

        if ($primary) {
            $network.interface_name = [string]$primary.Name
            $network.interface_description = [string]$primary.InterfaceDescription
            $network.link_speed = [string]$primary.LinkSpeed
            $network.mac_address = [string]$primary.MacAddress
        }

        try {
            $ipConfig = Get-NetIPConfiguration `
                -InterfaceIndex $primary.ifIndex `
                -ErrorAction Stop

            $network.ipv4_address = [string](
                $ipConfig.IPv4Address.IPAddress |
                    Select-Object -First 1
            )

            if ($ipConfig.IPv4DefaultGateway) {
                $network.gateway = [string](
                    $ipConfig.IPv4DefaultGateway.NextHop |
                        Select-Object -First 1
                )
            }

            if ($ipConfig.DNSServer) {
                $network.dns_servers = @(
                    $ipConfig.DNSServer.ServerAddresses
                )
            }
        }
        catch {}

        $nowUtc = (Get-Date).ToUniversalTime()
        $runtime = Read-AgentRuntimeState

        $rxNow = 0.0
        $txNow = 0.0

        foreach ($adapter in $activeAdapters) {
            try {
                $stats = Get-NetAdapterStatistics `
                    -Name $adapter.Name `
                    -ErrorAction Stop

                $rxNow += [double]$stats.ReceivedBytes
                $txNow += [double]$stats.SentBytes
            }
            catch {}
        }

        $prevRx = 0.0
        $prevTx = 0.0
        $prevTime = $null

        try { $prevRx = [double]$runtime.network_received_bytes } catch {}
        try { $prevTx = [double]$runtime.network_sent_bytes } catch {}

        try {
            if ($runtime.network_sample_time) {
                $prevTime = [datetime]$runtime.network_sample_time
            }
        }
        catch {
            $prevTime = $null
        }

        if ($prevTime) {
            $seconds = ($nowUtc - $prevTime.ToUniversalTime()).TotalSeconds

            if ($seconds -gt 0) {
                $rxDelta = [math]::Max(0, $rxNow - $prevRx)
                $txDelta = [math]::Max(0, $txNow - $prevTx)

                $receiveKbps = (($rxDelta * 8) / 1000) / $seconds
                $sendKbps = (($txDelta * 8) / 1000) / $seconds

                $network.receive_kbps = [math]::Round($receiveKbps, 1)
                $network.send_kbps = [math]::Round($sendKbps, 1)
                $network.total_kbps = [math]::Round(
                    $receiveKbps + $sendKbps,
                    1
                )
            }
        }

        if ($runtime.PSObject.Properties.Name -contains "network_received_bytes") {
            $runtime.network_received_bytes = $rxNow
        }
        else {
            $runtime | Add-Member -NotePropertyName network_received_bytes -NotePropertyValue $rxNow -Force
        }

        if ($runtime.PSObject.Properties.Name -contains "network_sent_bytes") {
            $runtime.network_sent_bytes = $txNow
        }
        else {
            $runtime | Add-Member -NotePropertyName network_sent_bytes -NotePropertyValue $txNow -Force
        }

        if ($runtime.PSObject.Properties.Name -contains "network_sample_time") {
            $runtime.network_sample_time = $nowUtc.ToString("o")
        }
        else {
            $runtime | Add-Member -NotePropertyName network_sample_time -NotePropertyValue $nowUtc.ToString("o") -Force
        }

        Write-AgentRuntimeState -State $runtime
    }
    catch {}

    return [ordered]@{
        cpu_percent       = $cpuPercent
        memory_percent    = $memoryPercent
        disk_free_percent = $diskFreePercent
        disk_used_percent = $diskUsedPercent
        network           = $network
        collected_at      = (Get-Date).ToUniversalTime().ToString("o")
        sample_type       = "sampled_counter"
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

    function Convert-CaweAction {
        param(
            [string]$UriStem,
            [string]$UriQuery
        )

        $stem = ([string]$UriStem).ToLowerInvariant()
        $query = ([string]$UriQuery)

        if ($stem -eq "/certsrv/" -or $stem -eq "/certsrv/default.asp") {
            return "Opened Web Enrollment portal"
        }

        if ($stem -like "*/certrqxt.asp") {
            return "Opened certificate request page"
        }

        if ($stem -like "*/certfnsh.asp") {
            return "Submitted or completed certificate request"
        }

        if ($stem -like "*/certnew.cer") {
            return "Downloaded issued certificate"
        }

        if ($stem -like "*/certcarc.asp") {
            return "Browsed CA certificate / chain"
        }

        if ($stem -like "*/certckpn.asp") {
            return "Checked pending certificate request"
        }

        if ($stem -like "*/certcrl.asp") {
            return "Downloaded CRL"
        }

        if ($query -match "ReqID|RequestID") {
            return "Viewed certificate request details"
        }

        return "CA Web Enrollment activity"
    }

    try {
        $logs = @(
            Get-ChildItem -LiteralPath $root -Recurse -Filter *.log -ErrorAction Stop |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 5
        )

        foreach ($log in $logs) {
            $fields = @()

            $lines = Get-Content -LiteralPath $log.FullName -Tail 500 -ErrorAction Stop

            foreach ($line in $lines) {
                $text = [string]$line

                if ($text -match "^#Fields:\s+(.+)$") {
                    $fields = $Matches[1] -split "\s+"
                    continue
                }

                if ($text -match "^#" -or $text -notmatch "/certsrv") {
                    continue
                }

                if (-not $fields -or $fields.Count -eq 0) {
                    $activity += [ordered]@{
                        time        = ""
                        username    = ""
                        source_ip   = ""
                        method      = ""
                        uri         = ""
                        status      = ""
                        action      = "CA Web Enrollment activity"
                        user_agent  = ""
                        time_taken  = ""
                        log_file    = $log.Name
                        raw         = $text
                    }
                    continue
                }

                $parts = $text -split "\s+"
                $row = @{}

                for ($i = 0; $i -lt $fields.Count -and $i -lt $parts.Count; $i++) {
                    $row[$fields[$i]] = $parts[$i]
                }

                $date = [string]$row["date"]
                $time = [string]$row["time"]
                $uriStem = [string]$row["cs-uri-stem"]
                $uriQuery = [string]$row["cs-uri-query"]

                $username = [string]$row["cs-username"]
                if ($username -eq "-") {
                    $username = ""
                }

                $sourceIp = [string]$row["c-ip"]
                if ($sourceIp -eq "-") {
                    $sourceIp = ""
                }

                $method = [string]$row["cs-method"]
                if ($method -eq "-") {
                    $method = ""
                }

                $status = [string]$row["sc-status"]
                if ($status -eq "-") {
                    $status = ""
                }

                $userAgent = [string]$row["cs(User-Agent)"]
                if ($userAgent -eq "-") {
                    $userAgent = ""
                }

                $timeTaken = [string]$row["time-taken"]
                if ($timeTaken -eq "-") {
                    $timeTaken = ""
                }

                $uri = $uriStem
                if ($uriQuery -and $uriQuery -ne "-") {
                    $uri = "$uriStem`?$uriQuery"
                }

                $activity += [ordered]@{
                    time        = ("$date $time").Trim()
                    username    = $username
                    source_ip   = $sourceIp
                    method      = $method
                    uri         = $uri
                    status      = $status
                    action      = Convert-CaweAction -UriStem $uriStem -UriQuery $uriQuery
                    user_agent  = $userAgent
                    time_taken  = $timeTaken
                    log_file    = $log.Name
                    raw         = $text
                }
            }
        }
    }
    catch {}

    return @(
        $activity |
            Sort-Object time -Descending |
            Select-Object -First 50
    )
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



function Get-CertShieldLocalGroupMembers {
    param(
        [Parameter(Mandatory)]
        [string]$GroupName
    )

    $members = @()

    try {
        $group = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"

        foreach ($member in @($group.psbase.Invoke("Members"))) {
            $name = ""
            $path = ""

            try {
                $name = [string]$member.GetType().InvokeMember(
                    "Name",
                    "GetProperty",
                    $null,
                    $member,
                    $null
                )
            }
            catch {}

            try {
                $path = [string]$member.GetType().InvokeMember(
                    "ADsPath",
                    "GetProperty",
                    $null,
                    $member,
                    $null
                )
            }
            catch {}

            if ($name) {
                $members += [ordered]@{
                    name = $name
                    path = $path
                    source = "local_group"
                }
            }
        }
    }
    catch {}

    return @($members)
}

function Test-CertShieldMemberActive {
    param(
        [Parameter(Mandatory)]
        [string]$MemberName,

        [Parameter(Mandatory)]
        [object[]]$Sessions
    )

    $member = ([string]$MemberName).Trim().ToLowerInvariant()

    if (-not $member) {
        return $false
    }

    foreach ($session in @($Sessions)) {
        if (-not $session) {
            continue
        }

        $username = ""

        try {
            $username = ([string]$session.username).Trim().ToLowerInvariant()
        }
        catch {
            $username = ""
        }

        if (-not $username) {
            continue
        }

        if ($member -eq $username) {
            return $true
        }

        if ($member.EndsWith("\$username")) {
            return $true
        }

        if ($member.EndsWith("/$username")) {
            return $true
        }

        if ($username.EndsWith("\$member")) {
            return $true
        }
    }

    return $false
}

function Get-PkiPrivilegedRoles {
    $sessions = @(Get-InteractiveSessions)
    $roles = @()

    $roleMap = @(
        [ordered]@{
            role_name = "Local Administrators"
            group_name = "Administrators"
            role_type = "host_admin"
            meaning = "Can administer the CA server and usually control AD CS service configuration."
        },
        [ordered]@{
            role_name = "Backup Operators"
            group_name = "Backup Operators"
            role_type = "backup_operator"
            meaning = "Can perform backup/restore style operations on the CA host."
        },
        [ordered]@{
            role_name = "Event Log Readers"
            group_name = "Event Log Readers"
            role_type = "audit_reader"
            meaning = "Can read Windows event logs used for AD CS audit visibility."
        },
        [ordered]@{
            role_name = "Remote Management Users"
            group_name = "Remote Management Users"
            role_type = "remote_management"
            meaning = "Can use remote management channels such as WinRM where permitted."
        },
        [ordered]@{
            role_name = "Certificate Service DCOM Access"
            group_name = "Certificate Service DCOM Access"
            role_type = "ca_dcom_access"
            meaning = "Can access AD CS DCOM/RPC interfaces remotely where CA permissions allow."
        },
        [ordered]@{
            role_name = "IIS_IUSRS"
            group_name = "IIS_IUSRS"
            role_type = "cawe_runtime"
            meaning = "Local IIS worker/runtime group used by web applications including CA Web Enrollment."
        }
    )

    foreach ($role in $roleMap) {
        $members = @(Get-CertShieldLocalGroupMembers -GroupName $role.group_name)

        foreach ($member in $members) {
            $display = [string]$member.name

            if ($member.path -match "WinNT://(.+)$") {
                $display = $Matches[1].Replace("/", "\")
            }

            $roles += [ordered]@{
                role_name = [string]$role.role_name
                group_name = [string]$role.group_name
                role_type = [string]$role.role_type
                member = $display
                source = [string]$member.source
                active_now = [bool](Test-CertShieldMemberActive -MemberName $display -Sessions $sessions)
                meaning = [string]$role.meaning
            }
        }

        if ($members.Count -eq 0) {
            $roles += [ordered]@{
                role_name = [string]$role.role_name
                group_name = [string]$role.group_name
                role_type = [string]$role.role_type
                member = ""
                source = "local_group"
                active_now = $false
                meaning = [string]$role.meaning
            }
        }
    }

    return @($roles)
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
        pki_roles = @(Get-PkiPrivilegedRoles)
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


function ConvertFrom-CertShieldAdcsMessage {
    param(
        [string]$Message
    )

    $details = [ordered]@{}

    foreach ($line in (($Message -split "`r?`n") | Where-Object { $_ })) {
        $text = ([string]$line).Trim()

        if ($text -match "^([^:]{2,120}):\s*(.*)$") {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()

            $normalized = (
                $key `
                    -replace "[^A-Za-z0-9]+", "_" `
            ).Trim("_").ToLowerInvariant()

            if ($normalized -and -not $details.Contains($normalized)) {
                $details[$normalized] = $value
            }
        }
    }

    if ($Message -match "Request\s+ID:\s*([^\r\n]+)") {
        $details["request_id"] = $Matches[1].Trim()
    }

    if ($Message -match "Requester:\s*([^\r\n]+)") {
        $details["requester"] = $Matches[1].Trim()
    }

    if ($Message -match "Subject:\s*([^\r\n]+)") {
        $details["subject"] = $Matches[1].Trim()
    }

    if ($Message -match "Certificate\s+Template:\s*([^\r\n]+)") {
        $details["template"] = $Matches[1].Trim()
    }

    if ($Message -match "CertificateTemplate:([A-Za-z0-9_.-]+)") {
        $details["template"] = $Matches[1].Trim()
    }

    if (-not $details.Contains("template") -and $details.Contains("attributes")) {
        $attributes = [string]$details["attributes"]

        if ($attributes -match "CertificateTemplate:([A-Za-z0-9_.-]+)") {
            $details["template"] = $Matches[1].Trim()
        }
    }

    return $details
}

function Get-CertShieldDetail {
    param(
        [Parameter(Mandatory)]
        [object]$Details,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        try {
            if ($Details.Contains($name) -and $Details[$name]) {
                return [string]$Details[$name]
            }
        }
        catch {}
    }

    return ""
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

    $parsed = ConvertFrom-CertShieldAdcsMessage -Message $message

    $summary = $message

    if ($summary.Length -gt 900) {
        $summary = $summary.Substring(0, 900)
    }

    $eventId = [int]$Event.Id

    $category = "adcs_audit"
    $eventType = "windows_event_{0}" -f $eventId
    $severity = "info"
    $title = "AD CS audit event {0}" -f $eventId

    switch ($eventId) {
        4870 {
            $category = "certificate"
            $eventType = "certificate_revoked"
            $severity = "warning"
            $title = "Certificate revoked"
        }

        4886 {
            $category = "certificate"
            $eventType = "certificate_requested"
            $severity = "info"
            $title = "Certificate request received"
        }

        4887 {
            $category = "certificate"
            $eventType = "certificate_issued"
            $severity = "success"
            $title = "Certificate issued"
        }

        4888 {
            $category = "certificate"
            $eventType = "certificate_denied"
            $severity = "high"
            $title = "Certificate request denied"
        }

        4889 {
            $category = "certificate"
            $eventType = "certificate_pending"
            $severity = "warning"
            $title = "Certificate request pending"
        }

        4880 {
            $category = "infrastructure"
            $eventType = "certsvc_started"
            $severity = "success"
            $title = "Certificate Services started"
        }

        4881 {
            $category = "infrastructure"
            $eventType = "certsvc_stopped"
            $severity = "high"
            $title = "Certificate Services stopped"
        }

        4890 {
            $category = "configuration"
            $eventType = "ca_configuration_changed"
            $severity = "warning"
            $title = "CA configuration changed"
        }

        4897 {
            $category = "configuration"
            $eventType = "role_separation_changed"
            $severity = "warning"
            $title = "CA role separation setting changed"
        }
    }

    $requestId = Get-CertShieldDetail `
        -Details $parsed `
        -Names @("request_id", "requestid", "request")

    $requester = Get-CertShieldDetail `
        -Details $parsed `
        -Names @("requester", "caller", "account_name", "user")

    $template = Get-CertShieldDetail `
        -Details $parsed `
        -Names @("template", "certificate_template", "certificatetemplate")

    $subject = Get-CertShieldDetail `
        -Details $parsed `
        -Names @("subject", "certificate_subject")

    $objectLabel = ""

    if ($requestId) {
        $objectLabel = "Request ID $requestId"
    }

    if ($subject) {
        if ($objectLabel) {
            $objectLabel = "$objectLabel · $subject"
        }
        else {
            $objectLabel = $subject
        }
    }

    $parsed["record_id"] = [int64]$Event.RecordId
    $parsed["event_id"] = $eventId
    $parsed["provider_name"] = [string]$Event.ProviderName
    $parsed["log_name"] = [string]$Event.LogName
    $parsed["machine_name"] = [string]$Event.MachineName
    $parsed["level_display_name"] = [string]$Event.LevelDisplayName
    $parsed["message"] = $message
    $parsed["request_id"] = $requestId
    $parsed["requester"] = $requester
    $parsed["template"] = $template
    $parsed["subject"] = $subject
    $parsed["object"] = $objectLabel

    return [ordered]@{
        event_key   = "windows-security:{0}:{1}" -f (
            $Event.MachineName
        ), (
            $Event.RecordId
        )
        category    = $category
        event_type  = $eventType
        severity    = $severity
        title       = $title
        summary     = $summary
        actor       = $requester
        source_ip   = ""
        occurred_at = ConvertTo-CertShieldUtcString `
            -Value $Event.TimeCreated
        details     = $parsed
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
        4870,
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

    try {
        $rolesNow = @()

        if (Get-Command Get-PkiPrivilegedRoles -ErrorAction SilentlyContinue) {
            $rolesNow = @(Get-PkiPrivilegedRoles)
        }

        if ($state -is [System.Collections.IDictionary]) {
            $state["pki_roles"] = @($rolesNow)
        }
        elseif ($state.PSObject.Properties.Name -contains "pki_roles") {
            $state.pki_roles = @($rolesNow)
        }
        else {
            $state |
                Add-Member `
                    -NotePropertyName pki_roles `
                    -NotePropertyValue @($rolesNow) `
                    -Force
        }

        $previewPath = Join-Path `
            (Split-Path -Parent $ConfigPath) `
            "heartbeat-preview.json"

        $state |
            ConvertTo-Json -Depth 30 |
            Set-Content `
                -LiteralPath $previewPath `
                -Encoding UTF8
    }
    catch {
        Add-Content `
            -LiteralPath (
                Join-Path `
                    (Split-Path -Parent $ConfigPath) `
                    "agent-error.log"
            ) `
            -Value (
                "{0} PKI role heartbeat collection failed: {1}" -f `
                (Get-Date).ToUniversalTime().ToString("o"),
                $_.Exception.Message
            )
    }

    $payload = [ordered]@{
        agent_key        = [string]$script:Config.agent_key
        hostname         = $env:COMPUTERNAME
        ca_name          = $caName
        agent_version    = "0.3.2"
        environment_name = [string]$script:Config.environment_name
        domain_name      = [string]$script:Config.domain_name
        forest_name      = [string]$script:Config.forest_name
        collector_type   = [string]$script:Config.collector_type
        state            = $state
    }

    return Invoke-AgentApi `
        -Method POST `
        -Path "/api/v1/monitoring/agent/heartbeat" `
        -Body $payload
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










