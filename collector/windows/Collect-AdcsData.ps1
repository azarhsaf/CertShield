<#
.SYNOPSIS
  Collect ADCS defensive inventory data and push to CertShield API.

.NOTES
  - PowerShell 5.1 compatible.
  - Requires certutil and (for template enumeration) ActiveDirectory RSAT module.
  - Preserves legacy broad enrollment fallback to keep existing finding behavior.

.EXAMPLE
  .\Collect-AdcsData.ps1 -ApiUrl "http://10.0.0.25:8000" -ApiToken "collector-dev-token"

.EXAMPLE
  .\Collect-AdcsData.ps1 -ApiUrl "http://10.0.0.25:8000" -ApiToken "collector-dev-token" -SkipIssued -DebugPayload
#>
param(
  [Parameter(Mandatory=$true)][string]$ApiUrl,
  [Parameter(Mandatory=$true)][string]$ApiToken,
  [string]$DomainName = $env:USERDNSDOMAIN,
  [int]$RecentRequestLimit = 200,
  [switch]$SkipIssued,
  [switch]$DebugPayload
)

$ErrorActionPreference = 'Stop'

function Write-Step {
  param([string]$Message)
  Write-Host "[CertShield Collector] $Message"
}

function Get-CertificateAuthorities {
  $cas = @()
  try {
    $lines = certutil -config - -ping 2>$null
    foreach ($line in $lines) {
      if ($line -match '^Connecting to (.+)\\(.+)$') {
        $cas += [pscustomobject]@{
          name = $matches[2]
          dns_name = $matches[1]
          status = 'online'
          config = @{}
        }
      }
    }
  } catch {
    Write-Warning "Unable to query CAs via certutil: $_"
  }
  return @($cas)
}

function Test-ActiveDirectoryModule {
  $module = Get-Module -ListAvailable -Name ActiveDirectory
  if ($null -eq $module) {
    Write-Warning "ActiveDirectory module not found. Install RSAT AD PowerShell tools on this host."
    return $false
  }
  Import-Module ActiveDirectory -ErrorAction Stop
  return $true
}

function Get-Templates {
  $templates = @()

  if (-not (Test-ActiveDirectoryModule)) {
    return @($templates)
  }

  try {
    $root = Get-ADRootDSE
    $configNc = $root.configurationNamingContext
    $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc"
    $props = "displayName","mspki-certificate-name-flag","mspki-enrollment-flag","msPKI-RA-Signature","pKIExtendedKeyUsage"
    $objs = Get-ADObject -Filter * -SearchBase $base -Properties $props

    foreach ($o in $objs) {
      $nameFlag = 0
      if ($o.'mspki-certificate-name-flag') { $nameFlag = [int]$o.'mspki-certificate-name-flag' }
      $enrollFlag = 0
      if ($o.'mspki-enrollment-flag') { $enrollFlag = [int]$o.'mspki-enrollment-flag' }

      $authSig = 0
      if ($o.'msPKI-RA-Signature') { $authSig = [int]$o.'msPKI-RA-Signature' }

      $ekuArray = @()
      if ($o.'pKIExtendedKeyUsage') { $ekuArray = @($o.'pKIExtendedKeyUsage') }

      # Keep this broad default to preserve existing risk finding behavior.
      $permissions = @(
        [pscustomobject]@{ principal = 'Authenticated Users'; can_enroll = $true; can_autoenroll = $false }
      )

      $display = $o.Name
      if ($o.displayName) { $display = [string]$o.displayName }

      $templates += [pscustomobject]@{
        name = [string]$o.Name
        display_name = $display
        eku = @($ekuArray)
        enrollee_supplies_subject = (($nameFlag -band 1) -ne 0)
        manager_approval = (($enrollFlag -band 2) -ne 0)
        authorized_signatures = $authSig
        validity_days = 365
        renewal_days = 30
        published_to = @()
        permissions = @($permissions)
        raw = @{}
      }
    }
  } catch {
    Write-Warning "Template enumeration failed: $_"
  }

  return @($templates)
}

function Parse-CertutilValue {
  param([string]$Line)
  $parts = $Line -split ':', 2
  if ($parts.Count -lt 2) { return "" }
  return $parts[1].Trim()
}

function Get-IssuedCertificates {
  $results = @()
  if ($SkipIssued) {
    Write-Step "Skipping issued certificate query due to -SkipIssued switch"
    return @($results)
  }

  try {
    $lines = certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,CertificateTemplate,CommonName,NotBefore,NotAfter" 2>$null
    $current = @{}
    foreach ($line in $lines) {
      if ($line -match '^Request ID:\s*(.+)$') {
        if ($current.ContainsKey('request_id')) {
          $results += [pscustomobject]$current
          $current = @{}
        }
        $current['request_id'] = $matches[1].Trim()
        $current['requester'] = ''
        $current['template_name'] = ''
        $current['subject'] = ''
        $current['san'] = ''
        $current['issued_at'] = ''
        $current['expires_at'] = ''
        $current['status'] = 'issued'
        continue
      }
      if ($line -match '^Requester Name:') { $current['requester'] = Parse-CertutilValue -Line $line; continue }
      if ($line -match '^Certificate Template:') { $current['template_name'] = Parse-CertutilValue -Line $line; continue }
      if ($line -match '^Issued Common Name:') { $current['subject'] = Parse-CertutilValue -Line $line; continue }
      if ($line -match '^Certificate Effective Date:') { $current['issued_at'] = Parse-CertutilValue -Line $line; continue }
      if ($line -match '^Certificate Expiration Date:') { $current['expires_at'] = Parse-CertutilValue -Line $line; continue }
    }

    if ($current.ContainsKey('request_id')) {
      $results += [pscustomobject]$current
    }
  } catch {
    Write-Warning "Unable to fetch issued certificates via certutil: $_"
  }

  if ($results.Count -gt $RecentRequestLimit) {
    $results = $results | Select-Object -First $RecentRequestLimit
  }

  return @($results)
}

if (-not $DomainName) {
  $DomainName = 'unknown.local'
}

Write-Step "Collecting ADCS data from host $env:COMPUTERNAME"
$payload = [ordered]@{
  domain_name = $DomainName
  source_host = $env:COMPUTERNAME
  cas = @(Get-CertificateAuthorities)
  templates = @(Get-Templates)
  issued_certificates = @(Get-IssuedCertificates)
}

$json = $payload | ConvertTo-Json -Depth 10
if ($DebugPayload) {
  Write-Step "Payload preview:"
  Write-Host $json
}

$uri = "$($ApiUrl.TrimEnd('/'))/api/v1/collector/ingest"
Write-Step "Posting payload to $uri"

try {
  $resp = Invoke-RestMethod -Method Post -Uri $uri -ContentType 'application/json' -Headers @{ Authorization = "Bearer $ApiToken" } -Body $json
  Write-Step "Ingest completed. Response: $($resp | ConvertTo-Json -Depth 4)"
} catch {
  Write-Error "Collector ingest failed: $($_.Exception.Message)"
  throw
}
