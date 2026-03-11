<#
.SYNOPSIS
  Collect defensive ADCS visibility data and send to CertShield.
.DESCRIPTION
  Safe collection only. This script does not request certificates or perform exploitation.
  PowerShell 5.1 compatible.
.EXAMPLE
  .\Collect-AdcsData.ps1 -ApiUrl "http://10.0.0.25:8000" -ApiToken "collector-token"
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
$CollectorVersion = 'collector-ps51-1.1'

function Write-Step { param([string]$Message) Write-Host "[CertShield] $Message" }

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
          config = @{ web_enrollment_assessed = $false; ca_policy_flags_assessed = $false; published_templates = @() }
        }
      }
    }
  } catch { Write-Warning "CA discovery failed via certutil: $_" }
  return @($cas)
}

function Test-ADModule {
  $module = Get-Module -ListAvailable -Name ActiveDirectory
  if ($null -eq $module) { Write-Warning "ActiveDirectory module missing. Install RSAT AD tools."; return $false }
  Import-Module ActiveDirectory -ErrorAction Stop
  return $true
}

function Get-Templates {
  $templates = @()
  if (-not (Test-ADModule)) { return @($templates) }
  try {
    $root = Get-ADRootDSE
    $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($root.configurationNamingContext)"
    $props = "displayName","mspki-certificate-name-flag","mspki-enrollment-flag","msPKI-RA-Signature","pKIExtendedKeyUsage"
    $objs = Get-ADObject -Filter * -SearchBase $base -Properties $props
    foreach ($o in $objs) {
      $nameFlag = 0; if ($o.'mspki-certificate-name-flag') { $nameFlag = [int]$o.'mspki-certificate-name-flag' }
      $enrollFlag = 0; if ($o.'mspki-enrollment-flag') { $enrollFlag = [int]$o.'mspki-enrollment-flag' }
      $authSig = 0; if ($o.'msPKI-RA-Signature') { $authSig = [int]$o.'msPKI-RA-Signature' }
      $eku = @(); if ($o.'pKIExtendedKeyUsage') { $eku = @($o.'pKIExtendedKeyUsage') }
      $display = $o.Name; if ($o.displayName) { $display = [string]$o.displayName }
      $templates += [pscustomobject]@{
        name = [string]$o.Name
        display_name = $display
        eku = @($eku)
        enrollee_supplies_subject = (($nameFlag -band 1) -ne 0)
        manager_approval = (($enrollFlag -band 2) -ne 0)
        authorized_signatures = $authSig
        validity_days = 365
        renewal_days = 30
        published_to = @()
        permissions = @([pscustomobject]@{ principal = 'Authenticated Users'; can_enroll = $true; can_autoenroll = $false })
        raw = @{ acl_assessed = $false; acl_details = @() }
      }
    }
  } catch { Write-Warning "Template enumeration failed: $_" }
  return @($templates)
}

function Parse-CertValue { param([string]$Line) $parts = $Line -split ':',2; if ($parts.Count -lt 2) { return '' }; return $parts[1].Trim() }

function Get-IssuedCertificates {
  $out = @()
  if ($SkipIssued) { return @($out) }
  try {
    $lines = certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,CertificateTemplate,CommonName,NotBefore,NotAfter" 2>$null
    $cur = @{}
    foreach ($line in $lines) {
      if ($line -match '^Request ID:\s*(.+)$') {
        if ($cur.ContainsKey('request_id')) { $out += [pscustomobject]$cur; $cur = @{} }
        $cur = @{ request_id=$matches[1].Trim(); requester=''; template_name=''; subject=''; san=''; issued_at=''; expires_at=''; status='issued' }
      } elseif ($line -match '^Requester Name:') { $cur['requester'] = Parse-CertValue -Line $line }
      elseif ($line -match '^Certificate Template:') { $cur['template_name'] = Parse-CertValue -Line $line }
      elseif ($line -match '^Issued Common Name:') { $cur['subject'] = Parse-CertValue -Line $line }
      elseif ($line -match '^Certificate Effective Date:') { $cur['issued_at'] = Parse-CertValue -Line $line }
      elseif ($line -match '^Certificate Expiration Date:') { $cur['expires_at'] = Parse-CertValue -Line $line }
    }
    if ($cur.ContainsKey('request_id')) { $out += [pscustomobject]$cur }
  } catch { Write-Warning "Issued certificate query failed: $_" }
  if ($out.Count -gt $RecentRequestLimit) { $out = $out | Select-Object -First $RecentRequestLimit }
  return @($out)
}

if (-not $DomainName) { $DomainName = 'unknown.local' }
$assessmentHints = @{ esc6_ca_policy = 'not_assessed'; esc7_ca_roles = 'not_assessed'; esc8_web_enrollment = 'insufficient_data'; esc4_template_acl = 'insufficient_data' }

$payload = [ordered]@{
  domain_name = $DomainName
  source_host = $env:COMPUTERNAME
  collector_version = $CollectorVersion
  cas = @(Get-CertificateAuthorities)
  templates = @(Get-Templates)
  issued_certificates = @(Get-IssuedCertificates)
  assessment_hints = $assessmentHints
}

$json = $payload | ConvertTo-Json -Depth 12
if ($DebugPayload) { Write-Host $json }
$uri = "$($ApiUrl.TrimEnd('/'))/api/v1/collector/ingest"
Write-Step "Posting payload to $uri"
Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $ApiToken" } -ContentType 'application/json' -Body $json
