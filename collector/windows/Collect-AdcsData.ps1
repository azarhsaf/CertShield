<#
.SYNOPSIS
  Collect defensive ADCS visibility data and send to CertShield.
.DESCRIPTION
  Safe, read-only collection only. This script does not request certificates,
  perform relay, change CA configuration, or perform exploitation. PowerShell 5.1 compatible.
.EXAMPLE
  .\Collect-AdcsData.ps1 -ApiUrl "http://10.0.0.25:8000" -ApiToken "collector-token"
.EXAMPLE
  .\Collect-AdcsData.ps1 -ApiUrl "http://10.0.0.25:8000" -ApiToken "collector-token" -NoPost -OutputJson .\adcs-payload.json -DebugPayload
#>
param(
  [Parameter(Mandatory=$true)][string]$ApiUrl,
  [Parameter(Mandatory=$true)][string]$ApiToken,
  [string]$DomainName = $env:USERDNSDOMAIN,
  [int]$RecentRequestLimit = 200,
  [switch]$SkipIssued,
  [switch]$DebugPayload,
  [switch]$NoPost,
  [string]$OutputJson,
  [switch]$SkipHealth,
  [switch]$SkipAcl,
  [switch]$SkipCrl
)

$ErrorActionPreference = 'Stop'
$CollectorVersion = 'collector-ps51-1.3'

function Write-Step { param([string]$Message) Write-Host "[CertShield] $Message" }
function Empty-List { return @() }

function Test-ADModule {
  $module = Get-Module -ListAvailable -Name ActiveDirectory
  if ($null -eq $module) { Write-Warning "ActiveDirectory module missing. Install RSAT AD tools."; return $false }
  Import-Module ActiveDirectory -ErrorAction Stop
  return $true
}

function Extract-Urls {
  param([string]$Text)
  $urls = @()
  if (-not $Text) { return @($urls) }
  $matches = [regex]::Matches($Text, '(https?://[^\s,;]+|ldap://[^\s,;]+)')
  foreach ($m in $matches) { $urls += [string]$m.Value }
  return @($urls | Select-Object -Unique)
}

function Get-CaCertificateHints {
  param([string]$ConfigString)
  $hint = @{
    ca_certificate_collected = $false
    config = @{
      certificate_collected = $false
      certificate_collection_reason = 'not available from current collector'
      crl = @{ assessed = $false; configured = $null; reachable = $null; urls = @(); next_update = $null; source = 'not collected' }
      aia = @{ assessed = $false; configured = $null; reachable = $null; urls = @(); source = 'not collected' }
      ocsp = @{ assessed = $false; configured = $null; reachable = $null; urls = @(); responder_status = 'not_assessed' }
    }
  }
  if ($SkipHealth) { return $hint }
  $tmp = [System.IO.Path]::GetTempFileName()
  try {
    certutil -config $ConfigString -ca.cert $tmp 2>$null | Out-Null
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmp)
    $hint.ca_certificate_collected = $true
    $hint.config.certificate_collected = $true
    $hint.config.certificate_expires_at = $cert.NotAfter.ToString('yyyy-MM-ddTHH:mm:ss')
    $hint.config.certificate_subject = $cert.Subject
    $hint.config.certificate_issuer = $cert.Issuer
    $hint.config.signature_algorithm = $cert.SignatureAlgorithm.FriendlyName
    try { $hint.config.key_size = $cert.PublicKey.Key.KeySize } catch { $hint.config.key_size = $null }
    $crlUrls = @(); $aiaUrls = @(); $ocspUrls = @()
    foreach ($ext in $cert.Extensions) {
      $formatted = $ext.Format($true)
      if ($ext.Oid.Value -eq '2.5.29.31') { $crlUrls += Extract-Urls -Text $formatted }
      elseif ($ext.Oid.Value -eq '1.3.6.1.5.5.7.1.1') {
        $urls = Extract-Urls -Text $formatted
        foreach ($url in $urls) {
          if ($url -match '/ocsp' -or $formatted -match 'OCSP') { $ocspUrls += $url } else { $aiaUrls += $url }
        }
      }
    }
    $crlUrls = @($crlUrls | Select-Object -Unique)
    $aiaUrls = @($aiaUrls | Select-Object -Unique)
    $ocspUrls = @($ocspUrls | Select-Object -Unique)
    if (-not $SkipCrl) { $hint.config.crl = @{ assessed = $true; configured = ($crlUrls.Count -gt 0); reachable = $null; urls = @($crlUrls); next_update = $null; source = 'ca certificate CDP extension' } }
    $hint.config.aia = @{ assessed = $true; configured = ($aiaUrls.Count -gt 0); reachable = $null; urls = @($aiaUrls); source = 'ca certificate AIA extension' }
    $hint.config.ocsp = @{ assessed = $true; configured = ($ocspUrls.Count -gt 0); reachable = $null; urls = @($ocspUrls); responder_status = 'not_tested' }
  } catch {
    $hint.config.certificate_collection_reason = "CA certificate query failed: $_"
  } finally {
    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
  }
  return $hint
}

function Get-PublishedTemplateMap {
  $map = @{}
  if (-not (Test-ADModule)) { return $map }
  try {
    $root = Get-ADRootDSE
    $base = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($root.configurationNamingContext)"
    $services = Get-ADObject -Filter * -SearchBase $base -Properties certificateTemplates,dNSHostName
    foreach ($svc in $services) {
      $templates = @()
      if ($svc.certificateTemplates) { $templates = @($svc.certificateTemplates) }
      $map[[string]$svc.Name] = @($templates)
    }
  } catch { Write-Warning "Published template mapping unavailable: $_" }
  return $map
}

function Get-CertificateAuthorities {
  param([hashtable]$PublishedMap, [hashtable]$HealthCoverage)
  $cas = @()
  try {
    $lines = certutil -config - -ping 2>$null
    foreach ($line in $lines) {
      if ($line -match '^Connecting to (.+)\\(.+)$') {
        $dns = $matches[1]
        $caName = $matches[2]
        $published = @()
        if ($PublishedMap -and $PublishedMap.ContainsKey($caName)) { $published = @($PublishedMap[$caName]) }
        $configString = "$dns\$caName"
        $certHint = Get-CaCertificateHints -ConfigString $configString
        if ($certHint.ca_certificate_collected) { $HealthCoverage['ca_certificate_collected'] = $true }
        if (($certHint.config.crl.urls).Count -gt 0) { $HealthCoverage['crl_collected'] = $true }
        if (($certHint.config.aia.urls).Count -gt 0) { $HealthCoverage['aia_collected'] = $true }
        if (($certHint.config.ocsp.urls).Count -gt 0) { $HealthCoverage['ocsp_collected'] = $true }
        $config = $certHint.config
        $config['web_enrollment_assessed'] = (-not $SkipHealth)
        $config['ca_policy_flags_assessed'] = (-not $SkipHealth)
        $config['ca_roles_assessed'] = $false
        $config['published_templates'] = @($published)
        $cas += [pscustomobject]@{ name = $caName; dns_name = $dns; status = 'online'; config = $config }
      }
    }
  } catch { Write-Warning "CA discovery failed via certutil: $_" }
  return @($cas)
}

function Get-Templates {
  param([hashtable]$PublishedMap, [hashtable]$HealthCoverage)
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
      $publishedTo = @()
      if ($PublishedMap) { foreach ($caName in $PublishedMap.Keys) { if (@($PublishedMap[$caName]) -contains $o.Name) { $publishedTo += [string]$caName } } }
      $HealthCoverage['template_acl_collected'] = (-not $SkipAcl)
      $templates += [pscustomobject]@{
        name = [string]$o.Name
        display_name = $display
        eku = @($eku)
        enrollee_supplies_subject = (($nameFlag -band 1) -ne 0)
        manager_approval = (($enrollFlag -band 2) -ne 0)
        authorized_signatures = $authSig
        validity_days = 365
        renewal_days = 30
        published_to = @($publishedTo)
        permissions = @([pscustomobject]@{ principal = 'Authenticated Users'; can_enroll = $true; can_autoenroll = $false })
        raw = @{ acl_assessed = (-not $SkipAcl); acl_details = @(); permissions_assessed = $true }
      }
    }
  } catch { Write-Warning "Template enumeration failed: $_" }
  return @($templates)
}

function Parse-CertValue { param([string]$Line) $parts = $Line -split ':',2; if ($parts.Count -lt 2) { return '' }; return $parts[1].Trim() }

function Get-IssuedCertificates {
  param([hashtable]$HealthCoverage)
  $out = @()
  if ($SkipIssued) { $HealthCoverage['issued_certificates_collected'] = $false; $HealthCoverage['issued_certificates_reason'] = 'collector ran with SkipIssued'; return @($out) }
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
    $HealthCoverage['issued_certificates_collected'] = ($out.Count -gt 0)
    if ($out.Count -eq 0) { $HealthCoverage['issued_certificates_reason'] = 'certutil returned zero issued certificate rows' }
  } catch { $HealthCoverage['issued_certificates_collected'] = $false; $HealthCoverage['issued_certificates_reason'] = "certutil issued certificate query failed: $_"; Write-Warning "Issued certificate query failed: $_" }
  if ($out.Count -gt $RecentRequestLimit) { $out = $out | Select-Object -First $RecentRequestLimit }
  return @($out)
}

if (-not $DomainName) { $DomainName = 'unknown.local' }
$assessmentHints = @{ esc6_ca_policy = 'not_assessed'; esc7_ca_roles = 'not_assessed'; esc8_web_enrollment = 'insufficient_data'; esc4_template_acl = 'insufficient_data' }
$healthCoverage = @{ ca_certificate_collected = $false; crl_collected = $false; aia_collected = $false; ocsp_collected = $false; issued_certificates_collected = $false; template_acl_collected = $false; ca_registry_collected = $false }
$publishedMap = Get-PublishedTemplateMap
$cas = @(Get-CertificateAuthorities -PublishedMap $publishedMap -HealthCoverage $healthCoverage)
$templates = @(Get-Templates -PublishedMap $publishedMap -HealthCoverage $healthCoverage)
$issued = @(Get-IssuedCertificates -HealthCoverage $healthCoverage)

$payload = [ordered]@{
  domain_name = $DomainName
  source_host = $env:COMPUTERNAME
  collector_version = $CollectorVersion
  cas = @($cas)
  templates = @($templates)
  issued_certificates = @($issued)
  assessment_hints = $assessmentHints
  health_coverage = $healthCoverage
}

$json = $payload | ConvertTo-Json -Depth 14
if ($DebugPayload) { Write-Host $json }
if ($OutputJson) { $json | Out-File -FilePath $OutputJson -Encoding utf8; Write-Step "Payload written to $OutputJson" }
if ($NoPost) { Write-Step "NoPost selected; collector payload was not sent."; return }
$uri = "$($ApiUrl.TrimEnd('/'))/api/v1/collector/ingest"
Write-Step "Posting payload to $uri"
Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $ApiToken" } -ContentType 'application/json' -Body $json
