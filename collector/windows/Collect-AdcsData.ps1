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
  [switch]$SkipCrl,
  [string[]]$ManualCaConfig,
  [string]$ExtraCaCertPath,
  [string]$ExtraCaCertFolder,
  [string]$OfflineCaMetadataPath,
  [int]$MaxIssuedCertificates = 200,
  [switch]$IncludeRevoked,
  [switch]$SkipTemplateAcl
)

$ErrorActionPreference = 'Stop'
$CollectorVersion = 'collector-ps51-1.8'

function Write-Step { param([string]$Message) Write-Host "[CertShield] $Message" }
function Empty-List { return @() }
function Test-SkipTemplateAcl { return ($SkipAcl -or $SkipTemplateAcl) }

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
  $matches = [regex]::Matches($Text, '(https?://[^\s,;]+|ldap://[^\s,;]+|file://[^\s,;]+)')
  foreach ($m in $matches) { $urls += [string]$m.Value }
  return @($urls | Select-Object -Unique)
}


function Get-RegistryUrls {
  param([string]$ConfigString, [string]$RegPath)
  $urls = @()
  try {
    $lines = certutil -config $ConfigString -getreg $RegPath 2>$null
    foreach ($line in $lines) { $urls += Extract-Urls -Text $line }
  } catch { }
  return @($urls | Select-Object -Unique)
}

function Test-HttpUrl {
  param([string]$Url)
  try {
    $request = [System.Net.WebRequest]::Create($Url)
    $request.Method = 'GET'
    $request.Timeout = 5000
    $response = $request.GetResponse()
    $stream = $response.GetResponseStream()
    $ms = New-Object System.IO.MemoryStream
    $stream.CopyTo($ms)
    $statusCode = $null
    try { $statusCode = [int]$response.StatusCode } catch { }
    $response.Close()
    return @{ ok = $true; reachable = $true; status_code = $statusCode; bytes = $ms.ToArray(); error = $null }
  } catch {
    $statusCode = $null
    $reachable = $false
    try {
      if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
        $reachable = $true
        $_.Exception.Response.Close()
      }
    } catch { }
    return @{ ok = $false; reachable = $reachable; status_code = $statusCode; bytes = $null; error = [string]$_ }
  }
}

function Convert-CertDateText {
  param([string]$Value)
  if (-not $Value) { return $null }
  try { return ([datetime]$Value).ToString('yyyy-MM-ddTHH:mm:ss') } catch { return $Value }
}

function Test-TruncatedConfigString {
  param([string]$ConfigString)
  return ($ConfigString -match '\.\.\.')
}

function New-CertificateFromBytes {
  param([byte[]]$Bytes)
  if (-not $Bytes) { return $null }
  try { return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$Bytes) } catch { return $null }
}

function New-CertificateFromPath {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
  try { return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path) } catch { return $null }
}

function Find-LocalCaCertificate {
  param([string]$CaName, [string]$DnsName)
  $stores = @('Cert:\LocalMachine\CA','Cert:\LocalMachine\Root','Cert:\LocalMachine\My')
  foreach ($store in $stores) {
    try {
      foreach ($cert in Get-ChildItem -Path $store -ErrorAction SilentlyContinue) {
        if (($CaName -and $cert.Subject -like "*$CaName*") -or ($DnsName -and $cert.Subject -like "*$DnsName*")) { return $cert }
      }
    } catch { }
  }
  return $null
}

function Get-EnrollmentServiceRecords {
  $records = @()
  if (-not (Test-ADModule)) { return @($records) }
  try {
    $root = Get-ADRootDSE
    $base = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($root.configurationNamingContext)"
    $props = 'certificateTemplates','dNSHostName','cACertificate','cn'
    $services = Get-ADObject -Filter * -SearchBase $base -Properties $props
    foreach ($svc in $services) {
      $templates = @(); if ($svc.certificateTemplates) { $templates = @($svc.certificateTemplates) }
      $certBytes = $null
      if ($svc.cACertificate) {
        if ($svc.cACertificate -is [byte[]]) { $certBytes = [byte[]]$svc.cACertificate }
        elseif ($svc.cACertificate[0] -is [byte[]]) { $certBytes = [byte[]]$svc.cACertificate[0] }
        else { try { $certBytes = [byte[]]$svc.cACertificate } catch { $certBytes = $null } }
      }
      if ($svc.Name -eq 'Enrollment Services' -and -not $certBytes) {
        Write-Warning 'Skipping Enrollment Services container noise because it has no CA certificate.'
        continue
      }
      $dns = [string]$svc.dNSHostName
      $configString = $null
      if ($dns -and $svc.Name) { $configString = "$dns\$($svc.Name)" }
      $records += [pscustomobject]@{
        name = [string]$svc.Name
        dns_name = $dns
        config_string = $configString
        published_templates = @($templates)
        ca_certificate_der = $certBytes
        discovery_source = 'AD Enrollment Services'
      }
    }
  } catch { Write-Warning "AD Enrollment Services discovery unavailable: $_" }
  return @($records)
}

function Get-DaysRemaining {
  param([string]$Value)
  if (-not $Value) { return $null }
  try { return [int](([datetime]$Value) - (Get-Date)).TotalDays } catch { return $null }
}

function Normalize-ExtensionText {
  param([string]$Value)
  if (-not $Value) { return $null }
  return (($Value -replace '\r?\n', ' ') -replace '\s+', ' ').Trim()
}

function Get-CrlFreshness {
  param([string[]]$Urls)
  $tested = @(); $errors = @(); $thisUpdate = $null; $nextUpdate = $null; $reachable = $null
  foreach ($url in $Urls) {
    if ($url -notmatch '^https?://') { continue }
    $tested += $url
    $result = Test-HttpUrl -Url $url
    if ($result.ok) {
      $reachable = $true
      $tmp = [System.IO.Path]::GetTempFileName()
      try {
        [System.IO.File]::WriteAllBytes($tmp, $result.bytes)
        $crl = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $dump = certutil -dump $tmp 2>$null
        foreach ($line in $dump) {
          if ($line -match 'ThisUpdate:\s*(.+)$') { $thisUpdate = Convert-CertDateText -Value $matches[1].Trim() }
          if ($line -match 'NextUpdate:\s*(.+)$') { $nextUpdate = Convert-CertDateText -Value $matches[1].Trim() }
        }
      } catch { $errors += "CRL parse failed for $($url): $_" } finally { Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue }
      break
    } else { $reachable = $result.reachable; $errors += "$url : $($result.error)" }
  }
  return @{ reachable = $reachable; tested_urls = @($tested); errors = @($errors); this_update = $thisUpdate; next_update = $nextUpdate; days_remaining = (Get-DaysRemaining -Value $nextUpdate) }
}

function Get-KeyProtectionHint {
  param([string]$ConfigString)
  $provider = $null; $providerType = $null; $keyContainer = $null; $evidence = @()
  if (-not $ConfigString) {
    return @{ provider = $null; crypto_provider = $null; provider_type = 'not_assessed'; key_storage_provider = $null; key_container = $null; storage = 'not_assessed'; hsm_detected = 'unknown'; evidence = @('CA config string not available') }
  }
  try {
    $lines = certutil -config $ConfigString -getreg CA\CSP 2>$null
    foreach ($line in $lines) {
      $evidence += [string]$line
      if ($line -match 'Provider\s*=\s*(.+)$') { $provider = $matches[1].Trim() }
      elseif ($line -match 'ProviderName\s*=\s*(.+)$') { $provider = $matches[1].Trim() }
      elseif ($line -match 'ProviderType\s*=\s*(.+)$') { $providerType = $matches[1].Trim() }
      elseif ($line -match 'Provider Type\s*=\s*(.+)$') { $providerType = $matches[1].Trim() }
      elseif ($line -match 'KeyContainer\s*=\s*(.+)$') { $keyContainer = $matches[1].Trim() }
      elseif ($line -match 'Key Container\s*=\s*(.+)$') { $keyContainer = $matches[1].Trim() }
    }
  } catch { $evidence += "CSP query failed: $_" }
  $storage = 'not_assessed'; $hsm = 'unknown'
  if ($provider) {
    $p = $provider.ToLowerInvariant()
    if ($p -match 'thales|safenet|luna|ncipher|nshield|entrust|utimaco|fortanix|azure key vault|keycontrol|aws cloudhsm|google cloud kms|hsm') { $storage = 'hsm'; $hsm = $true }
    elseif ($p -match 'microsoft software|microsoft enhanced|microsoft strong|software') { $storage = 'software'; $hsm = $false }
    else { $storage = 'unknown_provider'; $hsm = 'unknown' }
  }
  $resolvedProviderType = $providerType
  if (-not $resolvedProviderType) { $resolvedProviderType = $storage }
  return @{ provider = $provider; crypto_provider = $provider; key_storage_provider = $provider; provider_type = $resolvedProviderType; key_container = $keyContainer; storage = $storage; hsm_detected = $hsm; evidence = @($evidence) }
}
function Get-AuditHint {
  param([string]$ConfigString)
  $evidence = @(); $auditFilter = $null
  if (-not $ConfigString) { return @{ auditing_enabled = $null; audit_filter = $null; evidence = @('CA config string not available') } }
  try {
    $lines = certutil -config $ConfigString -getreg CA\AuditFilter 2>$null
    foreach ($line in $lines) {
      $evidence += [string]$line
      if ($line -match 'AuditFilter\s*=\s*(\d+)') { $auditFilter = [int]$matches[1] }
      elseif ($line -match 'AuditFilter.*REG_DWORD\s*=\s*(\d+)') { $auditFilter = [int]$matches[1] }
    }
  } catch { $evidence += "AuditFilter query failed: $_" }
  $enabled = $null
  if ($auditFilter -ne $null) { $enabled = ($auditFilter -ne 0) }
  return @{ auditing_enabled = $enabled; audit_filter = $auditFilter; evidence = @($evidence) }
}

function Get-CaCertificateHints {
  param([string]$ConfigString, [byte[]]$AdCaCertificate, [string]$CaName, [string]$DnsName, [string]$ExtraCaCertPath, [string]$ExtraCaCertFolder)
  $hint = @{
    ca_certificate_collected = $false
    config = @{
      certificate_collected = $false
      certificate_collection_reason = 'not available from current collector'
      ca_certificate = @{ collected = $false; error = 'not available from current collector' }
      crl = @{ assessed = $false; configured = $null; reachable = $null; urls = @(); next_update = $null; source = 'not collected'; reason = 'collector did not collect CRL evidence yet' }
      aia = @{ assessed = $false; configured = $null; reachable = $null; urls = @(); source = 'not collected'; reason = 'collector did not collect AIA evidence yet' }
      ocsp = @{ assessed = $false; configured = $null; reachable = $null; urls = @(); responder_status = 'not_assessed'; reason = 'collector did not collect OCSP evidence yet' }
    }
  }
  if ($SkipHealth) { return $hint }
  $tmp = [System.IO.Path]::GetTempFileName()
  try {
    $cert = $null
    if ($ConfigString -and -not (Test-TruncatedConfigString -ConfigString $ConfigString)) {
      try { certutil -config $ConfigString -ca.cert $tmp 2>$null | Out-Null; $cert = New-CertificateFromPath -Path $tmp } catch { }
    } elseif ($ConfigString) { Write-Warning "Rejected truncated CA config string: $ConfigString" }
    if (-not $cert -and $AdCaCertificate) { $cert = New-CertificateFromBytes -Bytes $AdCaCertificate }
    if (-not $cert) { $cert = Find-LocalCaCertificate -CaName $CaName -DnsName $DnsName }
    if (-not $cert -and $ExtraCaCertPath) { $cert = New-CertificateFromPath -Path $ExtraCaCertPath }
    if (-not $cert -and $ExtraCaCertFolder -and (Test-Path -LiteralPath $ExtraCaCertFolder)) {
      foreach ($candidate in Get-ChildItem -Path $ExtraCaCertFolder -File -ErrorAction SilentlyContinue) {
        $cert = New-CertificateFromPath -Path $candidate.FullName
        if ($cert) { break }
      }
    }
    if (-not $cert) { throw 'CA certificate could not be collected via certutil, AD cACertificate, local stores, or extra certificate path.' }
    $hint.ca_certificate_collected = $true
    $hint.config.certificate_collected = $true
    $subjectKeyIdentifier = $null
    $authorityKeyIdentifier = $null
    $publicKeyAlgorithm = $cert.PublicKey.Oid.FriendlyName
    $keySize = $null
    try { $keySize = $cert.PublicKey.Key.KeySize } catch { $keySize = $null }
    $isSelfSigned = ($cert.Subject -eq $cert.Issuer)
    $caRoleHint = 'issuing'
    if ($isSelfSigned) { $caRoleHint = 'root' }
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
      elseif ($ext.Oid.Value -eq '2.5.29.14') { $subjectKeyIdentifier = Normalize-ExtensionText -Value $formatted }
      elseif ($ext.Oid.Value -eq '2.5.29.35') { $authorityKeyIdentifier = Normalize-ExtensionText -Value $formatted }
    }
    $hint.config.ca_certificate = @{ collected = $true; subject = $cert.Subject; issuer = $cert.Issuer; serial_number = $cert.SerialNumber; thumbprint = $cert.Thumbprint; not_before = $cert.NotBefore.ToString('yyyy-MM-ddTHH:mm:ss'); not_after = $cert.NotAfter.ToString('yyyy-MM-ddTHH:mm:ss'); signature_algorithm = $cert.SignatureAlgorithm.FriendlyName; public_key_algorithm = $publicKeyAlgorithm; key_size = $keySize; subject_key_identifier = $subjectKeyIdentifier; authority_key_identifier = $authorityKeyIdentifier; is_self_signed = $isSelfSigned; ca_role_hint = $caRoleHint; chain_complete = $null }
    $hint.config.certificate_expires_at = $cert.NotAfter.ToString('yyyy-MM-ddTHH:mm:ss')
    $hint.config.certificate_subject = $cert.Subject
    $hint.config.certificate_issuer = $cert.Issuer
    $hint.config.signature_algorithm = $cert.SignatureAlgorithm.FriendlyName
    $hint.config.public_key_algorithm = $publicKeyAlgorithm
    $hint.config.key_size = $keySize
    $hint.config.subject_key_identifier = $subjectKeyIdentifier
    $hint.config.authority_key_identifier = $authorityKeyIdentifier
    $hint.config.ca_role_hint = $caRoleHint
    $crlUrls += Get-RegistryUrls -ConfigString $ConfigString -RegPath 'CA\CRLPublicationURLs'
    $aiaUrls += Get-RegistryUrls -ConfigString $ConfigString -RegPath 'CA\CACertPublicationURLs'
    $crlUrls = @($crlUrls | Select-Object -Unique)
    $aiaUrls = @($aiaUrls | Select-Object -Unique)
    $ocspUrls = @($ocspUrls | Select-Object -Unique)
    $crlHttp = @($crlUrls | Where-Object { $_ -match '^https?://' })
    $crlLdap = @($crlUrls | Where-Object { $_ -match '^ldap://' })
    $crlFile = @($crlUrls | Where-Object { $_ -match '^file://' })
    $aiaHttp = @($aiaUrls | Where-Object { $_ -match '^https?://' })
    $aiaLdap = @($aiaUrls | Where-Object { $_ -match '^ldap://' })
    $crlFresh = Get-CrlFreshness -Urls $crlHttp
    if (-not $SkipCrl) {
      $crlReason = 'CRL/CDP URLs extracted from CA certificate and registry; HTTP CRL fetch attempted when HTTP URLs were present.'
      if ($crlUrls.Count -eq 0) { $crlReason = 'No CRL/CDP URL was extracted from the CA certificate or registry.' }
      elseif ($crlHttp.Count -eq 0) { $crlReason = 'Only non-HTTP CRL/CDP URLs were found; LDAP reachability is recorded as not tested by this collector.' }
      $hint.config.crl = @{ assessed = $true; configured = ($crlUrls.Count -gt 0); reachable = $crlFresh.reachable; urls = @($crlUrls); http_urls = @($crlHttp); ldap_urls = @($crlLdap); file_urls = @($crlFile); this_update = $crlFresh.this_update; next_update = $crlFresh.next_update; days_remaining = $crlFresh.days_remaining; tested_urls = @($crlFresh.tested_urls); errors = @($crlFresh.errors); source = 'ca certificate CDP extension and CA registry'; reason = $crlReason }
    }
    $aiaReachable = $null; $aiaTested = @(); $aiaErrors = @()
    foreach ($url in $aiaHttp) {
      $aiaTested += $url
      $r = Test-HttpUrl -Url $url
      if ($r.reachable) { $aiaReachable = $true; break } else { $aiaReachable = $false; $aiaErrors += "$url : $($r.error)" }
    }
    $aiaReason = 'AIA URLs extracted from CA certificate and registry; HTTP AIA reachability attempted when HTTP URLs were present.'
    if ($aiaUrls.Count -eq 0) { $aiaReason = 'No AIA CA issuer URL was extracted from the CA certificate or registry.' }
    elseif ($aiaHttp.Count -eq 0) { $aiaReason = 'Only non-HTTP AIA URLs were found; LDAP reachability is recorded as not tested by this collector.' }
    $hint.config.aia = @{ assessed = $true; configured = ($aiaUrls.Count -gt 0); reachable = $aiaReachable; urls = @($aiaUrls); ca_issuer_urls = @($aiaUrls); ocsp_urls = @($ocspUrls); tested_urls = @($aiaTested); errors = @($aiaErrors); source = 'ca certificate AIA extension and CA registry'; reason = $aiaReason }
    $ocspReachable = $null; $ocspTested = @(); $ocspErrors = @()
    foreach ($url in @($ocspUrls | Where-Object { $_ -match '^https?://' })) {
      $ocspTested += $url
      $r = Test-HttpUrl -Url $url
      if ($r.reachable) { $ocspReachable = $true; break } else { $ocspReachable = $false; $ocspErrors += "$url : $($r.error)" }
    }
    $ocspReason = 'No OCSP URL was present in the CA certificate AIA extension.'
    if ($ocspUrls.Count -gt 0) { $ocspReason = 'OCSP URLs extracted from AIA; HTTP endpoint reachability was probed without sending OCSP requests.' }
    $hint.config.ocsp = @{ assessed = $true; configured = ($ocspUrls.Count -gt 0); reachable = $ocspReachable; urls = @($ocspUrls); tested_urls = @($ocspTested); status = 'not_tested'; errors = @($ocspErrors); reason = $ocspReason; source = 'ca certificate AIA extension' }
    $hint.config.key_protection = Get-KeyProtectionHint -ConfigString $ConfigString
    $auditHint = Get-AuditHint -ConfigString $ConfigString
    $hint.config.auditing_enabled = $auditHint.auditing_enabled
    $hint.config.audit = $auditHint
    $validityPeriod = Get-CaRegistryValue -ConfigString $ConfigString -RegPath 'CA\ValidityPeriod'
    $validityUnits = Get-CaRegistryValue -ConfigString $ConfigString -RegPath 'CA\ValidityPeriodUnits'
    $policyModules = Get-CaRegistryValue -ConfigString $ConfigString -RegPath 'PolicyModules'
    $exitModules = Get-CaRegistryValue -ConfigString $ConfigString -RegPath 'ExitModules'
    $hint.config.ca_registry = @{ validity_period = $validityPeriod.value; validity_period_units = $validityUnits.value; policy_modules = $policyModules.value; exit_modules = $exitModules.value; evidence = @($validityPeriod.evidence + $validityUnits.evidence + $policyModules.evidence + $exitModules.evidence) }
  } catch {
    $hint.config.certificate_collection_reason = "CA certificate collection failed: $_"
    $hint.config.ca_certificate = @{ collected = $false; error = "CA certificate collection failed: $_" }
  } finally {
    Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
  }
  return $hint
}

function Get-PublishedTemplateMap {
  param([object[]]$EnrollmentServices)
  $map = @{}
  foreach ($svc in @($EnrollmentServices)) { $map[[string]$svc.name] = @($svc.published_templates) }
  return $map
}


function Convert-ADIntervalToDays {
  param($Value)
  if ($null -eq $Value) { return $null }
  try {
    $ticks = $null
    if ($Value -is [byte[]]) { $ticks = [BitConverter]::ToInt64([byte[]]$Value, 0) }
    elseif ($Value.PSObject.Properties['HighPart'] -and $Value.PSObject.Properties['LowPart']) {
      $ticks = ([int64]$Value.HighPart -shl 32) -bor ([uint32]$Value.LowPart)
    } else { $ticks = [int64]$Value }
    if ($ticks -eq 0) { return $null }
    return [int]([math]::Round([math]::Abs($ticks) / 864000000000))
  } catch { return $null }
}

function Convert-EkuOidToName {
  param([string]$Oid)
  $map = @{
    '1.3.6.1.5.5.7.3.2' = 'Client Authentication'
    '1.3.6.1.5.5.7.3.1' = 'Server Authentication'
    '1.3.6.1.4.1.311.20.2.2' = 'Smart Card Logon'
    '1.3.6.1.4.1.311.20.2.1' = 'Certificate Request Agent'
    '2.5.29.37.0' = 'Any Purpose'
  }
  if ($map.ContainsKey($Oid)) { return "$($map[$Oid]) ($Oid)" }
  return $Oid
}

function Test-BroadPrincipal {
  param([string]$Principal)
  if (-not $Principal) { return $false }
  $leaf = ($Principal -split '\\')[-1].ToLowerInvariant()
  return @('authenticated users','domain users','everyone','domain computers') -contains $leaf
}

function Convert-TemplateAcl {
  param($SecurityDescriptor, [string]$TemplateName)
  $permissions = @(); $aclDetails = @(); $owner = $null
  $enrollGuid = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
  $autoEnrollGuid = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
  try {
    if ($null -eq $SecurityDescriptor) { throw 'nTSecurityDescriptor was not returned by Active Directory' }
    try { $owner = $SecurityDescriptor.GetOwner([System.Security.Principal.NTAccount]).Value } catch { $owner = $null }
    $rules = $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
      if ($rule.AccessControlType -ne 'Allow') { continue }
      $sid = [string]$rule.IdentityReference.Value
      $principal = $sid
      try { $principal = $rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { }
      $rightsText = [string]$rule.ActiveDirectoryRights
      $rights = @($rightsText -split ',\s*')
      $canEnroll = (($rule.ObjectType -eq $enrollGuid) -or ($rightsText -match 'GenericAll'))
      $canAutoEnroll = (($rule.ObjectType -eq $autoEnrollGuid) -or ($rightsText -match 'GenericAll'))
      $genericAll = ($rightsText -match 'GenericAll')
      $writeDacl = ($rightsText -match 'WriteDacl')
      $writeOwner = ($rightsText -match 'WriteOwner')
      $writeProperty = ($rightsText -match 'WriteProperty')
      if ($canEnroll -or $canAutoEnroll -or $genericAll -or $writeDacl -or $writeOwner -or $writeProperty) {
        $entry = [ordered]@{
          principal = $principal; sid = $sid; rights = @($rights); can_enroll = [bool]$canEnroll; can_autoenroll = [bool]$canAutoEnroll;
          generic_all = [bool]$genericAll; write_dacl = [bool]$writeDacl; write_owner = [bool]$writeOwner; write_property = [bool]$writeProperty;
          owner = $owner; is_broad_principal = (Test-BroadPrincipal -Principal $principal)
        }
        $permissions += [pscustomobject]$entry
        $aclDetails += [pscustomobject]$entry
      }
    }
    return @{ permissions_assessed = $true; acl_collection_reason = 'nTSecurityDescriptor parsed from Active Directory'; permissions = @($permissions); acl_details = @($aclDetails); owner = $owner }
  } catch {
    return @{ permissions_assessed = $false; acl_collection_reason = "Template ACL collection failed for $($TemplateName): $_"; permissions = @(); acl_details = @(); owner = $owner }
  }
}

function Get-OfflineCaMetadata {
  param([string]$Path)
  if (-not $Path) { return @{} }
  if (-not (Test-Path -LiteralPath $Path)) { Write-Warning "Offline CA metadata file not found: $Path"; return @{} }
  try {
    $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $map = @{}
    foreach ($prop in $json.PSObject.Properties) { $map[$prop.Name] = $prop.Value }
    return $map
  } catch { Write-Warning "Offline CA metadata could not be parsed: $_"; return @{} }
}

function Merge-OfflineCaMetadata {
  param([hashtable]$Config, $Metadata)
  if ($null -eq $Metadata) { return $Config }
  foreach ($prop in $Metadata.PSObject.Properties) {
    if ($prop.Name -eq 'key_protection' -and $prop.Value) {
      $kp = @{}
      foreach ($kpProp in $prop.Value.PSObject.Properties) { $kp[$kpProp.Name] = $kpProp.Value }
      $Config['key_protection'] = $kp
    } else { $Config[$prop.Name] = $prop.Value }
  }
  $Config['offline_metadata_supplied'] = $true
  $Config['offline_metadata_source'] = $OfflineCaMetadataPath
  return $Config
}

function Get-CaRegistryValue {
  param([string]$ConfigString, [string]$RegPath)
  $evidence = @(); $value = $null
  if (-not $ConfigString) { return @{ value = $null; evidence = @('CA config string not available') } }
  try {
    $lines = certutil -config $ConfigString -getreg $RegPath 2>$null
    foreach ($line in $lines) {
      $evidence += [string]$line
      if ($line -match '=\s*(.+)$') { $value = $matches[1].Trim() }
    }
  } catch { $evidence += "$RegPath query failed: $_" }
  return @{ value = $value; evidence = @($evidence) }
}
function Get-CertificateAuthorities {
  param([hashtable]$PublishedMap, [hashtable]$HealthCoverage, [object[]]$EnrollmentServices)
  $cas = @()
  $records = @($EnrollmentServices)
  foreach ($manual in @($ManualCaConfig)) {
    if (-not $manual) { continue }
    if (Test-TruncatedConfigString -ConfigString $manual) { Write-Warning "Rejected truncated manual CA config string: $manual"; continue }
    $parts = $manual -split '\\',2
    if ($parts.Count -eq 2) {
      $records += [pscustomobject]@{ name=$parts[1]; dns_name=$parts[0]; config_string=$manual; published_templates=@(); ca_certificate_der=$null; discovery_source='ManualCaConfig' }
    }
  }
  if ($records.Count -eq 0) {
    try {
      $lines = certutil -config - -ping 2>$null
      foreach ($line in $lines) {
        if ($line -match '^Connecting to (.+)\\(.+)$') {
          $configString = "$($matches[1])\$($matches[2])"
          if (Test-TruncatedConfigString -ConfigString $configString) { Write-Warning "Rejected truncated certutil discovery config: $configString"; continue }
          $records += [pscustomobject]@{ name=$matches[2]; dns_name=$matches[1]; config_string=$configString; published_templates=@(); ca_certificate_der=$null; discovery_source='certutil fallback' }
        }
      }
    } catch { Write-Warning "CA discovery failed via certutil fallback: $_" }
  }
  foreach ($record in @($records)) {
    $caName = [string]$record.name
    $dns = [string]$record.dns_name
    $configString = [string]$record.config_string
    if (-not $caName -or ($caName -eq 'Enrollment Services' -and -not $record.ca_certificate_der)) { continue }
    if ($configString -and (Test-TruncatedConfigString -ConfigString $configString)) { Write-Warning "Rejected truncated CA config string: $configString"; continue }
    $published = @($record.published_templates)
    if (-not $published -and $PublishedMap -and $PublishedMap.ContainsKey($caName)) { $published = @($PublishedMap[$caName]) }
    $certHint = Get-CaCertificateHints -ConfigString $configString -AdCaCertificate $record.ca_certificate_der -CaName $caName -DnsName $dns -ExtraCaCertPath $ExtraCaCertPath -ExtraCaCertFolder $ExtraCaCertFolder
    if (-not $certHint.ca_certificate_collected -and $record.discovery_source -eq 'AD Enrollment Services' -and $caName -eq 'Enrollment Services') { continue }
    if ($certHint.ca_certificate_collected) { $HealthCoverage['ca_certificate_collected'] = $true }
    if (-not $SkipHealth -and $configString) { $HealthCoverage['ca_registry_collected'] = $true }
    if (($certHint.config.crl.urls).Count -gt 0) { $HealthCoverage['crl_collected'] = $true }
    if (($certHint.config.aia.urls).Count -gt 0) { $HealthCoverage['aia_collected'] = $true }
    if (($certHint.config.ocsp.urls).Count -gt 0) { $HealthCoverage['ocsp_collected'] = $true }
    if ($certHint.config.key_protection.provider) { $HealthCoverage['key_protection_collected'] = $true }
    $config = $certHint.config
    $config['web_enrollment_assessed'] = (-not $SkipHealth)
    $config['ca_policy_flags_assessed'] = (-not $SkipHealth)
    $config['ca_roles_assessed'] = $false
    $config['published_templates'] = @($published)
    $config['config_string'] = $configString
    $config['source_host'] = $env:COMPUTERNAME
    $config['discovery_source'] = [string]$record.discovery_source
    if ($offlineMetadata.ContainsKey($caName)) {
      $config = Merge-OfflineCaMetadata -Config $config -Metadata $offlineMetadata[$caName]
      $HealthCoverage['key_protection_collected'] = $true
      $HealthCoverage['audit_collected'] = $true
    }
    if ($config.audit -and $config.audit.audit_filter -ne $null) { $HealthCoverage['audit_collected'] = $true }
    $status = 'online'; if (-not $configString) { $status = 'not_assessed' }
    $cas += [pscustomobject]@{ name = $caName; dns_name = $dns; status = $status; config = $config }
  }
  return @($cas)
}

function Get-Templates {
  param([hashtable]$PublishedMap, [hashtable]$HealthCoverage)
  $templates = @()
  if (-not (Test-ADModule)) { return @($templates) }
  try {
    $root = Get-ADRootDSE
    $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($root.configurationNamingContext)"
    $props = @(
      'displayName','pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy','msPKI-Certificate-Name-Flag',
      'msPKI-Enrollment-Flag','msPKI-Private-Key-Flag','msPKI-RA-Signature','msPKI-RA-Application-Policies',
      'msPKI-RA-Policies','msPKI-Template-Schema-Version','pKIExpirationPeriod','pKIOverlapPeriod','flags',
      'revision','whenChanged','nTSecurityDescriptor'
    )
    $objs = Get-ADObject -Filter * -SearchBase $base -Properties $props -SecurityMask Dacl,Owner
    $aclCollected = $false
    foreach ($o in $objs) {
      $nameFlag = 0; if ($o.'msPKI-Certificate-Name-Flag') { $nameFlag = [int]$o.'msPKI-Certificate-Name-Flag' }
      $enrollFlag = 0; if ($o.'msPKI-Enrollment-Flag') { $enrollFlag = [int]$o.'msPKI-Enrollment-Flag' }
      $privateKeyFlag = 0; if ($o.'msPKI-Private-Key-Flag') { $privateKeyFlag = [int]$o.'msPKI-Private-Key-Flag' }
      $authSig = 0; if ($o.'msPKI-RA-Signature') { $authSig = [int]$o.'msPKI-RA-Signature' }
      $ekuOids = @()
      if ($o.'pKIExtendedKeyUsage') { $ekuOids += @($o.'pKIExtendedKeyUsage') }
      if ($o.'msPKI-Certificate-Application-Policy') { $ekuOids += @($o.'msPKI-Certificate-Application-Policy') }
      $ekuOids = @($ekuOids | Where-Object { $_ } | Select-Object -Unique)
      $eku = @(); foreach ($oid in $ekuOids) { $eku += Convert-EkuOidToName -Oid ([string]$oid) }
      $display = $o.Name; if ($o.displayName) { $display = [string]$o.displayName }
      $publishedTo = @()
      if ($PublishedMap) { foreach ($caName in $PublishedMap.Keys) { if (@($PublishedMap[$caName]) -contains $o.Name) { $publishedTo += [string]$caName } } }
      $validityDays = Convert-ADIntervalToDays -Value $o.'pKIExpirationPeriod'
      $renewalDays = Convert-ADIntervalToDays -Value $o.'pKIOverlapPeriod'
      $acl = @{ permissions_assessed = $false; acl_collection_reason = 'Template ACL collection skipped'; permissions = @(); acl_details = @(); owner = $null }
      if (-not (Test-SkipTemplateAcl)) { $acl = Convert-TemplateAcl -SecurityDescriptor $o.nTSecurityDescriptor -TemplateName $o.Name }
      if ($acl.permissions_assessed) { $aclCollected = $true }
      $validityOut = 0; if ($validityDays -ne $null) { $validityOut = $validityDays }
      $renewalOut = 0; if ($renewalDays -ne $null) { $renewalOut = $renewalDays }
      $templates += [pscustomobject]@{
        name = [string]$o.Name
        display_name = $display
        eku = @($eku)
        enrollee_supplies_subject = (($nameFlag -band 1) -ne 0 -or ($nameFlag -band 65536) -ne 0)
        manager_approval = (($enrollFlag -band 2) -ne 0)
        authorized_signatures = $authSig
        validity_days = $validityOut
        renewal_days = $renewalOut
        published_to = @($publishedTo)
        permissions = @($acl.permissions)
        raw = @{
          permissions_assessed = [bool]$acl.permissions_assessed
          acl_assessed = [bool]$acl.permissions_assessed
          acl_collection_reason = $acl.acl_collection_reason
          acl_details = @($acl.acl_details)
          owner = $acl.owner
          validity_days_assessed = ($validityDays -ne $null)
          renewal_days_assessed = ($renewalDays -ne $null)
          pKIExpirationPeriod = $o.'pKIExpirationPeriod'
          pKIOverlapPeriod = $o.'pKIOverlapPeriod'
          eku_oids = @($ekuOids)
          name_flags = $nameFlag
          enrollment_flags = $enrollFlag
          private_key_flags = $privateKeyFlag
          private_key_exportable = (($privateKeyFlag -band 16) -ne 0)
          ra_signature = $authSig
          ra_application_policies = @($o.'msPKI-RA-Application-Policies')
          ra_policies = @($o.'msPKI-RA-Policies')
          template_schema_version = $o.'msPKI-Template-Schema-Version'
          flags = $o.flags
          revision = $o.revision
          when_changed = $o.whenChanged
          client_authentication = ((@($eku) -join ' ') -match 'Client Authentication|Smart Card Logon')
          any_purpose = ((@($eku) -join ' ') -match 'Any Purpose')
        }
      }
    }
    $HealthCoverage['template_acl_collected'] = [bool]$aclCollected
    if ((Test-SkipTemplateAcl)) { $HealthCoverage['template_acl_reason'] = 'collector ran with SkipAcl or SkipTemplateAcl' }
    elseif (-not $aclCollected) { $HealthCoverage['template_acl_reason'] = 'No template ACLs were readable from Active Directory' }
  } catch { Write-Warning "Template enumeration failed: $_" }
  return @($templates)
}
function Parse-CertValue { param([string]$Line) $parts = $Line -split ':',2; if ($parts.Count -lt 2) { return '' }; return $parts[1].Trim() }

function Get-IssuedCertificates {
  param([hashtable]$HealthCoverage, [object[]]$Cas)
  $out = @()
  $queried = @()
  if ($SkipIssued) {
    $HealthCoverage['issued_certificates_collected'] = $false
    $HealthCoverage['issued_certificates_reason'] = 'collector ran with SkipIssued'
    $HealthCoverage['issued_certificates_count'] = 0
    return @($out)
  }
  try {
    foreach ($ca in $Cas) {
      $configString = $null
      try { $configString = [string]$ca.config.config_string } catch { }
      if (-not $configString) { continue }
      $queried += $configString
      $restrict = "Disposition=20"
      if ($IncludeRevoked) { $restrict = "Disposition>=20" }
      $lines = certutil -config $configString -view -restrict $restrict -out "RequestID,RequesterName,CertificateTemplate,CommonName,NotBefore,NotAfter,SerialNumber,CertificateHash,RequestAttributes,Disposition,DispositionMessage" 2>$null
      $cur = @{}
      foreach ($line in $lines) {
        if ($line -match '^\s*Request\s*ID:\s*(.+)$') {
          if ($cur.ContainsKey('request_id')) { $out += [pscustomobject]$cur; $cur = @{} }
          $cur = @{ request_id=$matches[1].Trim(); requester=''; template_name=''; subject=''; san=''; issued_at=''; expires_at=''; status='issued'; serial_number=''; certificate_hash=''; request_attributes=''; disposition=''; disposition_message='' }
        } elseif ($line -match '^\s*Requester\s*Name:') { $cur['requester'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*Certificate\s*Template:') { $cur['template_name'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*(Issued\s*)?Common\s*Name:') { $cur['subject'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*(Certificate\s*)?(Effective\s*Date|NotBefore):') { $cur['issued_at'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*(Certificate\s*)?(Expiration\s*Date|NotAfter):') { $cur['expires_at'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*Serial\s*Number:') { $cur['serial_number'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*Certificate\s*Hash:') { $cur['certificate_hash'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*Request\s*Attributes:') { $cur['request_attributes'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*Disposition:') { $cur['disposition'] = Parse-CertValue -Line $line }
        elseif ($line -match '^\s*Disposition\s*Message:') { $cur['disposition_message'] = Parse-CertValue -Line $line }
      }
      if ($cur.ContainsKey('request_id')) { $out += [pscustomobject]$cur }
    }
    if ($queried.Count -eq 0) { throw 'No CA config strings were available for certutil -view.' }
    $HealthCoverage['issued_certificates_collected'] = $true
    $HealthCoverage['issued_certificates_count'] = $out.Count
    $HealthCoverage['issued_certificates_queried_cas'] = @($queried)
    $HealthCoverage['issued_certificates_query'] = 'certutil -config <CAHost\CAName> -view -restrict Disposition=20 (or Disposition>=20 with IncludeRevoked)'
    if ($out.Count -eq 0) { $HealthCoverage['issued_certificates_reason'] = 'certutil queried CA database successfully but returned zero issued certificate rows' }
    else { $HealthCoverage['issued_certificates_reason'] = 'certutil issued certificate rows parsed successfully' }
  } catch {
    $HealthCoverage['issued_certificates_collected'] = $false
    $HealthCoverage['issued_certificates_count'] = 0
    $HealthCoverage['issued_certificates_error'] = "certutil issued certificate query failed: $_"
    $HealthCoverage['issued_certificates_reason'] = "certutil issued certificate query failed. Run from a host/account that can read the CA database. Error: $_"
    $HealthCoverage['issued_certificates_queried_cas'] = @($queried)
    Write-Warning "Issued certificate query failed: $_"
  }
  if ($MaxIssuedCertificates -gt 0 -and $out.Count -gt $MaxIssuedCertificates) { $out = $out | Select-Object -First $MaxIssuedCertificates }
  return @($out)
}

if (-not $DomainName) { $DomainName = 'unknown.local' }
$assessmentHints = @{ esc6_ca_policy = 'not_assessed'; esc7_ca_roles = 'not_assessed'; esc8_web_enrollment = 'insufficient_data'; esc4_template_acl = 'insufficient_data' }
$healthCoverage = @{ ca_certificate_collected = $false; crl_collected = $false; aia_collected = $false; ocsp_collected = $false; issued_certificates_collected = $false; template_acl_collected = $false; ca_registry_collected = $false; key_protection_collected = $false; audit_collected = $false }
$offlineMetadata = Get-OfflineCaMetadata -Path $OfflineCaMetadataPath
$enrollmentServices = @(Get-EnrollmentServiceRecords)
$publishedMap = Get-PublishedTemplateMap -EnrollmentServices $enrollmentServices
$cas = @(Get-CertificateAuthorities -PublishedMap $publishedMap -HealthCoverage $healthCoverage -EnrollmentServices $enrollmentServices)
$templates = @(Get-Templates -PublishedMap $publishedMap -HealthCoverage $healthCoverage)
$issued = @(Get-IssuedCertificates -HealthCoverage $healthCoverage -Cas $cas)

$payload = [ordered]@{
  collector_type = 'adcs'
  schema_version = '1.2'
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
