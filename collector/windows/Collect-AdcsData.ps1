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
  [string]$EnvironmentName,
  [string]$EnvironmentKey,
  [string]$PkiLabel,
  [ValidateSet('full','incremental','partial')]
  [string]$CollectionMode = 'full',
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
$CollectorVersion = 'collector-ps51-1.8.5-esc5-esc7-tier0'

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

function Convert-RegistryNumber {
  param([string]$Value)

  if (-not $Value) {
    return $null
  }

  $text = $Value.Trim()

  # certutil commonly returns:
  # 7f (127)
  # 0x7f
  # 127
  if ($text -match '\((\d+)\)\s*$') {
    return [int64]$matches[1]
  }

  if ($text -match '0x([0-9a-fA-F]+)') {
    return [Convert]::ToInt64($matches[1], 16)
  }

  if ($text -match '^([0-9a-fA-F]+)\s*$') {
    $number = $matches[1]

    if ($number -match '[a-fA-F]') {
      return [Convert]::ToInt64($number, 16)
    }

    return [int64]$number
  }

  if ($text -match '(\d+)') {
    return [int64]$matches[1]
  }

  return $null
}


function Invoke-CaRegistryQuery {
  param(
    [string]$ConfigString,
    [string]$RegistryPath
  )

  $evidence = @()
  $errorText = $null
  $success = $false
  $exitCode = $null

  if (-not $ConfigString) {
    return @{
      success = $false
      exit_code = $null
      evidence = @('CA config string not available')
      error = 'CA config string not available'
    }
  }

  try {
    $lines = @(
      & certutil.exe `
        -config $ConfigString `
        -getreg $RegistryPath 2>&1
    )

    $exitCode = $LASTEXITCODE

    foreach ($line in $lines) {
      $evidence += [string]$line
    }

    if ($exitCode -eq 0) {
      $success = $true
    } else {
      $errorText = (
        "certutil registry query failed with exit code " +
        "$exitCode for $RegistryPath"
      )
    }
  } catch {
    $errorText = $_.Exception.Message
    $evidence += (
      "Registry query exception for " +
      "$RegistryPath`: $errorText"
    )
  }

  return @{
    success = $success
    exit_code = $exitCode
    evidence = @($evidence)
    error = $errorText
  }
}


function Get-KeyProtectionHint {
  param([string]$ConfigString)

  $provider = $null
  $providerType = $null
  $keyContainer = $null

  $query = Invoke-CaRegistryQuery `
    -ConfigString $ConfigString `
    -RegistryPath 'CA\CSP'

  foreach ($line in @($query.evidence)) {
    $text = [string]$line

    if (
      $text -match
      '^\s*ProviderType(?:\s+REG_\w+)?\s*=\s*(.+)$'
    ) {
      $providerType = Convert-RegistryNumber `
        -Value $matches[1]
    } elseif (
      $text -match
      '^\s*Provider\s+Type(?:\s+REG_\w+)?\s*=\s*(.+)$'
    ) {
      $providerType = Convert-RegistryNumber `
        -Value $matches[1]
    } elseif (
      $text -match
      '^\s*ProviderName(?:\s+REG_\w+)?\s*=\s*(.+)$'
    ) {
      $provider = $matches[1].Trim()
    } elseif (
      $text -match
      '^\s*Provider(?:\s+REG_\w+)?\s*=\s*(.+)$'
    ) {
      $provider = $matches[1].Trim()
    } elseif (
      $text -match
      '^\s*KeyContainer(?:\s+REG_\w+)?\s*=\s*(.+)$'
    ) {
      $keyContainer = $matches[1].Trim()
    } elseif (
      $text -match
      '^\s*Key\s+Container(?:\s+REG_\w+)?\s*=\s*(.+)$'
    ) {
      $keyContainer = $matches[1].Trim()
    }
  }

  $storage = 'not_assessed'
  $hsmDetected = 'unknown'

  if ($provider) {
    $providerLower = $provider.ToLowerInvariant()

    if (
      $providerLower -match
      'thales|safenet|luna|ncipher|nshield|entrust|' +
      'utimaco|cryptoserver|fortanix|azure key vault|' +
      'aws cloudhsm|google cloud kms|hsm'
    ) {
      $storage = 'hsm'
      $hsmDetected = $true
    } elseif (
      $providerLower -match
      'microsoft software|microsoft enhanced|' +
      'microsoft strong|software key storage'
    ) {
      $storage = 'software'
      $hsmDetected = $false
    } else {
      $storage = 'unknown_provider'
      $hsmDetected = 'unknown'
    }
  }

  $reason = $null

  if ($provider) {
    $reason = (
      "CA crypto provider collected and classified as $storage."
    )
  } elseif ($query.error) {
    $reason = $query.error
  } else {
    $reason = (
      'CA CSP registry query completed but no provider was parsed.'
    )
  }

  return @{
    collected = [bool]$provider
    assessed = [bool]$provider
    provider = $provider
    crypto_provider = $provider
    key_storage_provider = $provider
    provider_type = $storage
    csp_provider_type = $providerType
    key_container = $keyContainer
    storage = $storage
    hsm_detected = $hsmDetected
    source = 'certutil CA\CSP'
    reason = $reason
    error = $query.error
    query_exit_code = $query.exit_code
    evidence = @($query.evidence)
  }
}


function Get-AuditHint {
  param([string]$ConfigString)

  $auditFilter = $null
  $missingValue = $false

  $query = Invoke-CaRegistryQuery `
    -ConfigString $ConfigString `
    -RegistryPath 'CA\AuditFilter'

  foreach ($line in @($query.evidence)) {
    $text = [string]$line

    if (
      $text -match
      '^\s*AuditFilter(?:\s+REG_DWORD)?\s*=\s*(.+)$'
    ) {
      $auditFilter = Convert-RegistryNumber `
        -Value $matches[1]
    }

    if (
      $text -match
      '0x80070002|ERROR_FILE_NOT_FOUND|cannot find the file specified'
    ) {
      $missingValue = $true
    }
  }

  $assessed = $false
  $collected = $false
  $enabled = $null
  $state = 'not_assessed'
  $reason = $null
  $reportedError = $query.error

  if ($null -ne $auditFilter) {
    $assessed = $true
    $collected = $true
    $enabled = ($auditFilter -ne 0)
    $state = if ($enabled) {
      'enabled'
    } else {
      'disabled'
    }

    $reason = (
      "CA AuditFilter collected successfully. Value: " +
      "$auditFilter."
    )
  } elseif ($missingValue) {
    # The CA registry was reached successfully, but AuditFilter
    # does not exist. This is evidence that CA auditing has not
    # been configured, rather than missing collector evidence.
    $auditFilter = 0
    $assessed = $true
    $collected = $true
    $enabled = $false
    $state = 'not_configured'
    $reportedError = $null

    $reason = (
      'CA registry was reached, but the AuditFilter value does ' +
      'not exist. CA auditing is treated as not configured.'
    )
  } elseif ($query.error) {
    $reason = $query.error
  } else {
    $reason = (
      'CA AuditFilter query completed but no value was parsed.'
    )
  }

  return @{
    assessed = $assessed
    collected = $collected
    auditing_enabled = $enabled
    audit_filter = $auditFilter
    state = $state
    source = 'certutil CA\AuditFilter'
    reason = $reason
    error = $reportedError
    query_error = $query.error
    query_exit_code = $query.exit_code
    evidence = @($query.evidence)
  }
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
    $hint.config.certificate_collection_reason = $null
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
      $genericWrite = ($rightsText -match 'GenericWrite')
      $writeDacl = ($rightsText -match 'WriteDacl')
      $writeOwner = ($rightsText -match 'WriteOwner')
      $writeProperty = ($rightsText -match 'WriteProperty')
      if ($canEnroll -or $canAutoEnroll -or $genericAll -or $genericWrite -or $writeDacl -or $writeOwner -or $writeProperty) {
        $entry = [ordered]@{
          principal = $principal; sid = $sid; rights = @($rights); can_enroll = [bool]$canEnroll; can_autoenroll = [bool]$canAutoEnroll;
          generic_all = [bool]$genericAll; generic_write = [bool]$genericWrite; write_dacl = [bool]$writeDacl; write_owner = [bool]$writeOwner; write_property = [bool]$writeProperty;
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



function Test-CertShieldPkiAdminLike {
  param([string]$Principal)

  $p = ([string]$Principal).Trim().ToLowerInvariant()

  return (
    $p -like "*pki*" -or
    $p -like "*cert*" -or
    $p -like "*ca admin*" -or
    $p -like "*enterprise admin*" -or
    $p -like "*domain admin*"
  )
}

function Test-CertShieldRiskyPrincipal {
  param([string]$Principal)

  if ([string]::IsNullOrWhiteSpace($Principal)) {
    return $false
  }

  if (Test-BroadPrincipal -Principal $Principal) {
    return $true
  }

  if (-not (Test-CertShieldPkiAdminLike -Principal $Principal)) {
    return $true
  }

  return $false
}

function Convert-CertShieldDangerousRights {
  param($Rights)

  $r = ([string]$Rights).ToLowerInvariant()
  $out = @()

  if ($r -match "genericall") { $out += "GenericAll" }
  if ($r -match "genericwrite") { $out += "GenericWrite" }
  if ($r -match "writedacl") { $out += "WriteDacl" }
  if ($r -match "writeowner") { $out += "WriteOwner" }
  if ($r -match "writeproperty") { $out += "WriteProperty" }

  return @($out | Select-Object -Unique)
}

function Get-CertShieldDirectoryAclEvidence {
  param(
    [Parameter(Mandatory=$true)][string]$DistinguishedName,
    [Parameter(Mandatory=$true)][string]$ObjectType
  )

  $out = @()

  try {
    $obj = [ADSI]("LDAP://$DistinguishedName")
    $acl = $obj.ObjectSecurity
    $rules = $acl.GetAccessRules(
      $true,
      $true,
      [System.Security.Principal.NTAccount]
    )

    foreach ($rule in $rules) {
      if ([string]$rule.AccessControlType -ne "Allow") {
        continue
      }

      $principal = ([string]$rule.IdentityReference).Trim()
      $dangerousRights = @(
        Convert-CertShieldDangerousRights `
          -Rights $rule.ActiveDirectoryRights
      )

      if ($dangerousRights.Count -eq 0) {
        continue
      }

      if (-not (Test-CertShieldRiskyPrincipal -Principal $principal)) {
        continue
      }

      $out += [pscustomobject]@{
        object_type        = $ObjectType
        distinguished_name = $DistinguishedName
        principal          = $principal
        rights             = @($dangerousRights)
        inherited          = [bool]$rule.IsInherited
        risk               = "Risky principal can modify PKI-related AD object"
      }
    }
  } catch {
    return @()
  }

  return @($out)
}

function Get-CertShieldPkiObjectControlEvidence {
  $out = @()

  if ($SkipAcl) {
    return @{
      assessed = $false
      evidence = @()
      principals = @()
      broad = $false
      reason = "Collector ran with SkipAcl"
    }
  }

  if (-not (Test-ADModule)) {
    return @{
      assessed = $false
      evidence = @()
      principals = @()
      broad = $false
      reason = "ActiveDirectory module not available"
    }
  }

  try {
    $root = Get-ADRootDSE
    $base = (
      "CN=Public Key Services," +
      "CN=Services," +
      $root.configurationNamingContext
    )

    $objects = Get-ADObject `
      -Filter * `
      -SearchBase $base `
      -SearchScope Subtree `
      -Properties distinguishedName,objectClass,name

    foreach ($obj in $objects) {
      $dn = [string]$obj.DistinguishedName
      $classes = @($obj.objectClass)
      $objectType = "pkiObject"

      if ($classes.Count -gt 0) {
        $objectType = [string]$classes[-1]
      }

      $out += Get-CertShieldDirectoryAclEvidence `
        -DistinguishedName $dn `
        -ObjectType $objectType
    }

    $principals = @(
      $out |
      ForEach-Object { $_.principal } |
      Where-Object { $_ } |
      Select-Object -Unique
    )

    $broad = $false

    foreach ($p in $principals) {
      if (Test-BroadPrincipal -Principal $p) {
        $broad = $true
      }
    }

    return @{
      assessed = $true
      evidence = @($out)
      principals = @($principals)
      broad = $broad
      reason = "Collected ACLs from Public Key Services container"
    }
  } catch {
    return @{
      assessed = $false
      evidence = @()
      principals = @()
      broad = $false
      reason = $_.Exception.Message
    }
  }
}

function Get-CertShieldCaSecurityEvidence {
  param([string]$ConfigString)

  $result = @{
    assessed = $false
    broad_management = $false
    manage_principals = @()
    raw_preview = ""
    reason = ""
  }

  if ([string]::IsNullOrWhiteSpace($ConfigString)) {
    $result.reason = "CA config string not available"
    return $result
  }

  try {
    $lines = certutil.exe -config $ConfigString -getsecurity 2>&1
    $raw = ($lines | Out-String)

    if ([string]::IsNullOrWhiteSpace($raw)) {
      $result.reason = "certutil returned empty CA security output"
      return $result
    }

    $result.assessed = $true
    $result.raw_preview = $raw.Substring(
      0,
      [Math]::Min(2500, $raw.Length)
    )

    $found = @()

    foreach ($principal in @(
      "Everyone",
      "Authenticated Users",
      "Domain Users",
      "Domain Computers",
      "Users"
    )) {
      if ($raw -match [regex]::Escape($principal)) {
        $found += $principal
      }
    }

    $result.manage_principals = @($found | Select-Object -Unique)
    $result.broad_management = ($found.Count -gt 0)
    $result.reason = "Collected CA security descriptor using certutil -getsecurity"

    return $result
  } catch {
    $result.reason = $_.Exception.Message
    return $result
  }
}

function Get-CertShieldLocalAdministrators {
  param([string]$ComputerName)

  $out = @()

  if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    return @()
  }

  try {
    $group = [ADSI]"WinNT://$ComputerName/Administrators,group"

    foreach ($member in @($group.psbase.Invoke("Members"))) {
      $name = $member.GetType().InvokeMember(
        "Name",
        "GetProperty",
        $null,
        $member,
        $null
      )

      $path = $member.GetType().InvokeMember(
        "ADsPath",
        "GetProperty",
        $null,
        $member,
        $null
      )

      $out += [pscustomobject]@{
        computer  = $ComputerName
        principal = [string]$name
        path      = [string]$path
      }
    }
  } catch {
    return @()
  }

  return @($out)
}

function Get-CertShieldCertSvcAccount {
  param([string]$ComputerName)

  if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    return $null
  }

  try {
    $svc = Get-CimInstance `
      -ClassName Win32_Service `
      -ComputerName $ComputerName `
      -Filter "Name='CertSvc'"

    if ($svc) {
      return [pscustomobject]@{
        computer  = $ComputerName
        service   = "CertSvc"
        startName = [string]$svc.StartName
      }
    }
  } catch {
    return $null
  }

  return $null
}

function Get-CertShieldTier0Evidence {
  param(
    [string]$ComputerName,
    [object]$PkiObjectControl
  )

  $admins = @()
  $svc = $null
  $delegates = @()
  $broad = $false
  $assessed = $false
  $reason = ""

  if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
    $admins = @(Get-CertShieldLocalAdministrators -ComputerName $ComputerName)
    $svc = Get-CertShieldCertSvcAccount -ComputerName $ComputerName
  }

  foreach ($a in $admins) {
    if ($a.principal) {
      $delegates += [string]$a.principal
    }
  }

  if ($svc -and $svc.startName) {
    $delegates += [string]$svc.startName
  }

  if ($PkiObjectControl -and $PkiObjectControl.principals) {
    foreach ($p in @($PkiObjectControl.principals)) {
      if ($p) {
        $delegates += [string]$p
      }
    }
  }

  $delegates = @(
    $delegates |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Select-Object -Unique
  )

  foreach ($d in $delegates) {
    if (Test-BroadPrincipal -Principal $d) {
      $broad = $true
    }
  }

  if (
    $admins.Count -gt 0 -or
    $svc -or
    ($PkiObjectControl -and $PkiObjectControl.assessed)
  ) {
    $assessed = $true
    $reason = "Collected PKI delegation evidence; CA host admin evidence collected where reachable"
  } else {
    $assessed = $false
    $reason = "Could not collect PKI delegation or CA host administration evidence"
  }

  return @{
    assessed = $assessed
    local_admins = @($admins)
    service_account = $svc
    delegated_admin_principals = @($delegates)
    broad = $broad
    reason = $reason
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
  $pkiObjectControl = Get-CertShieldPkiObjectControlEvidence
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
    # ESC5-like: PKI AD object control evidence.
    $config['pki_control_paths'] = @($pkiObjectControl.evidence)
    $config['dangerous_pki_object_control'] = @($pkiObjectControl.evidence)
    $config['pki_control_paths_assessed'] = [bool]$pkiObjectControl.assessed
    $config['pki_control_paths_reason'] = [string]$pkiObjectControl.reason

    # ESC7-like: CA management/security descriptor evidence.
    $caSecurity = Get-CertShieldCaSecurityEvidence -ConfigString $configString
    $config['ca_roles_assessed'] = [bool]$caSecurity.assessed
    $config['ca_manage_principals'] = @($caSecurity.manage_principals)
    $config['manage_ca_principals'] = @($caSecurity.manage_principals)
    $config['manage_ca_broad'] = [bool]$caSecurity.broad_management
    $config['ca_security_raw_preview'] = [string]$caSecurity.raw_preview
    $config['ca_security_reason'] = [string]$caSecurity.reason

    # Tier-0: PKI delegation + CA host admin/service account evidence.
    $tier0 = Get-CertShieldTier0Evidence `
      -ComputerName $dns `
      -PkiObjectControl $pkiObjectControl

    $config['tier0_posture_assessed'] = [bool]$tier0.assessed
    $config['delegated_admin_principals'] = @($tier0.delegated_admin_principals)
    $config['tier0_admin_principals'] = @($tier0.delegated_admin_principals)
    $config['tier0_admin_broad'] = [bool]$tier0.broad
    $config['ca_local_admins'] = @($tier0.local_admins)
    $config['ca_service_account'] = $tier0.service_account
    $config['tier0_posture_reason'] = [string]$tier0.reason
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
  param(
    [hashtable]$PublishedMap,
    [hashtable]$HealthCoverage
  )

  $templates = @()
  $searcher = $null
  $results = $null
  $searchRoot = $null

  function Get-ResultFirstValue {
    param(
      $SearchResult,
      [string]$PropertyName
    )

    $key = $PropertyName.ToLowerInvariant()
    $values = $SearchResult.Properties[$key]

    if ($null -ne $values -and $values.Count -gt 0) {
      return ,$values[0]
    }

    return $null
  }

  function Get-ResultStringValues {
    param(
      $SearchResult,
      [string]$PropertyName
    )

    $output = @()
    $key = $PropertyName.ToLowerInvariant()
    $values = $SearchResult.Properties[$key]

    if ($null -ne $values) {
      foreach ($value in $values) {
        if ($null -ne $value -and [string]$value) {
          $output += [string]$value
        }
      }
    }

    return @($output)
  }

  try {
    $rootDse = [ADSI]'LDAP://RootDSE'
    $configurationNamingContext = [string]$rootDse.configurationNamingContext

    if (-not $configurationNamingContext) {
      throw 'Active Directory configurationNamingContext was not returned.'
    }

    $base = (
      "CN=Certificate Templates," +
      "CN=Public Key Services," +
      "CN=Services," +
      $configurationNamingContext
    )

    $searchRoot = [ADSI]("LDAP://$base")

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $searchRoot
    $searcher.Filter = '(objectClass=pKICertificateTemplate)'
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
    $searcher.PageSize = 1000
    $searcher.CacheResults = $false

    if (-not (Test-SkipTemplateAcl)) {
      $searcher.SecurityMasks = (
        [System.DirectoryServices.SecurityMasks]::Dacl -bor
        [System.DirectoryServices.SecurityMasks]::Owner
      )
    }

    $properties = @(
      'cn',
      'displayName',
      'pKIExtendedKeyUsage',
      'msPKI-Certificate-Application-Policy',
      'msPKI-Certificate-Name-Flag',
      'msPKI-Enrollment-Flag',
      'msPKI-Private-Key-Flag',
      'msPKI-RA-Signature',
      'msPKI-RA-Application-Policies',
      'msPKI-RA-Policies',
      'msPKI-Template-Schema-Version',
      'pKIExpirationPeriod',
      'pKIOverlapPeriod',
      'flags',
      'revision',
      'whenChanged',
      'nTSecurityDescriptor'
    )

    foreach ($property in $properties) {
      [void]$searcher.PropertiesToLoad.Add($property)
    }

    $results = $searcher.FindAll()
    $aclCollected = $false

    foreach ($result in $results) {
      $name = [string](
        Get-ResultFirstValue `
          -SearchResult $result `
          -PropertyName 'cn'
      )

      if (-not $name) {
        continue
      }

      $displayName = [string](
        Get-ResultFirstValue `
          -SearchResult $result `
          -PropertyName 'displayName'
      )

      if (-not $displayName) {
        $displayName = $name
      }

      $nameFlag = 0
      $nameFlagValue = Get-ResultFirstValue `
        -SearchResult $result `
        -PropertyName 'msPKI-Certificate-Name-Flag'

      if ($null -ne $nameFlagValue) {
        $nameFlag = [int]$nameFlagValue
      }

      $enrollmentFlag = 0
      $enrollmentFlagValue = Get-ResultFirstValue `
        -SearchResult $result `
        -PropertyName 'msPKI-Enrollment-Flag'

      if ($null -ne $enrollmentFlagValue) {
        $enrollmentFlag = [int]$enrollmentFlagValue
      }

      $privateKeyFlag = 0
      $privateKeyFlagValue = Get-ResultFirstValue `
        -SearchResult $result `
        -PropertyName 'msPKI-Private-Key-Flag'

      if ($null -ne $privateKeyFlagValue) {
        $privateKeyFlag = [int]$privateKeyFlagValue
      }

      $authorizedSignatures = 0
      $signatureValue = Get-ResultFirstValue `
        -SearchResult $result `
        -PropertyName 'msPKI-RA-Signature'

      if ($null -ne $signatureValue) {
        $authorizedSignatures = [int]$signatureValue
      }

      $ekuOids = @()

      $ekuOids += @(
        Get-ResultStringValues `
          -SearchResult $result `
          -PropertyName 'pKIExtendedKeyUsage'
      )

      $ekuOids += @(
        Get-ResultStringValues `
          -SearchResult $result `
          -PropertyName 'msPKI-Certificate-Application-Policy'
      )

      $ekuOids = @(
        $ekuOids |
          Where-Object { $_ } |
          Select-Object -Unique
      )

      $ekuNames = @()

      foreach ($oid in $ekuOids) {
        $ekuNames += Convert-EkuOidToName -Oid ([string]$oid)
      }

      $expirationPeriod = Get-ResultFirstValue `
        -SearchResult $result `
        -PropertyName 'pKIExpirationPeriod'

      $overlapPeriod = Get-ResultFirstValue `
        -SearchResult $result `
        -PropertyName 'pKIOverlapPeriod'

      $validityDays = Convert-ADIntervalToDays `
        -Value $expirationPeriod

      $renewalDays = Convert-ADIntervalToDays `
        -Value $overlapPeriod

      $publishedTo = @()

      if ($PublishedMap) {
        foreach ($caName in $PublishedMap.Keys) {
          if (@($PublishedMap[$caName]) -contains $name) {
            $publishedTo += [string]$caName
          }
        }
      }

      $acl = @{
        permissions_assessed = $false
        acl_collection_reason = 'Template ACL collection skipped'
        permissions = @()
        acl_details = @()
        owner = $null
      }

      if (-not (Test-SkipTemplateAcl)) {
        try {
          $securityDescriptorValue = Get-ResultFirstValue `
            -SearchResult $result `
            -PropertyName 'nTSecurityDescriptor'

          if ($null -eq $securityDescriptorValue) {
            throw 'nTSecurityDescriptor was not returned by DirectorySearcher.'
          }

          if ($securityDescriptorValue -is [byte[]]) {
            $securityDescriptor = New-Object `
              System.DirectoryServices.ActiveDirectorySecurity

            $securityDescriptor.SetSecurityDescriptorBinaryForm(
              [byte[]]$securityDescriptorValue
            )
          } elseif (
            $securityDescriptorValue -is
            [System.DirectoryServices.ActiveDirectorySecurity]
          ) {
            $securityDescriptor = $securityDescriptorValue
          } else {
            throw (
              "Unsupported nTSecurityDescriptor value type: " +
              $securityDescriptorValue.GetType().FullName
            )
          }

          $acl = Convert-TemplateAcl `
            -SecurityDescriptor $securityDescriptor `
            -TemplateName $name
        } catch {
          $acl = @{
            permissions_assessed = $false
            acl_collection_reason = (
              "Template ACL collection failed for " +
              "$name`: $($_.Exception.Message)"
            )
            permissions = @()
            acl_details = @()
            owner = $null
          }
        }
      }

      if ($acl.permissions_assessed) {
        $aclCollected = $true
      }

      $validityOutput = 0

      if ($null -ne $validityDays) {
        $validityOutput = $validityDays
      }

      $renewalOutput = 0

      if ($null -ne $renewalDays) {
        $renewalOutput = $renewalDays
      }

      $templates += [pscustomobject]@{
        name = $name
        display_name = $displayName
        eku = @($ekuNames)
        enrollee_supplies_subject = (
          (($nameFlag -band 1) -ne 0) -or
          (($nameFlag -band 65536) -ne 0)
        )
        manager_approval = (($enrollmentFlag -band 2) -ne 0)
        authorized_signatures = $authorizedSignatures
        validity_days = $validityOutput
        renewal_days = $renewalOutput
        published_to = @($publishedTo)
        permissions = @($acl.permissions)
        raw = @{
          permissions_assessed = [bool]$acl.permissions_assessed
          acl_assessed = [bool]$acl.permissions_assessed
          acl_collection_reason = $acl.acl_collection_reason
          acl_details = @($acl.acl_details)
          dangerous_acl = @($acl.acl_details)
          owner = $acl.owner
          validity_days_assessed = ($null -ne $validityDays)
          renewal_days_assessed = ($null -ne $renewalDays)
          pKIExpirationPeriod = $expirationPeriod
          pKIOverlapPeriod = $overlapPeriod
          eku_oids = @($ekuOids)
          name_flags = $nameFlag
          enrollment_flags = $enrollmentFlag
          private_key_flags = $privateKeyFlag
          private_key_exportable = (
            ($privateKeyFlag -band 16) -ne 0
          )
          ra_signature = $authorizedSignatures
          ra_application_policies = @(
            Get-ResultStringValues `
              -SearchResult $result `
              -PropertyName 'msPKI-RA-Application-Policies'
          )
          ra_policies = @(
            Get-ResultStringValues `
              -SearchResult $result `
              -PropertyName 'msPKI-RA-Policies'
          )
          template_schema_version = (
            Get-ResultFirstValue `
              -SearchResult $result `
              -PropertyName 'msPKI-Template-Schema-Version'
          )
          flags = (
            Get-ResultFirstValue `
              -SearchResult $result `
              -PropertyName 'flags'
          )
          revision = (
            Get-ResultFirstValue `
              -SearchResult $result `
              -PropertyName 'revision'
          )
          when_changed = (
            Get-ResultFirstValue `
              -SearchResult $result `
              -PropertyName 'whenChanged'
          )
          client_authentication = (
            ((@($ekuNames) -join ' ') -match
              'Client Authentication|Smart Card Logon')
          )
          any_purpose = (
            ((@($ekuNames) -join ' ') -match 'Any Purpose')
          )
          template_collection_fallback = $false
          collection_source = 'AD DirectorySearcher'
        }
      }
    }

    $HealthCoverage['template_collected'] = (
      @($templates).Count -gt 0
    )

    $HealthCoverage['template_count'] = @($templates).Count
    $HealthCoverage['template_acl_collected'] = [bool]$aclCollected

    if (@($templates).Count -gt 0) {
      $HealthCoverage['template_collection_reason'] = (
        "Collected $(@($templates).Count) full template objects " +
        "from the AD Configuration partition using DirectorySearcher."
      )
    } else {
      $HealthCoverage['template_collection_reason'] = (
        'DirectorySearcher returned zero certificate template objects.'
      )
    }

    if (Test-SkipTemplateAcl) {
      $HealthCoverage['template_acl_reason'] = (
        'Collector ran with SkipAcl or SkipTemplateAcl.'
      )
    } elseif ($aclCollected) {
      $HealthCoverage['template_acl_reason'] = (
        'Template DACL and owner evidence collected from Active Directory.'
      )
    } else {
      $HealthCoverage['template_acl_reason'] = (
        'Template objects were collected but no template ACL was readable.'
      )
    }
  } catch {
    $HealthCoverage['template_collected'] = $false
    $HealthCoverage['template_count'] = 0
    $HealthCoverage['template_acl_collected'] = $false

    $HealthCoverage['template_collection_reason'] = (
      "DirectorySearcher template enumeration failed: " +
      "$($_.Exception.Message)"
    )

    Write-Warning (
      "Template enumeration failed: $($_.Exception.Message)"
    )
  } finally {
    if ($null -ne $results) {
      $results.Dispose()
    }

    if ($null -ne $searcher) {
      $searcher.Dispose()
    }

    if ($null -ne $searchRoot) {
      $searchRoot.Dispose()
    }
  }

  return @($templates)
}

function Add-TemplateFallbackFromPublishedTemplates {
  param([object[]]$Templates, [hashtable]$PublishedMap, [hashtable]$HealthCoverage)
  if (@($Templates).Count -gt 0) { return @($Templates) }
  $fallback = @{}
  if ($PublishedMap) {
    foreach ($caName in $PublishedMap.Keys) {
      foreach ($templateName in @($PublishedMap[$caName])) {
        if (-not $templateName) { continue }
        $key = [string]$templateName
        if (-not $fallback.ContainsKey($key)) {
          $fallback[$key] = [ordered]@{ name = $key; published_to = @() }
        }
        $fallback[$key].published_to += [string]$caName
      }
    }
  }
  $records = @()
  foreach ($templateName in ($fallback.Keys | Sort-Object)) {
    $publishedTo = @($fallback[$templateName].published_to | Select-Object -Unique)
    $records += [pscustomobject]@{
      name = [string]$templateName
      display_name = [string]$templateName
      eku = @()
      enrollee_supplies_subject = $false
      manager_approval = $false
      authorized_signatures = 0
      validity_days = $null
      renewal_days = $null
      published_to = @($publishedTo)
      permissions = @()
      raw = @{
        permissions_assessed = $false
        acl_assessed = $false
        acl_collection_reason = 'Template object enumeration failed; fallback created from CA published_templates.'
        template_collection_fallback = $true
        validity_days_assessed = $false
        renewal_days_assessed = $false
      }
    }
  }
  if ($records.Count -gt 0) {
    $HealthCoverage['template_collected'] = $true
    $HealthCoverage['template_count'] = $records.Count
    $HealthCoverage['template_collection_reason'] = "Fallback: created $($records.Count) template records from CA published_templates because AD template object enumeration returned zero."
    $HealthCoverage['template_acl_collected'] = $false
    $HealthCoverage['template_acl_reason'] = 'Fallback templates do not include ACL evidence.'
  }
  return @($records)
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
if (-not $EnvironmentName) { $EnvironmentName = $DomainName }
if (-not $EnvironmentKey) {
  $EnvironmentKey = "adcs:$($DomainName.ToLowerInvariant())"
}
if (-not $PkiLabel) { $PkiLabel = "$EnvironmentName ADCS" }
$assessmentHints = @{ esc6_ca_policy = 'not_assessed'; esc7_ca_roles = 'collector_attempted'; esc8_web_enrollment = 'insufficient_data'; esc4_template_acl = 'collector_attempted'; esc5_pki_object_control = 'collector_attempted'; tier0_pki_posture = 'collector_attempted' }
$healthCoverage = @{ ca_certificate_collected = $false; crl_collected = $false; aia_collected = $false; ocsp_collected = $false; issued_certificates_collected = $false; template_acl_collected = $false; ca_registry_collected = $false; key_protection_collected = $false; audit_collected = $false }
$offlineMetadata = Get-OfflineCaMetadata -Path $OfflineCaMetadataPath
$enrollmentServices = @(Get-EnrollmentServiceRecords)
$publishedMap = Get-PublishedTemplateMap -EnrollmentServices $enrollmentServices
$cas = @(Get-CertificateAuthorities -PublishedMap $publishedMap -HealthCoverage $healthCoverage -EnrollmentServices $enrollmentServices)
$templates = @(Get-Templates -PublishedMap $publishedMap -HealthCoverage $healthCoverage)
$templates = @(Add-TemplateFallbackFromPublishedTemplates -Templates $templates -PublishedMap $publishedMap -HealthCoverage $healthCoverage)
$issued = @(Get-IssuedCertificates -HealthCoverage $healthCoverage -Cas $cas)

$payload = [ordered]@{
  collector_type = 'adcs'
  environment_name = $EnvironmentName
  environment_key = $EnvironmentKey
  pki_label = $PkiLabel
  collection_mode = $CollectionMode
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
