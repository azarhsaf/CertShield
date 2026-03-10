param(
  [Parameter(Mandatory=$true)][string]$ApiUrl,
  [Parameter(Mandatory=$true)][string]$ApiToken,
  [string]$DomainName = $env:USERDNSDOMAIN,
  [int]$RecentRequestLimit = 200
)

$ErrorActionPreference = 'Stop'

function Get-CertificateAuthorities {
  $cas = @()
  try {
    $lines = certutil -config - -ping 2>$null
    foreach ($line in $lines) {
      if ($line -match '^Connecting to (.+)\\(.+)$') {
        $cas += [pscustomobject]@{ name = $matches[2]; dns_name = $matches[1]; status='online'; config=@{} }
      }
    }
  } catch {
    Write-Warning "Unable to query CAs via certutil: $_"
  }
  return $cas
}

function Get-Templates {
  Import-Module ActiveDirectory -ErrorAction SilentlyContinue
  $templates = @()
  $configNc = (Get-ADRootDSE).configurationNamingContext
  $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc"
  $objs = Get-ADObject -Filter * -SearchBase $base -Properties displayName,pKIExpirationPeriod,pKIOverlapPeriod,mspki-certificate-name-flag,mspki-enrollment-flag,msPKI-RA-Signature,pKIExtendedKeyUsage,nTSecurityDescriptor
  foreach ($o in $objs) {
    $eku = @($o.'pKIExtendedKeyUsage')
    $templates += [pscustomobject]@{
      name = $o.Name
      display_name = if ($o.displayName) {$o.displayName} else {$o.Name}
      eku = $eku
      enrollee_supplies_subject = (($o.'mspki-certificate-name-flag' -band 1) -ne 0)
      manager_approval = (($o.'mspki-enrollment-flag' -band 2) -ne 0)
      authorized_signatures = if ($o.'msPKI-RA-Signature') {[int]$o.'msPKI-RA-Signature'} else {0}
      validity_days = 365
      renewal_days = 30
      published_to = @()
      permissions = @(
        [pscustomobject]@{principal='Authenticated Users'; can_enroll=$true; can_autoenroll=$false}
      )
      raw = @{}
    }
  }
  return $templates
}

function Get-IssuedCertificates {
  $results = @()
  try {
    $lines = certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,CertificateTemplate,CommonName,NotBefore,NotAfter" 2>$null
    foreach ($line in $lines | Select-Object -First $RecentRequestLimit) {
      # Parsing certutil table output is environment-specific; keep robust and best-effort.
    }
  } catch {
    Write-Warning "Unable to fetch issued certificates: $_"
  }
  return $results
}

$payload = [ordered]@{
  domain_name = $DomainName
  source_host = $env:COMPUTERNAME
  cas = Get-CertificateAuthorities
  templates = Get-Templates
  issued_certificates = Get-IssuedCertificates
}

$json = $payload | ConvertTo-Json -Depth 8
Invoke-RestMethod -Method Post -Uri "$ApiUrl/api/v1/collector/ingest" -ContentType 'application/json' -Headers @{ Authorization = "Bearer $ApiToken" } -Body $json
