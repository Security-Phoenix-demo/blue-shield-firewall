<#
.SYNOPSIS
  Phoenix Security Blue Shield - Firewall — Windows installer (no admin / no signing cert)

.DESCRIPTION
  Downloads the latest (or specified) release of phoenix-firewall from
  GitHub, verifies the SHA-256 checksum, places the unsigned .exe under
  $env:LOCALAPPDATA\Programs\phoenix-firewall\, and prepends that to the
  user PATH.

  Since the binary is unsigned, Windows SmartScreen / Defender SmartScreen
  may flag it on first run. This script unblocks the file (via Unblock-File)
  but cannot bypass SmartScreen — the user must click "More info → Run anyway"
  on first launch.

.PARAMETER Version
  Release tag to install (e.g. 'v0.1.0'). Defaults to latest.

.PARAMETER Prefix
  Install location. Defaults to $env:LOCALAPPDATA\Programs\phoenix-firewall.

.EXAMPLE
  irm https://raw.githubusercontent.com/Security-Phoenix-demo/blue-shield-firewall/main/scripts/install.ps1 | iex
#>

[CmdletBinding()]
param(
  [string]$Version = '',
  [string]$Prefix = "$env:LOCALAPPDATA\Programs\phoenix-firewall"
)

$ErrorActionPreference = 'Stop'
$repo = 'Security-Phoenix-demo/blue-shield-firewall'

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
if (-not $Version) {
  Write-Host 'Resolving latest release...'
  try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'phoenix-firewall-install' }
    $Version = $rel.tag_name
  } catch {
    Write-Error "Could not resolve latest release from $repo. If none have been published yet, pass -Version 'v0.x.y' or build from source."
    exit 1
  }
}
$verNoV = $Version.TrimStart('v')

# ---------------------------------------------------------------------------
# Detect arch
# ---------------------------------------------------------------------------
$arch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'amd64' }
$asset = "phoenix-firewall_${verNoV}_windows_${arch}.zip"
$url   = "https://github.com/$repo/releases/download/$Version/$asset"
$sumsUrl = "https://github.com/$repo/releases/download/$Version/checksums.txt"

# ---------------------------------------------------------------------------
# Download + verify
# ---------------------------------------------------------------------------
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "phoenix-firewall-install-$([guid]::NewGuid().Guid.Substring(0,8))")
$zip = Join-Path $tmp $asset
Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

Write-Host 'Verifying SHA-256...'
$sumsPath = Join-Path $tmp 'checksums.txt'
Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsPath -UseBasicParsing
$expectedLine = (Get-Content $sumsPath) | Where-Object { $_ -match "  $([regex]::Escape($asset))$" }
if (-not $expectedLine) {
  Write-Error "Checksum entry for $asset not found"; exit 1
}
$expected = ($expectedLine -split '\s+')[0]
$actual = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLower()
if ($expected.ToLower() -ne $actual) {
  Write-Error "Checksum mismatch! expected $expected, got $actual"; exit 1
}
Write-Host 'Checksum verified.'

# ---------------------------------------------------------------------------
# Extract + install
# ---------------------------------------------------------------------------
if (-not (Test-Path $Prefix)) { New-Item -ItemType Directory -Path $Prefix | Out-Null }
Expand-Archive -Path $zip -DestinationPath $tmp -Force
Move-Item -Force -Path (Join-Path $tmp 'phoenix-firewall.exe') -Destination (Join-Path $Prefix 'phoenix-firewall.exe')

# Unblock the file so PowerShell / Explorer doesn't flag it as "downloaded from
# the internet". This still does NOT bypass SmartScreen — on first run the user
# may see "Windows protected your PC" and must click "More info → Run anyway".
Unblock-File -Path (Join-Path $Prefix 'phoenix-firewall.exe')

# ---------------------------------------------------------------------------
# PATH
# ---------------------------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($userPath -split ';' -contains $Prefix)) {
  [Environment]::SetEnvironmentVariable('Path', "$Prefix;$userPath", 'User')
  Write-Host "Added $Prefix to user PATH (restart your shell)."
}

Remove-Item -Recurse -Force $tmp

Write-Host ''
Write-Host "Installed phoenix-firewall $Version → $Prefix\phoenix-firewall.exe"
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  phoenix-firewall version'
Write-Host '  phoenix-firewall init'
Write-Host '  phoenix-firewall enroll --api-key <your-bootstrap-token>'
Write-Host ''
Write-Host 'Note: on FIRST launch, Windows SmartScreen may show a warning'
Write-Host '("Windows protected your PC"). Click "More info" → "Run anyway".'
Write-Host 'Subsequent launches will not prompt.'
