# Runs the EXISTING AI STUDIO 3.6.0 package on Windows 11 with Docker Desktop.
# Read-only toward OLA main/repository; never merges or pushes anything.
param(
  [string]$Archive = (Join-Path $PSScriptRoot 'AI_STUDIO_3.6.0_FULL_AUTONOMOUS_EU_COMPLIANCE_PRODUCTION.tar.gz'),
  [string]$Target = (Join-Path $env:USERPROFILE 'OLA\AI_STUDIO_3.6.0_PRODUCTION'),
  [ValidateRange(1024,65535)][int]$Port = 8001
)
$ErrorActionPreference = 'Stop'
$python = (Get-Command python -ErrorAction Stop).Source
$tool = Join-Path $PSScriptRoot 'scripts\ai_studio_archive.py'
if (!(Test-Path -LiteralPath $tool)) {
  $tool = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\ai_studio_archive.py'
}
if (!(Test-Path -LiteralPath $Archive)) { throw "Archiwum nie istnieje: $Archive" }
if (!(Test-Path -LiteralPath $tool)) { throw "Brak weryfikatora archiwum: $tool" }
& $python $tool verify --archive $Archive
if ($LASTEXITCODE -ne 0) { throw 'NO-GO: SHA-256 lub struktura archiwum niezgodna' }
if (!(Test-Path -LiteralPath $Target)) {
  & $python $tool install --archive $Archive --target $Target
  if ($LASTEXITCODE -ne 0) { throw 'NO-GO: nieudana bezpieczna ekstrakcja' }
} else {
  $proof = Join-Path $Target 'OLA_ARCHIVE_SOURCE.json'
  if (!(Test-Path $proof)) { throw "NO-GO: istniejący katalog bez manifestu: $Target" }
  $manifest = Get-Content -Raw $proof | ConvertFrom-Json
  if ($manifest.sha256 -ne '29b9c6614e8af1a702e01993e766240760ee55837f1a68d0d94925fb7f99d890') {
    throw 'NO-GO: niezweryfikowany katalog instalacji'
  }
}
# Existing deployments are not trusted based on a manifest alone.
$expectedFiles = @{
  'frontend\index.html' = '1ed655070aba8533729be67c8bc97896a2b011a302d9705ddd20ba02c48534fc';
  'backend\main.py' = '08b9927ecdbf23dbde220e527d2b9ea0ca8a25c6080e97d8e1f1c0ee868a498c';
  'Dockerfile' = '4706ad90d14b3f88bc529b1bfce8ddc101b431efecb3da75ebf0a88adcd025c3';
  'requirements.txt' = '42bfc26eac41ae08819dbca8d681f47486dffa8c8f6ecd637b3328de2707c711';
  'docker-compose.ola.yml' = 'c2d1c49396427737ff4c365bdaebaeb75b87d3863780dc7c54c6949964acaec6'
}
foreach ($relative in $expectedFiles.Keys) {
  $path = Join-Path $Target $relative
  if (!(Test-Path -LiteralPath $path)) { throw "NO-GO: brak zainstalowanego pliku $relative" }
  $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expectedFiles[$relative]) { throw "NO-GO: plik zmodyfikowany: $relative" }
}
& docker info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'NO-GO: Docker Desktop nie działa' }
$env:OLA_STUDIO_PORT = "$Port"
Push-Location -LiteralPath $Target
try {
  & docker compose -f docker-compose.ola.yml up --detach --build
  if ($LASTEXITCODE -ne 0) { throw 'NO-GO: Docker Compose nie uruchomił Studio' }
} finally { Pop-Location }
$ok = $false
foreach ($i in 1..30) {
  try {
    $r = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/health" -TimeoutSec 3
    if ($r.ok -eq $true -and $r.version -eq '3.6.0') { $ok = $true; break }
  } catch { Start-Sleep -Seconds 1 }
}
if (-not $ok) { throw 'NO-GO: AI STUDIO nie przeszło testu /api/health' }
Write-Host "STAGING VERIFIED: http://127.0.0.1:$Port/" -ForegroundColor Green
Write-Host 'OLA Core działa osobno na swoim dotychczasowym adresie; logowanie i bazy NIE są jeszcze współdzielone.'
