$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$EvidenceDir = Join-Path $Root "workstation-evidence"
if (-not (Test-Path (Join-Path $EvidenceDir "MANIFEST.json"))) { Write-Host "[BLOCKED] No workstation evidence manifest exists."; exit 1 }
$manifest = Get-Content (Join-Path $EvidenceDir "MANIFEST.json") | ConvertFrom-Json
if ($manifest.final_status -ne "READY") { Write-Host "[BLOCKED] Workstation status is $($manifest.final_status)"; exit 2 }
foreach ($gate in @("prerequisites","source_pin","image_build","pytest","runtime_health","agent_runtime","independent_verify","append_only_tamper")) {
  if ($manifest.gates.$gate -ne "VERIFIED") { Write-Host "[BLOCKED] Gate $gate is not VERIFIED"; exit 3 }
}
Write-Host "[VERIFIED] OLA Workstation Kit local evidence is complete."
Write-Host "Source commit: $($manifest.source_commit)"
