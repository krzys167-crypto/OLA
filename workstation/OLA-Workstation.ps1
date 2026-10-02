$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{40}$")]
    [string]$SourceCommit
)
$RepoUrl = "https://github.com/krzysztofcieciwa07-ship-it/OLA.git"
$Root = Split-Path -Parent $PSScriptRoot
$RepoDir = Join-Path $Root "ola-source"
$EvidenceDir = Join-Path $Root "workstation-evidence"
$Container = "ola-workstation-v1"
$Image = "ola-workstation:$($SourceCommit.Substring(0,12))"
$Port = 8000
$RegistrationRunId = [guid]::NewGuid().ToString()
$StartedAt = (Get-Date).ToUniversalTime().ToString("o")
function Write-Gate($name, $status, $detail) { Write-Host ("[{0}] {1} - {2}" -f $status, $name, $detail) }
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Gate "GIT" "BLOCKED" "Git is not installed"; exit 20 }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Gate "DOCKER" "BLOCKED" "Docker is not installed"; exit 21 }
try { docker info | Out-Null } catch { Write-Gate "DOCKER_ENGINE" "BLOCKED" "Docker engine is not running"; exit 22 }
Write-Gate "PREREQUISITES" "VERIFIED" "Git and Docker are available"
$computer = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os = Get-CimInstance Win32_OperatingSystem
$tpmPresent = $false
try { $tpmPresent = [bool](Get-Tpm).TpmPresent } catch {}
$deviceFingerprintInput = "$($computer.Manufacturer)|$($computer.Model)|$($bios.SerialNumber)"
$deviceFingerprint = [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($deviceFingerprintInput)
    )
).ToLowerInvariant()
@{
    schema = "ola-zbook-runtime-registration/v1"
    run_id = $RegistrationRunId
    started_at = $StartedAt
    hostname = $env:COMPUTERNAME
    manufacturer = $computer.Manufacturer
    model = $computer.Model
    bios_serial_sha256 = $deviceFingerprint
    os_caption = $os.Caption
    os_version = $os.Version
    tpm_present = $tpmPresent
    source_commit = $SourceCommit
    evidence_class = "PHYSICAL_WORKSTATION_METADATA"
    physical_execution = "NOT_SELF_PROVEN"
} | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "workstation-registration.json")
if (Test-Path $RepoDir) { Remove-Item -Recurse -Force $RepoDir }
git clone $RepoUrl $RepoDir | Out-Host
Set-Location $RepoDir
git fetch --depth 1 origin $SourceCommit | Out-Host
git checkout --detach $SourceCommit | Out-Host
$actual = (git rev-parse HEAD).Trim()
if ($actual -ne $SourceCommit) { Write-Gate "SOURCE_PIN" "BLOCKED" "SHA mismatch"; exit 30 }
Write-Gate "SOURCE_PIN" "VERIFIED" $actual
"repository=$RepoUrl" | Set-Content (Join-Path $EvidenceDir "source.txt")
"commit=$actual" | Add-Content (Join-Path $EvidenceDir "source.txt")
docker build --tag $Image $RepoDir | Tee-Object -FilePath (Join-Path $EvidenceDir "docker-build.log")
if ($LASTEXITCODE -ne 0) { Write-Gate "IMAGE_BUILD" "BLOCKED" "Docker build failed"; exit 40 }
Write-Gate "IMAGE_BUILD" "VERIFIED" $Image
docker run --rm $Image python -m pytest -q | Tee-Object -FilePath (Join-Path $EvidenceDir "pytest.txt")
if ($LASTEXITCODE -ne 0) { Write-Gate "PYTEST" "BLOCKED" "pytest failed"; exit 50 }
Write-Gate "PYTEST" "VERIFIED" "pytest passed"
docker rm -f $Container 2>$null | Out-Null
docker run -d --name $Container -p ("${Port}:8000") -e OLA_LLM_MODE=deterministic -e OLA_SOURCE_COMMIT=$SourceCommit -e OLA_RUNTIME_COMMIT=$SourceCommit $Image | Set-Content (Join-Path $EvidenceDir "container-id.txt")
$healthy = $false
for ($i=0; $i -lt 30; $i++) {
  try { $h = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 3; if ($h.status -eq "ok") { $healthy = $true; break } } catch {}
  Start-Sleep -Seconds 1
}
if (-not $healthy) { docker logs $Container | Set-Content (Join-Path $EvidenceDir "runtime.log"); Write-Gate "RUNTIME_HEALTH" "BLOCKED" "health failed"; docker rm -f $Container | Out-Null; exit 60 }
Write-Gate "RUNTIME_HEALTH" "VERIFIED" "health endpoint"
$rawKey = "ola-workstation-key"
$tenantId = [guid]::NewGuid().ToString()
docker exec $Container python -c "import hashlib,sqlite3,uuid; db=sqlite3.connect('/data/ola.db'); tid='$tenantId'; key='$rawKey'; db.execute('INSERT INTO tenants(id,name) VALUES (?,?)',(tid,'ola-workstation')); db.execute('INSERT INTO api_keys(id,tenant_id,key_hash) VALUES (?,?,?)',(str(uuid.uuid4()),tid,hashlib.sha256(key.encode()).hexdigest())); db.commit(); db.close()" | Out-Null
$headers = @{ "X-API-Key" = $rawKey; "Content-Type" = "application/json" }
$body = @{ task = "Calculate 17 * 23 and return the verified result." } | ConvertTo-Json
$agentResult = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/agent-run" -Headers $headers -Body $body -TimeoutSec 30
$agentResult | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "agent-run.json")
if ($agentResult.status -ne "VERIFIED" -or $agentResult.final_result -ne "391" -or $agentResult.evidence_count -ne 6 -or $agentResult.source_commit -ne $SourceCommit) { Write-Gate "AGENT_RUNTIME" "BLOCKED" "runtime proof failed"; docker logs $Container | Set-Content (Join-Path $EvidenceDir "runtime.log"); docker rm -f $Container | Out-Null; exit 70 }
Write-Gate "AGENT_RUNTIME" "VERIFIED" "six-agent runtime returned 391"
docker exec $Container python scripts/verify_agent_runtime.py --tenant-id $tenantId --run-id $agentResult.run_id --expected-commit $SourceCommit --expected-task "Calculate 17 * 23 and return the verified result." --expected-result 391 | Tee-Object -FilePath (Join-Path $EvidenceDir "independent-verifier.txt")
if ($LASTEXITCODE -ne 0) { Write-Gate "INDEPENDENT_VERIFY" "BLOCKED" "standalone verifier rejected evidence"; docker rm -f $Container | Out-Null; exit 80 }
Write-Gate "INDEPENDENT_VERIFY" "VERIFIED" "standalone verifier passed"
$tamperExit = 0
docker exec $Container python -c "import sqlite3; db=sqlite3.connect('/data/ola.db'); r=db.execute('select id from evidence_records where tenant_id=? order by seq desc limit 1',('$tenantId',)).fetchone(); db.execute('update evidence_records set payload_json=payload_json where id=?',(r[0],)); db.commit()" 2> (Join-Path $EvidenceDir "tamper-error.txt"); $tamperExit = $LASTEXITCODE
if ($tamperExit -eq 0) { Write-Gate "APPEND_ONLY_TAMPER" "BLOCKED" "mutation accepted"; docker rm -f $Container | Out-Null; exit 90 }
Write-Gate "APPEND_ONLY_TAMPER" "VERIFIED" "append-only trigger rejected mutation"
$agentRunId = $agentResult.run_id
$manifest = @{ schema="ola-workstation-evidence/v2"; registration_run_id=$RegistrationRunId; agent_run_id=$agentRunId; source_commit=$SourceCommit; final_status="READY_FOR_EXTERNAL_REVIEW"; gates=@{ prerequisites="VERIFIED"; source_pin="VERIFIED"; image_build="VERIFIED"; pytest="VERIFIED"; runtime_health="VERIFIED"; agent_runtime="VERIFIED"; independent_verify="VERIFIED"; append_only_tamper="VERIFIED"; physical_execution="NOT_SELF_PROVEN"; workstation_registration="CAPTURED" } }
$manifest | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "MANIFEST.json")
Get-ChildItem $EvidenceDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 } | ForEach-Object { "$($_.Hash)  $($_.Path)" } | Set-Content (Join-Path $EvidenceDir "SHA256SUMS.txt")
Write-Gate "WORKSTATION" "READY" "all local gates passed"
docker rm -f $Container | Out-Null
