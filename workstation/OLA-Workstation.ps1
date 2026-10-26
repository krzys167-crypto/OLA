$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoUrl = "https://github.com/krzysztofcieciwa07-ship-it/OLA.git"
# No mutable default; the operator provides the exact signed release.
$SourceCommit = $env:OLA_WORKSTATION_SOURCE_SHA
$ExpectedSigner = $env:OLA_SIGNER_FINGERPRINT
$Root = Split-Path -Parent $PSScriptRoot
$RunToken = [guid]::NewGuid().ToString("N").Substring(0, 12)
$RepoDir = Join-Path $Root ("ola-source-" + $RunToken)
$EvidenceDir = Join-Path $Root ("workstation-evidence-" + $RunToken)
$Container = "ola-workstation-" + $RunToken
$Image = "ola-workstation:pending-source"
$Port = 18080
function Write-Gate($name, $status, $detail) { Write-Host ("[{0}] {1} - {2}" -f $status, $name, $detail) }
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
# Fail closed before any cloning, image build, container cleanup or source checkout.
if (-not $SourceCommit -or $SourceCommit -cnotmatch '^[0-9a-fA-F]{40}$') {
    Write-Gate "SOURCE_PIN" "BLOCKED" "A 40-hex OLA_WORKSTATION_SOURCE_SHA is required"; exit 23
}
$SourceCommit = $SourceCommit.ToLowerInvariant()
if (-not $ExpectedSigner -or $ExpectedSigner -cnotmatch '^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$') {
    Write-Gate "SIGNER" "BLOCKED" "A trusted 40/64-hex OLA_SIGNER_FINGERPRINT is required"; exit 25
}
$ExpectedSigner = $ExpectedSigner.ToUpperInvariant()
$Image = "ola-workstation:$($SourceCommit.Substring(0,12))"
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Gate "GIT" "BLOCKED" "Git is not installed"; exit 20 }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Gate "DOCKER" "BLOCKED" "Docker is not installed"; exit 21 }
docker info | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Gate "DOCKER_ENGINE" "BLOCKED" "Docker engine is not running"; exit 22 }
Write-Gate "PREREQUISITES" "VERIFIED" "Git and Docker are available"
if (-not $env:OLA_API_KEY_PEPPER -or $env:OLA_API_KEY_PEPPER.Length -lt 32) { Write-Gate "API_KEY_PEPPER" "BLOCKED" "Configure the secret for this workstation"; exit 24 }
if (Test-Path $RepoDir) { Write-Gate "WORK_DIR" "BLOCKED" "Refusing to overwrite existing source directory"; exit 26 }
git clone $RepoUrl $RepoDir | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Gate "GIT_CLONE" "BLOCKED" "Clone failed"; exit 27 }
Set-Location $RepoDir
git fetch --depth 1 origin $SourceCommit | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Gate "GIT_FETCH" "BLOCKED" "Source SHA not reachable"; exit 28 }
git checkout --detach $SourceCommit | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Gate "GIT_CHECKOUT" "BLOCKED" "Source checkout failed"; exit 29 }
$actual = (git rev-parse HEAD).Trim()
if ($actual -ne $SourceCommit) { Write-Gate "SOURCE_PIN" "BLOCKED" "SHA mismatch"; exit 30 }
# The actual source SHA and signing key must come from operator-approved release inputs.
git verify-commit $SourceCommit | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Gate "SOURCE_SIGNATURE" "BLOCKED" "Commit signature verification failed"; exit 31 }
$signer = (git show -s --format="%GF" $SourceCommit).Trim()
$signatureStatus = (git show -s --format="%G?" $SourceCommit).Trim()
if ($signatureStatus -ne "G" -or $signer -ine $ExpectedSigner) {
    Write-Gate "SIGNER" "BLOCKED" "Signing fingerprint or trust mismatch"; exit 32
}
git cat-file -e "${SourceCommit}:app/api_key_hashing.py"
if ($LASTEXITCODE -ne 0) {
    Write-Gate "SOURCE_MODULE" "BLOCKED" "Pinned source lacks API-key hashing module"; exit 33
}
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
docker run -d --name $Container -e OLA_API_KEY_PEPPER=$env:OLA_API_KEY_PEPPER -p ("127.0.0.1:${Port}:8000") -e OLA_LLM_MODE=deterministic -e OLA_RUNTIME_COMMIT=$SourceCommit $Image | Set-Content (Join-Path $EvidenceDir "container-id.txt")
$healthy = $false
for ($i=0; $i -lt 30; $i++) {
  try { $h = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 3; if ($h.status -eq "ok") { $healthy = $true; break } } catch {}
  Start-Sleep -Seconds 1
}
if (-not $healthy) { docker logs $Container | Set-Content (Join-Path $EvidenceDir "runtime.log"); Write-Gate "RUNTIME_HEALTH" "BLOCKED" "health failed"; docker rm -f $Container | Out-Null; exit 60 }
Write-Gate "RUNTIME_HEALTH" "VERIFIED" "health endpoint"
$rawKey = ([guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N"))
$tenantId = [guid]::NewGuid().ToString()
docker exec $Container python -c "import hashlib,sqlite3,uuid; db=sqlite3.connect('/data/ola.db'); tid='$tenantId'; key='$rawKey'; db.execute('INSERT INTO tenants(id,name) VALUES (?,?)',(tid,'ola-workstation')); db.execute('INSERT INTO api_keys(id,tenant_id,key_hash) VALUES (?,?,?)',(str(uuid.uuid4()),tid,__import__('app.api_key_hashing',fromlist=['api_key_fingerprint']).api_key_fingerprint(key))); db.commit(); db.close()" | Out-Null
$headers = @{ "X-API-Key" = $rawKey; "Content-Type" = "application/json" }
$body = @{ task = "Calculate 17 * 23 and return the verified result." } | ConvertTo-Json
$agentResult = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/agent-run" -Headers $headers -Body $body -TimeoutSec 30
$agentResult | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "agent-run.json")
if ($agentResult.status -ne "VERIFIED" -or $agentResult.final_result -ne "391" -or $agentResult.evidence_count -ne 6) { Write-Gate "AGENT_RUNTIME" "BLOCKED" "runtime proof failed"; docker logs $Container | Set-Content (Join-Path $EvidenceDir "runtime.log"); docker rm -f $Container | Out-Null; exit 70 }
Write-Gate "AGENT_RUNTIME" "VERIFIED" "six-agent runtime returned 391"
docker exec $Container python scripts/verify_agent_runtime.py --tenant-id $tenantId --run-id $agentResult.run_id --expected-commit $SourceCommit --expected-task "Calculate 17 * 23 and return the verified result." --expected-result 391 | Tee-Object -FilePath (Join-Path $EvidenceDir "independent-verifier.txt")
if ($LASTEXITCODE -ne 0) { Write-Gate "INDEPENDENT_VERIFY" "BLOCKED" "standalone verifier rejected evidence"; docker rm -f $Container | Out-Null; exit 80 }
Write-Gate "INDEPENDENT_VERIFY" "VERIFIED" "standalone verifier passed"
$tamperExit = 0
docker exec $Container python -c "import sqlite3; db=sqlite3.connect('/data/ola.db'); r=db.execute('select id from evidence_records where tenant_id=? order by seq desc limit 1',('$tenantId',)).fetchone(); db.execute('update evidence_records set payload_json=payload_json where id=?',(r[0],)); db.commit()" 2> (Join-Path $EvidenceDir "tamper-error.txt"); $tamperExit = $LASTEXITCODE
if ($tamperExit -eq 0) { Write-Gate "APPEND_ONLY_TAMPER" "BLOCKED" "mutation accepted"; docker rm -f $Container | Out-Null; exit 90 }
Write-Gate "APPEND_ONLY_TAMPER" "VERIFIED" "append-only trigger rejected mutation"
$manifest = @{ schema="ola-workstation-evidence/v1"; source_commit=$SourceCommit; final_status="READY"; gates=@{ prerequisites="VERIFIED"; source_pin="VERIFIED"; image_build="VERIFIED"; pytest="VERIFIED"; runtime_health="VERIFIED"; agent_runtime="VERIFIED"; independent_verify="VERIFIED"; append_only_tamper="VERIFIED" } }
$manifest | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "MANIFEST.json")
Get-ChildItem $EvidenceDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 } | ForEach-Object { "$($_.Hash)  $($_.Path)" } | Set-Content (Join-Path $EvidenceDir "SHA256SUMS.txt")
Write-Gate "WORKSTATION" "READY" "all local gates passed"
docker rm -f $Container | Out-Null
