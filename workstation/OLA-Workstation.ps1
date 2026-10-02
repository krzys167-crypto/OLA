param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{40}$")]
    [string]$SourceCommit
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoUrl = "https://github.com/krzysztofcieciwa07-ship-it/OLA.git"
$Root = Split-Path -Parent $PSScriptRoot
$RepoDir = Join-Path $Root "ola-source"
$EvidenceDir = Join-Path $Root "workstation-evidence"
$Container = "ola-workstation-v1"
$Image = "ola-workstation:$($SourceCommit.Substring(0,12))"
$Port = 8000
$OllamaModel = "qwen2.5:0.5b-instruct"
$OllamaBaseUrl = "http://host.docker.internal:11434"
$RegistrationRunId = [guid]::NewGuid().ToString()
$StartedAtDate = (Get-Date).ToUniversalTime()
$StartedAt = $StartedAtDate.ToString("o")
$GateResults = [ordered]@{}
function Write-Gate($name, $status, $detail, $exitCode = 0) {
    Write-Host ("[{0}] {1} - {2}" -f $status, $name, $detail)
    $GateResults[$name] = [ordered]@{
        status = $status
        detail = $detail
        exit_code = $exitCode
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
    }
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Gate "GIT" "BLOCKED" "Git is not installed"; exit 20 }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Gate "DOCKER" "BLOCKED" "Docker is not installed"; exit 21 }
try { docker info | Out-Null } catch { Write-Gate "DOCKER_ENGINE" "BLOCKED" "Docker engine is not running"; exit 22 }
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) { Write-Gate "OLLAMA" "BLOCKED" "Ollama is not installed"; exit 23 }
try { ollama list | Out-Null } catch { Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden | Out-Null; Start-Sleep -Seconds 3 }
ollama pull $OllamaModel | Tee-Object -FilePath (Join-Path $EvidenceDir "ollama-pull.log")
$pullExit = $LASTEXITCODE
if ($pullExit -ne 0) { Write-Gate "OLLAMA_PULL" "BLOCKED" "ollama pull failed" $pullExit; exit 23 }
$ollamaTags = $null
try {
    $ollamaTags = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 5
    $ollamaTags | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "ollama-models.json")
} catch { Write-Gate "OLLAMA_ENGINE" "BLOCKED" "Ollama API is not reachable" 24; exit 24 }
$modelEntry = @($ollamaTags.models | Where-Object { $_.name -eq $OllamaModel -or $_.model -eq $OllamaModel } | Select-Object -First 1)
if ($modelEntry.Count -ne 1 -or [string]::IsNullOrWhiteSpace($modelEntry[0].digest)) {
    Write-Gate "OLLAMA_MODEL_DIGEST" "BLOCKED" "Ollama model digest missing" 25
    exit 25
}
@{
    model = $OllamaModel
    digest = [string]$modelEntry[0].digest
    size = $modelEntry[0].size
    modified_at = $modelEntry[0].modified_at
} | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "ollama-model.json")
Write-Gate "OLLAMA_MODEL_DIGEST" "VERIFIED" ([string]$modelEntry[0].digest)
Write-Gate "PREREQUISITES" "VERIFIED" "Git, Docker and Ollama are available"
$computer = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os = Get-CimInstance Win32_OperatingSystem
$tpmPresent = $false
try { $tpmPresent = [bool](Get-Tpm).TpmPresent } catch {}
$deviceFingerprintInput = "$($computer.Manufacturer)|$($computer.Model)|$($bios.SerialNumber)"
$sha = [System.Security.Cryptography.SHA256]::Create()
$deviceFingerprint = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($deviceFingerprintInput)) | ForEach-Object { $_.ToString("x2") }) -join "")
$sha.Dispose()
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
    physical_execution = "CAPTURED_METADATA"
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
$buildExit = $LASTEXITCODE
if ($buildExit -ne 0) { Write-Gate "IMAGE_BUILD" "BLOCKED" "Docker build failed" $buildExit; exit 40 }
$imageInspect = @(docker image inspect $Image | Out-String | ConvertFrom-Json)
if ($imageInspect.Count -ne 1 -or [string]::IsNullOrWhiteSpace($imageInspect[0].Id) -or -not $imageInspect[0].Id.StartsWith("sha256:")) {
    Write-Gate "IMAGE_DIGEST" "BLOCKED" "Docker image content digest missing" 41
    exit 41
}
@{
    image = $Image
    image_id = $imageInspect[0].Id
    repo_digests = @($imageInspect[0].RepoDigests)
    created = $imageInspect[0].Created
} | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "docker-image.json")
Write-Gate "IMAGE_BUILD" "VERIFIED" $Image
Write-Gate "IMAGE_DIGEST" "VERIFIED" $imageInspect[0].Id
docker run --rm $Image python -m pytest -q | Tee-Object -FilePath (Join-Path $EvidenceDir "pytest.txt")
$pytestExit = $LASTEXITCODE
if ($pytestExit -ne 0) { Write-Gate "PYTEST" "BLOCKED" "pytest failed" $pytestExit; exit 50 }
Write-Gate "PYTEST" "VERIFIED" "pytest passed"
docker rm -f $Container 2>$null | Out-Null
docker run -d --name $Container -p ("${Port}:8000") -e OLA_LLM_PROVIDER=ollama -e OLA_LLM_MODE=required -e OLA_LLM_MODEL=$OllamaModel -e OLLAMA_MODEL=$OllamaModel -e OLLAMA_BASE_URL=$OllamaBaseUrl -e OLA_LLM_TIMEOUT=60 -e OLA_SOURCE_COMMIT=$SourceCommit -e OLA_RUNTIME_COMMIT=$SourceCommit $Image | Set-Content (Join-Path $EvidenceDir "container-id.txt")
$healthy = $false
for ($i=0; $i -lt 30; $i++) {
  try { $h = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 3; if ($h.status -eq "ok") { $healthy = $true; break } } catch {}
  Start-Sleep -Seconds 1
}
if (-not $healthy) { docker logs $Container | Set-Content (Join-Path $EvidenceDir "runtime.log"); Write-Gate "RUNTIME_HEALTH" "BLOCKED" "health failed" 60; docker rm -f $Container | Out-Null; exit 60 }
Write-Gate "RUNTIME_HEALTH" "VERIFIED" "health endpoint"
$rawKey = "ola-workstation-key"
$tenantId = [guid]::NewGuid().ToString()
docker exec $Container python -c "import hashlib,sqlite3,uuid; db=sqlite3.connect('/data/ola.db'); tid='$tenantId'; key='$rawKey'; db.execute('INSERT INTO tenants(id,name) VALUES (?,?)',(tid,'ola-workstation')); db.execute('INSERT INTO api_keys(id,tenant_id,key_hash) VALUES (?,?,?)',(str(uuid.uuid4()),tid,hashlib.sha256(key.encode()).hexdigest())); db.commit(); db.close()" | Out-Null
$headers = @{ "X-API-Key" = $rawKey; "Content-Type" = "application/json" }
$body = @{ task = "Calculate 17 * 23 and return the verified result." } | ConvertTo-Json
$agentResult = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/agent-run" -Headers $headers -Body $body -TimeoutSec 30
$agentResult | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "agent-run.json")
if ($agentResult.status -ne "VERIFIED" -or $agentResult.final_result -ne "391" -or $agentResult.evidence_count -ne 6 -or $agentResult.source_commit -ne $SourceCommit -or @($agentResult.execution).Count -ne 6) { Write-Gate "AGENT_RUNTIME" "BLOCKED" "runtime proof failed" 70; docker logs $Container | Set-Content (Join-Path $EvidenceDir "runtime.log"); docker rm -f $Container | Out-Null; exit 70 }
foreach ($item in @($agentResult.execution)) {
    if ($item.provider -ne "ollama" -or $item.model -ne $OllamaModel -or $item.invocation_type -ne "real_llm" -or ([string]::IsNullOrWhiteSpace($item.response_id) -and [string]::IsNullOrWhiteSpace($item.response_digest)) -or [string]::IsNullOrWhiteSpace($item.started_at) -or [string]::IsNullOrWhiteSpace($item.ended_at)) {
        Write-Gate "AGENT_RUNTIME" "BLOCKED" "real Ollama evidence incomplete" 71
        docker rm -f $Container | Out-Null
        exit 71
    }
}
Write-Gate "AGENT_RUNTIME" "VERIFIED" "six-agent real Ollama runtime returned 391"
$verifyOutput = docker exec $Container python scripts/verify_agent_runtime.py --tenant-id $tenantId --run-id $agentResult.run_id --expected-commit $SourceCommit --expected-task "Calculate 17 * 23 and return the verified result." --expected-result 391 --expected-provider ollama --expected-model $OllamaModel --expected-invocation-type real_llm | Tee-Object -FilePath (Join-Path $EvidenceDir "independent-verifier.txt")
$verifyExit = $LASTEXITCODE
if ($verifyExit -ne 0) { Write-Gate "INDEPENDENT_VERIFY" "BLOCKED" "standalone verifier rejected evidence" $verifyExit; docker rm -f $Container | Out-Null; exit 80 }
$verifyJsonLine = @($verifyOutput | Where-Object { $_ -match '^{' } | Select-Object -Last 1)
if ($verifyJsonLine.Count -ne 1) { Write-Gate "INDEPENDENT_VERIFY" "BLOCKED" "standalone verifier did not emit JSON result" 81; docker rm -f $Container | Out-Null; exit 81 }
$verifyResult = $verifyJsonLine[0] | ConvertFrom-Json
@{
    schema = "ola-independent-verifier/v1"
    status = $verifyResult.status
    verifier_component = "ola-workstation-independent-verifier"
    runtime_component = "ola-workstation-runtime"
    run_id = $agentResult.run_id
    source_commit = $SourceCommit
} | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "independent-verifier.json")
Write-Gate "INDEPENDENT_VERIFY" "VERIFIED" "standalone verifier passed"
$tamperExit = 0
docker exec $Container python -c "import sqlite3; db=sqlite3.connect('/data/ola.db'); r=db.execute('select id,payload_json from evidence_records where tenant_id=? order by seq desc limit 1',('$tenantId',)).fetchone(); db.execute('update evidence_records set payload_json=? where id=?', (r[1]+'-TAMPER-MUTATION', r[0])); db.commit()" 2> (Join-Path $EvidenceDir "tamper-error.txt")
$tamperExit = $LASTEXITCODE
if ($tamperExit -eq 0) { Write-Gate "APPEND_ONLY_TAMPER" "BLOCKED" "mutation accepted" 0; docker rm -f $Container | Out-Null; exit 90 }
Write-Gate "APPEND_ONLY_TAMPER" "VERIFIED" "append-only trigger rejected real mutation" 1

Write-Gate "STABILITY" "VERIFIED" "30-second health stability window" 0
for ($i = 0; $i -lt 30; $i++) {
    try { Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 3 | Out-Null } catch { Write-Gate "STABILITY" "BLOCKED" "health failed during stability window" 92; docker rm -f $Container | Out-Null; exit 92 }
    Start-Sleep -Seconds 1
}

$agentRunId = $agentResult.run_id
@{
    runtime_component = "ola-workstation-runtime"
    verifier_component = "ola-workstation-independent-verifier"
    external_anchor = $false
    calls = @($agentResult.execution | ForEach-Object {
        @{
            agent = $_.agent
            run_id = $agentRunId
            source_commit = $_.source_commit
            response_id = $_.response_id
            response_digest = $_.response_digest
            model = $_.model
            started_at = $_.started_at
            ended_at = $_.ended_at
        }
    })
} | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "provider-trace.json")

$EndedAtDate = (Get-Date).ToUniversalTime()
$durationSeconds = ($EndedAtDate - $StartedAtDate).TotalSeconds
@{
    started_at = $StartedAtDate.ToString("o")
    ended_at = $EndedAtDate.ToString("o")
    duration_seconds = [math]::Round($durationSeconds, 3)
} | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "runtime-window.json")

@{
    schema = "ola-zbook-runtime-registration/v2"
    run_id = $RegistrationRunId
    agent_run_id = $agentRunId
    started_at = $StartedAtDate.ToString("o")
    ended_at = $EndedAtDate.ToString("o")
    hostname = $env:COMPUTERNAME
    manufacturer = $computer.Manufacturer
    model = $computer.Model
    bios_serial_sha256 = $deviceFingerprint
    os_caption = $os.Caption
    os_version = $os.Version
    tpm_present = $tpmPresent
    source_commit = $SourceCommit
    evidence_class = "PHYSICAL_WORKSTATION_RUNTIME"
    physical_execution = "CAPTURED"
} | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $EvidenceDir "workstation-registration.json")

$GateResults["STABILITY"] = [ordered]@{
    status = "VERIFIED"
    detail = "30-second health stability window"
    exit_code = 0
    timestamp = $EndedAtDate.ToString("o")
}
@{
    prerequisites = $GateResults["PREREQUISITES"]
    ollama_pull = $GateResults["OLLAMA_PULL"]
    ollama_model_digest = $GateResults["OLLAMA_MODEL_DIGEST"]
    source_pin = $GateResults["SOURCE_PIN"]
    image_build = $GateResults["IMAGE_BUILD"]
    image_digest = $GateResults["IMAGE_DIGEST"]
    pytest = $GateResults["PYTEST"]
    runtime_health = $GateResults["RUNTIME_HEALTH"]
    agent_runtime = $GateResults["AGENT_RUNTIME"]
    independent_verify = $GateResults["INDEPENDENT_VERIFY"]
    append_only_tamper = $GateResults["APPEND_ONLY_TAMPER"]
    stability = $GateResults["STABILITY"]
    skipped = @()
} | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "gate-results.json")

$manifest = @{
    schema="ola-workstation-evidence/v3"
    provider="ollama"
    model=$OllamaModel
    registration_run_id=$RegistrationRunId
    agent_run_id=$agentRunId
    source_commit=$SourceCommit
    docker_image_id=$imageInspect[0].Id
    ollama_model_digest=[string]$modelEntry[0].digest
    final_status="READY_FOR_EXTERNAL_REVIEW"
    gates=@{
        source_pin="VERIFIED"
        image_build="VERIFIED"
        image_digest="VERIFIED"
        pytest="VERIFIED"
        runtime_health="VERIFIED"
        agent_runtime="VERIFIED"
        independent_verify="VERIFIED"
        append_only_tamper="VERIFIED"
        stability="VERIFIED"
        provider_authenticity="REVIEW_REQUIRED"
        physical_execution="CAPTURED"
        workstation_registration="CAPTURED"
    }
}
$manifest | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "MANIFEST.json")
Get-ChildItem $EvidenceDir -File |
    Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        "$hash  $($_.Name)"
    } |
    Set-Content (Join-Path $EvidenceDir "SHA256SUMS.txt")
Write-Gate "WORKSTATION" "READY" "all local gates passed; external provider authenticity remains REVIEW_REQUIRED"
docker rm -f $Container | Out-Null
