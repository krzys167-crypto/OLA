# OLA DI-OS ZBook preview auth: read-only by default.
# -IssueKey creates a new tenant credential ONLY in the already configured preview.
[CmdletBinding()]
param([switch]$IssueKey,[switch]$SelfTest)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Preview='ola-cc-preview'
function Get-Preview {
 $raw=& docker.exe inspect --format '{{json .}}' $script:Preview 2>$null
 if($LASTEXITCODE -ne 0 -or !$raw){return $null}
 $c=$raw|ConvertFrom-Json
 if($c.Name -ne '/ola-cc-preview' -or $c.HostConfig.Privileged -or $c.HostConfig.NetworkMode -eq 'host'){throw 'BLOCKED_UNEXPECTED_CONTAINER'}
 $port=$c.HostConfig.PortBindings.'8000/tcp'
 if(!$port -or @($port).Count -ne 1 -or $port[0].HostIp -ne '127.0.0.1' -or $port[0].HostPort -ne '18081'){throw 'BLOCKED_UNSAFE_PORT'}
 $c
}
function Test-Pepper {
 $v=& docker.exe exec $script:Preview python -c "import os; print('READY' if len(os.environ.get('OLA_API_KEY_PEPPER','').encode('utf-8')) >= 32 else 'MISSING')" 2>$null
 ($LASTEXITCODE -eq 0 -and ([string]$v).Trim() -eq 'READY')
}
if($SelfTest){
 if($script:Preview -ne 'ola-cc-preview'){throw 'PREVIEW_NAME_CHANGED'}
 Write-Host 'OLA_PREVIEW_AUTH_SELFTEST=PASS';exit 0
}
if(!(Get-Command docker.exe -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
$state=Get-Preview
if(!$state){Write-Host 'PREVIEW_NOT_FOUND: create a new credential-enabled preview after verifying source SHA.';exit 2}
if($state.State.Status -ne 'running'){Write-Host ("PREVIEW_NOT_RUNNING: "+$state.State.Status);exit 3}
if(!(Test-Pepper)){
 Write-Host 'AUTH_NOT_CONFIGURED: preview has no OLA_API_KEY_PEPPER.' -ForegroundColor Yellow
 Write-Host 'BLOCKED: no key created, no container restart, no data changed.'
 Write-Host 'A reviewed backup + preview recreation is required before issuing credentials.'
 exit 4
}
$module=& docker.exe exec $script:Preview python -c "import scripts.provision_local_operator; print('READY')" 2>$null
if($LASTEXITCODE -ne 0 -or ([string]$module).Trim() -ne 'READY'){
 Write-Host 'AUTH_MODULE_NOT_DEPLOYED: update preview image after source verification.'
 exit 5
}
if(!$IssueKey){
 Write-Host 'PREVIEW_AUTH_READY. Run this script with -IssueKey to create the operator API key.' -ForegroundColor Green
 exit 0
}
Write-Host 'Creating a NEW tenant API key for OLA Core, not a Windows Local Executor token.' -ForegroundColor Cyan
& docker.exe exec $script:Preview python -m scripts.provision_local_operator
if($LASTEXITCODE -ne 0){throw 'KEY_ISSUANCE_FAILED_OR_DUPLICATE_TENANT'}
Write-Host 'Copy X_API_KEY_ONCE into Command Center > SETTINGS > X-API-Key > Verify.' -ForegroundColor Green
Write-Host 'Do not send the key to ChatGPT or store it in your Git repository.'
