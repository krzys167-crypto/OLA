# OLA DI-OS ZBook preview auth: read-only by default.
# -IssueKey creates a new tenant credential ONLY in the already configured preview.
[CmdletBinding()]
param([switch]$IssueKey,[switch]$CreatePreview,[switch]$SelfTest,[string]$ExpectedSha='', [string]$Model='')
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

function New-PreviewSecretFile {
 $secretDir=Join-Path $env:LOCALAPPDATA 'OLA-Control\secrets'
 $secretPath=Join-Path $secretDir 'preview.env'
 if(Test-Path -LiteralPath $secretPath){throw 'PREVIEW_SECRET_FILE_ALREADY_EXISTS'}
 New-Item -ItemType Directory -Path $secretDir -Force|Out-Null
 $username=[Security.Principal.WindowsIdentity]::GetCurrent().Name
 $acl=Get-Acl -LiteralPath $secretDir
 $acl.SetAccessRuleProtection($true,$false)
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($username,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
 Set-Acl -LiteralPath $secretDir -AclObject $acl
 $bytes=New-Object byte[] 48
 $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
 try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
 $pepper=[Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
 [IO.File]::WriteAllText($secretPath,("OLA_API_KEY_PEPPER="+$pepper+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
 $aclFile=Get-Acl -LiteralPath $secretPath
 $aclFile.SetAccessRuleProtection($true,$false)
 $aclFile.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($username,'FullControl','Allow')))
 Set-Acl -LiteralPath $secretPath -AclObject $aclFile
 $secretPath
}
function Create-Preview {
 if(Get-Preview){throw 'PREVIEW_EXISTS: no existing data will be modified or replaced'}
 if($ExpectedSha -notmatch '^[a-f0-9]{40}$'){throw 'EXPECTED_SOURCE_SHA_REQUIRED'}
 $repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
 if(!(Test-Path -LiteralPath (Join-Path $repo '.git'))){throw 'CHECKOUT_REQUIRED'}
 $actual=(& git.exe -C $repo rev-parse HEAD).Trim()
 if($LASTEXITCODE -ne 0 -or $actual -ne $ExpectedSha){throw 'SOURCE_SHA_MISMATCH'}
 $branch=(& git.exe -C $repo branch --show-current).Trim()
 if($branch -ne 'ui/ola-command-center-live-20261014'){throw 'UNEXPECTED_GIT_BRANCH'}
 $dirty=@(& git.exe -C $repo status --porcelain)
 if($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0){throw 'DIRTY_CHECKOUT_BLOCKED'}
 if(!(Test-Path -LiteralPath (Join-Path $repo 'scripts\provision_local_operator.py'))){throw 'PROVISION_MODULE_MISSING'}
 try{$tags=Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5}
 catch{throw 'OLLAMA_NOT_AVAILABLE: start host Ollama first'}
 $available=@($tags.models|ForEach-Object{$_.name})
 if(!$Model){
  $localModels=@($available|Where-Object{$_ -and $_ -notmatch ':cloud$'})
  if($localModels.Count -eq 0){throw 'NO_LOCAL_OLLAMA_MODEL'}
  $Model=[string]$localModels[0]
 }
 if($Model -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.\/-]{0,95}(:[a-zA-Z0-9_.-]{1,32})?$'){throw 'INVALID_OLLAMA_MODEL_NAME'}
 if($Model -notin $available){throw 'OLLAMA_MODEL_NOT_PRESENT'}
 $volume='ola-cc-preview-data'
 & docker.exe volume inspect $volume *> $null
 if($LASTEXITCODE -eq 0){throw 'PREVIEW_VOLUME_EXISTS: manual review required'}
 $secretFile=New-PreviewSecretFile
 $image='ola-cc-preview:'+($ExpectedSha.Substring(0,12))
 & docker.exe build -t $image $repo
 if($LASTEXITCODE -ne 0){throw 'BUILD_FAILED: no container created'}
 & docker.exe volume create $volume | Out-Null
 if($LASTEXITCODE -ne 0){throw 'VOLUME_CREATE_FAILED'}
 $arguments=@(
  'run','-d','--name',$script:Preview,'--restart','no',
  '--memory','2g','--env-file',$secretFile,
  '--env',('OLA_RUNTIME_COMMIT='+$ExpectedSha),
  '--env','OLA_LLM_PROVIDER=ollama','--env','OLA_CHAT_PROVIDER=ollama',
  '--env',('OLA_LLM_MODEL='+$Model),'--env',('OLA_CHAT_MODEL='+$Model),
  '--env','OLA_LLM_MODE=required',
  '--env','OLLAMA_BASE_URL=http://host.docker.internal:11434',
  '--add-host','host.docker.internal:host-gateway',
  '--mount',('type=volume,source='+$volume+',target=/data'),
  '--publish','127.0.0.1:18081:8000',
  '--label',('ola.source_sha='+$ExpectedSha),$image
 )
 & docker.exe @arguments | Out-Null
 if($LASTEXITCODE -ne 0){throw 'PREVIEW_START_FAILED: volume and secret preserved for manual diagnosis'}
 $ready=$false
 for($i=0;$i -lt 20;$i++){
  Start-Sleep -Seconds 2
  try{
   $response=Invoke-RestMethod 'http://127.0.0.1:18081/health' -TimeoutSec 5
   if($response.status -eq 'ok'){$ready=$true;break}
  }catch{}
 }
 if(!$ready){throw 'PREVIEW_HEALTH_FAILED: previous OLA services unchanged'}
 Write-Host 'OLA PREVIEW CREATED / HEALTH PASS / PERSISTENT SQLITE / SOURCE PINNED' -ForegroundColor Green
 Write-Host 'Random pepper stored in restricted LocalAppData; it was not printed.'
 Write-Host 'Run -IssueKey separately to create the first tenant credential.'
}

if($SelfTest){
 if($script:Preview -ne 'ola-cc-preview'){throw 'PREVIEW_NAME_CHANGED'}
 Write-Host 'OLA_PREVIEW_AUTH_SELFTEST=PASS';exit 0
}
if($IssueKey -and $CreatePreview){throw 'USE_ONLY_ONE_WRITE_MODE'}
if($CreatePreview -and !(Get-Command git.exe -ErrorAction SilentlyContinue)){throw 'GIT_CLI_MISSING'}
if(!(Get-Command docker.exe -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
if($CreatePreview){Create-Preview;exit 0}
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
