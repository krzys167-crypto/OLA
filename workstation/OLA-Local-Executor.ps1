# OLA Windows Local Executor: loopback-only; fixed command list, no arbitrary shell.
param([switch]$SelfTest)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Port=18110
$script:Origins=@('http://127.0.0.1:18081','http://localhost:18081','http://127.0.0.1:18080','http://localhost:18080')
$script:Root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:Approval=@{}
$script:Actions=[ordered]@{
 'docker-containers'=@{label='Docker: kontenery';mode='read';exe='docker.exe';args='ps -a --format "{{.Names}} | {{.Image}} | {{.Status}}"';cwd=''}
 'ola-container'=@{label='OLA: stan kontenera';mode='read';exe='docker.exe';args='inspect --format "{{.State.Status}}" ola-zbook-local';cwd=''}
 'preview-container'=@{label='Command Center: stan kontenera';mode='read';exe='docker.exe';args='inspect --format "{{.State.Status}}" ola-cc-preview';cwd=''}
 'ollama-models'=@{label='Ollama: lista modeli';mode='read';exe='ollama.exe';args='list';cwd=''}
 'wsl-list'=@{label='WSL: dystrybucje';mode='read';exe='wsl.exe';args='--list --verbose';cwd=''}
 'git-status'=@{label='Git: stan repozytorium';mode='read';exe='git.exe';args='status --short --branch --untracked-files=no';cwd=$script:Root}
 'api-health'=@{label='OLA Core: health';mode='read';exe='curl.exe';args='--fail --silent --show-error --max-time 6 http://127.0.0.1:18080/health';cwd=''}
 'preview-health'=@{label='Command Center: health';mode='read';exe='curl.exe';args='--fail --silent --show-error --max-time 6 http://127.0.0.1:18081/health';cwd=''}
 'docker-unpause-ola'=@{label='Wznow kontener OLA Core';mode='confirm';exe='docker.exe';args='unpause ola-zbook-local';cwd=''}
 'docker-start-ola'=@{label='Uruchom kontener OLA Core';mode='confirm';exe='docker.exe';args='start ola-zbook-local';cwd=''}
}
function New-Token {
 $b=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
 try{$rng.GetBytes($b)}finally{$rng.Dispose()}
 [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function Equal-Token([string]$a,[string]$b){
 if(!$a -or !$b){return $false}
 $x=[Text.Encoding]::UTF8.GetBytes($a);$y=[Text.Encoding]::UTF8.GetBytes($b)
 if($x.Length -ne $y.Length){return $false}
 [int]$d=0
 for([int]$i=0;$i -lt $x.Length;$i++){$d=$d -bor ($x[$i] -bxor $y[$i])}
 ($d -eq 0)
}
function Action-List {
 @($script:Actions.GetEnumerator()|ForEach-Object {@{id=$_.Key;label=$_.Value.label;mode=$_.Value.mode}})
}
function Audit([string]$id,[string]$phase,[int]$exit,[string]$output){
 $dir=if(Test-Path -LiteralPath 'D:\' -PathType Container){'D:\OLA-Control'}else{Join-Path $env:LOCALAPPDATA 'OLA-Control'}
 New-Item -ItemType Directory -Path $dir -Force|Out-Null
 $sha=[Security.Cryptography.SHA256]::Create()
 try{$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($output))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 $row=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');action=$id;phase=$phase;exit_code=$exit;output_sha256=$hash;trust='LOCAL_LOG_NOT_INDEPENDENT_VERIFICATION'}
 Add-Content -LiteralPath (Join-Path $dir 'local-executor.jsonl') -Encoding UTF8 -Value ($row|ConvertTo-Json -Compress)
}
function Run-FixedProcess([hashtable]$spec){
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=[string]$spec.exe;$psi.Arguments=[string]$spec.args
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 if($spec.cwd){if(!(Test-Path -LiteralPath $spec.cwd -PathType Container)){throw 'WORKDIR_MISSING'};$psi.WorkingDirectory=[string]$spec.cwd}
 $p=New-Object Diagnostics.Process;$p.StartInfo=$psi
 try{
  [void]$p.Start()
  $outTask=$p.StandardOutput.ReadToEndAsync();$errTask=$p.StandardError.ReadToEndAsync()
  if(!$p.WaitForExit(15000)){try{$p.Kill()}catch{};[void]$p.WaitForExit(3000);throw 'COMMAND_TIMEOUT'}
  $out=($outTask.GetAwaiter().GetResult()+[Environment]::NewLine+$errTask.GetAwaiter().GetResult()).Trim()
  if($out.Length -gt 8000){$out=$out.Substring(0,8000)+' [TRUNCATED]'}
  @{exit_code=[int]$p.ExitCode;output=$out}
 }finally{$p.Dispose()}
}
function Execute([string]$id){
 if(!$script:Actions.Contains($id)){throw 'ACTION_NOT_ALLOWLISTED'}
 Audit $id 'STARTED' -1 ''
 try{
  $v=Run-FixedProcess $script:Actions[$id];Audit $id 'FINISHED' $v.exit_code $v.output
  @{action=$id;status=$(if($v.exit_code -eq 0){'LOCAL_EXECUTED'}else{'COMMAND_FAILED'});exit_code=$v.exit_code;output=$v.output;scope='ZBOOK_LOCAL';production='NOT_VERIFIED'}
 }catch{
  $err=$_.Exception.Message;Audit $id 'FAILED' -1 $err
  @{action=$id;status='COMMAND_FAILED';exit_code=-1;output=$err;scope='ZBOOK_LOCAL';production='NOT_VERIFIED'}
 }
}
function Reply($ctx,[int]$status,$obj,[string]$origin){
 $r=$ctx.Response;$r.StatusCode=$status;$r.ContentType='application/json; charset=utf-8'
 $r.Headers['Cache-Control']='no-store';$r.Headers['X-Content-Type-Options']='nosniff';$r.Headers['Vary']='Origin'
 if($script:Origins -contains $origin){
  $r.Headers['Access-Control-Allow-Origin']=$origin
  $r.Headers['Access-Control-Allow-Headers']='Authorization, Content-Type'
  $r.Headers['Access-Control-Allow-Methods']='GET, POST, OPTIONS'
  $r.Headers['Access-Control-Max-Age']='0'
 }
 $bytes=if($status -eq 204){[byte[]]@()}else{[Text.Encoding]::UTF8.GetBytes(($obj|ConvertTo-Json -Compress -Depth 8))}
 $r.ContentLength64=$bytes.Length
 if($bytes.Length -gt 0){$r.OutputStream.Write($bytes,0,$bytes.Length)}
 $r.Close()
}
function Parse-Body($request){
 [long]$n=$request.ContentLength64
 if($n -lt 2 -or $n -gt 2048){throw 'BAD_BODY_LENGTH'}
 if($request.ContentType -notmatch '^application/json(?:\s*;|$)'){throw 'JSON_REQUIRED'}
 $data=New-Object byte[] ([int]$n)
 [int]$offset=0
 while($offset -lt $n){
  $count=$request.InputStream.Read($data,$offset,([int]$n-$offset))
  if($count -le 0){throw 'INCOMPLETE_BODY'}
  $offset+=$count
 }
 $body=[Text.Encoding]::UTF8.GetString($data)|ConvertFrom-Json
 if($null -eq $body -or $body -isnot [pscustomobject]){throw 'JSON_OBJECT_REQUIRED'}
 if(@($body.PSObject.Properties.Name|Where-Object{$_ -notin @('action','approval')}).Count -gt 0){throw 'UNEXPECTED_FIELDS'}
 if($body.PSObject.Properties.Name -notcontains 'action' -or $body.action -isnot [string] -or $body.action.Length -gt 64){throw 'INVALID_ACTION'}
 $body
}
function Handle($ctx,[string]$token){
 $req=$ctx.Request;$origin=[string]$req.Headers['Origin']
 if([string]$req.Headers['Host'] -ne "127.0.0.1:$script:Port"){Reply $ctx 403 @{error='BAD_HOST'} '';return}
 if(![Net.IPAddress]::IsLoopback($req.RemoteEndPoint.Address) -or $script:Origins -notcontains $origin){Reply $ctx 403 @{error='BAD_ORIGIN'} '';return}
 if($req.HttpMethod -eq 'OPTIONS'){Reply $ctx 204 @{} $origin;return}
 if(!(Equal-Token ([string]$req.Headers['Authorization']) "Bearer $token")){Reply $ctx 401 @{error='TOKEN_REQUIRED'} $origin;return}
 $path=$req.Url.AbsolutePath
 if($req.HttpMethod -eq 'GET' -and $path -eq '/v1/actions'){Reply $ctx 200 @{status='BRIDGE_ONLINE';actions=(Action-List);scope='ZBOOK_LOCAL'} $origin;return}
 if($req.HttpMethod -ne 'POST' -or $path -notin @('/v1/run','/v1/prepare','/v1/execute')){Reply $ctx 404 @{error='NOT_FOUND'} $origin;return}
 try{$body=Parse-Body $req}catch{Reply $ctx 400 @{error=$_.Exception.Message} $origin;return}
 $id=[string]$body.action
 if(!$script:Actions.Contains($id)){Reply $ctx 403 @{error='ACTION_NOT_ALLOWLISTED'} $origin;return}
 $spec=$script:Actions[$id]
 if($path -eq '/v1/run'){
  if($spec.mode -ne 'read'){Reply $ctx 403 @{error='APPROVAL_REQUIRED'} $origin}
  else{Reply $ctx 200 (Execute $id) $origin}
  return
 }
 if($path -eq '/v1/prepare'){
  if($spec.mode -ne 'confirm'){Reply $ctx 403 @{error='ACTION_READ_ONLY'} $origin;return}
  $nonce=New-Token
  $script:Approval=@{id=$id;nonce=$nonce;expires=[DateTime]::UtcNow.AddSeconds(30)}
  Reply $ctx 200 @{action=$id;description=$spec.label;command=($spec.exe+' '+$spec.args);approval=$nonce;expires_seconds=30} $origin;return
 }
 # Single-use nonce consumed before executing any state-changing action.
 $pending=$script:Approval;$script:Approval=@{}
 $given=if($body.PSObject.Properties.Name -contains 'approval'){[string]$body.approval}else{''}
 if($spec.mode -ne 'confirm' -or !$pending.ContainsKey('id') -or !$pending.ContainsKey('nonce') -or !$pending.ContainsKey('expires') -or $pending.id -ne $id -or [DateTime]::UtcNow -gt $pending.expires -or !(Equal-Token $given $pending.nonce)){
  Reply $ctx 403 @{error='APPROVAL_EXPIRED_OR_INVALID'} $origin;return
 }
 Reply $ctx 200 (Execute $id) $origin
}
if($SelfTest){
 if(@(Action-List).Count -ne 10){throw 'ACTION_COUNT_FAIL'}
 if($script:Actions['docker-unpause-ola'].mode -ne 'confirm'){throw 'MUTATION_UNGUARDED'}
 if(!(Equal-Token 'Bearer abc' 'Bearer abc')){throw 'TOKEN_COMPARE_FAIL'}
 if(Equal-Token 'Bearer xyz' 'Bearer abc'){throw 'TOKEN_FALSE_POSITIVE'}
 if($script:Origins -contains 'https://example.com'){throw 'ORIGIN_FALSE_POSITIVE'}
 Write-Host 'OLA_LOCAL_EXECUTOR_SELFTEST=PASS';exit 0
}
if($env:OS -ne 'Windows_NT'){throw 'WINDOWS_REQUIRED'}
$token=New-Token
$server=New-Object System.Net.HttpListener
$server.Prefixes.Add("http://127.0.0.1:$script:Port/")
try{$server.Start()}catch{throw "LOOPBACK_BIND_BLOCKED: $($_.Exception.Message)"}
Write-Host 'OLA LOCAL EXECUTOR - ZBOOK' -ForegroundColor Cyan
Write-Host "ADDRESS: http://127.0.0.1:$script:Port"
Write-Host "LOCAL TOKEN: $token" -ForegroundColor Yellow
Write-Host 'Podaj token tylko w panelu; nie wysylaj go do czatu. Zatrzymaj przez Ctrl+C.'
try{
 while($server.IsListening){
  $ctx=$server.GetContext()
  try{Handle $ctx $token}catch{
   try{Reply $ctx 500 @{error='INTERNAL_LOCAL_ERROR'} ([string]$ctx.Request.Headers['Origin'])}catch{}
   Write-Warning ('Executor internal error: '+$_.Exception.GetType().Name)
  }
 }
}finally{$server.Stop();$server.Close()}
