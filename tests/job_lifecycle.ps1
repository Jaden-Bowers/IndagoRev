param([string]$Executable = "$PSScriptRoot/../out/build/Release/indago.exe")
$ErrorActionPreference='Stop'
$workspace=Join-Path ([IO.Path]::GetTempPath()) ('indago-jobs-'+[guid]::NewGuid().ToString('N'))
function Invoke-JobCli([string[]]$Arguments){$raw=& $Executable --workspace $workspace @Arguments;if($LASTEXITCODE -notin @(0,3)){throw "Job command failed: $raw"};return ($raw|ConvertFrom-Json)}
$null=Invoke-JobCli @('project','create','--name','demo')
$null=Invoke-JobCli @('target','import','--project','demo','--file',"$PSScriptRoot/../xair/XAIR/tests/corpus/phase3/control-flow.pe64")
$request=Join-Path $workspace 'action.json'
[IO.File]::WriteAllText($request,(@{project='demo';backend='xair';operation='inventory';idempotency_key='once'}|ConvertTo-Json -Compress))
$first=Invoke-JobCli @('action','submit','--request',$request)
$second=Invoke-JobCli @('action','submit','--request',$request)
if($first.id -ne $second.id){throw 'Duplicate job created'}
$deadline=[DateTime]::UtcNow.AddSeconds(30)
do {
    $job=(Invoke-JobCli @('job','show','--project','demo','--id',$first.id)).jobs[0]
    if($job.status -notin @('queued','running')){break}
    if([DateTime]::UtcNow -gt $deadline){throw 'Asynchronous worker did not finish'}
    Start-Sleep -Milliseconds 50
} while($true)
if($job.status -notin @('completed','partial')){throw "Worker failed: $($job | ConvertTo-Json -Depth 4)"}
$cached=Invoke-JobCli @('action','run','--request',$request)
if($cached.request_id -ne $first.id){throw 'Completed request reran'}
$events=Invoke-JobCli @('job','events','--project','demo','--id',$first.id)
if(@($events.events|Where-Object kind -eq 'started').Count -ne 1){throw 'Job executed more than once'}
Write-Output "Asynchronous idempotency and lifecycle verified: $workspace"
