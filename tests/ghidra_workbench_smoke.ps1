param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[string]$Fixture="$PSScriptRoot/../out/build/Release/indago_runtime_fixture.exe")
$ErrorActionPreference='Stop'
$workspace=Join-Path $env:TEMP ('indago-ghidra-'+[guid]::NewGuid().ToString('N'))
function Native([string[]]$Command){$raw=& $Executable --workspace $workspace @Command;if($LASTEXITCODE -notin @(0,3)){throw "$Command : $raw"};return $raw|ConvertFrom-Json}
function Query($operation,$arguments=@{},$address='',$items=32){
  $request=@{project='smoke';backend='ghidra';operation=$operation;address=$address;arguments=$arguments;budget=@{max_items=$items;wall_ms=120000;output_bytes=1048576}}
  $path=Join-Path $workspace 'action.json'
  $request|ConvertTo-Json -Depth 20|Set-Content $path -Encoding utf8
  return Native @('action','run','--request',$path)
}
$null=Native @('project','create','--name','smoke')
$null=Native @('target','import','--project','smoke','--file',(Resolve-Path $Fixture).Path)
$first=Query 'functions' @{} '' 1
if(!$first.data.pagination.next_cursor){throw 'No continuation'}
$second=Query 'functions' @{cursor=$first.data.pagination.next_cursor} '' 1
if($first.data.functions[0].entry -eq $second.data.functions[0].entry){throw 'Repeated page'}
$find=Query 'functions' @{search='runtime_probe'} '' 8
$address=$find.data.functions[0].entry
if(!$address){throw 'No probe'}
$pcode=Query 'pcode' @{} $address 64
if(!$pcode.data.pcode.operations.Count -or !$pcode.data.pcode.varnodes.Count){throw 'No native p-code'}
if(!$pcode.index.entities -or !$pcode.index.relations -or !$pcode.evidence_ids.Count){throw 'P-code evidence was not indexed'}
$tokens=Query 'tokens' @{} $address 128
foreach($token in $tokens.data.decompilation.tokens){
  if($tokens.data.decompilation.rendered_c.Substring($token.rendered_offset,$token.rendered_end-$token.rendered_offset) -ne $token.text){throw 'Token mapping mismatch'}
}
$revision=$tokens.data.program_revision
$edit=Query 'annotate' @{expected_revision=$revision;annotation=@{kind='rename';name='renamed_probe'}} $address
if($edit.data.program_revision -ne $revision+1){throw 'Revision not incremented'}
$null=Query 'close'
Start-Sleep -Milliseconds 300
$reopened=Query 'functions' @{search='renamed_probe'}
if(!$reopened.data.functions.Count){throw 'Annotation did not survive reopen'}
$session=Query 'session'
if($session.data.session.revision -ne $edit.data.program_revision){throw 'Session revision mismatch'}
$flow=Query 'control_flow' @{} $address
if(!$flow.data.control_flow.exception_tls_coverage){throw 'Missing coverage statement'}
$structure=Query 'annotate' @{expected_revision=$flow.data.program_revision;annotation=@{kind='create_structure';name='SmokeRecord';size=8;fields=@()}} $address
if($structure.data.program_revision -ne $flow.data.program_revision+1){throw 'Structure revision not incremented'}
$rejected=$false
try {$null=Query 'functions' @{cursor=$first.data.pagination.next_cursor} '' 1} catch {if($_.Exception.Message -match 'stale or mismatched cursor'){$rejected=$true}else{throw}}
if(!$rejected){throw 'Stale cursor was accepted'}
$null=Query 'close'
$inventory=Query 'functions' @{profile='inventory'}
$analyzed=Query 'analyze' @{profile='inventory';expected_revision=$inventory.data.program_revision} $address
if($analyzed.data.program_revision -ne $inventory.data.program_revision+1){throw 'Analysis revision not incremented'}
$null=Query 'close' @{profile='inventory'}
[pscustomobject]@{status='passed';workspace=$workspace;address=$address;revision=$edit.data.program_revision}|ConvertTo-Json -Compress
