$ErrorActionPreference='Stop'
. "$PSScriptRoot/storage_guard.ps1"
$root=Join-Path ([IO.Path]::GetTempPath()) ('indago-catalogue-tests-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'Challenges'))
[void][IO.Directory]::CreateDirectory((Join-Path $root 'Challenges/Write-ups'))
[IO.File]::WriteAllBytes((Join-Path $root 'Challenges/tiny.exe'),[byte[]]@(77,90,0,0))
[IO.File]::WriteAllBytes((Join-Path $root 'Challenges/tiny.zip'),[byte[]]@(80,75,3,4))
[IO.File]::WriteAllText((Join-Path $root 'Challenges/README.md'),'must not enter catalogue')
[IO.File]::WriteAllBytes((Join-Path $root 'Challenges/Write-ups/answer.bin'),[byte[]]@(1,2,3))
$catalogue=& "$PSScriptRoot/corpus_catalogue.ps1" -CorpusRoot "$root/Challenges" -HashBudgetBytes 4 -MaxFileHashBytes 4 -TimeoutSeconds 5 | ConvertFrom-Json
if($catalogue.files.Count -ne 2 -or -not $catalogue.partial -or $catalogue.hashes_complete -or $catalogue.unhashed_files -ne 1 -or $catalogue.bytes_hashed -ne 4){throw 'Hash/read accounting failed'}
if($catalogue.excluded -ne 2 -or $catalogue.archives_extracted -or $catalogue.solution_retrieval){throw 'Corpus exclusion or execution policy failed'}
$limited=& "$PSScriptRoot/corpus_catalogue.ps1" -CorpusRoot "$root/Challenges" -MaxFiles 1 -TimeoutSeconds 5 | ConvertFrom-Json
if(-not $limited.partial -or $limited.files.Count -ne 1){throw 'File bound failed'}
$refused=$false
try { $null=Assert-IndagoStorage -Path $root -MinimumFreeBytes ([UInt64]::MaxValue) -ReserveBytes 0 }catch{$refused=$true}
if(-not $refused){throw 'Low disk refusal failed'}
$complete=& "$PSScriptRoot/corpus_catalogue.ps1" -CorpusRoot "$root/Challenges" -HashBudgetBytes 8 -MaxFileHashBytes 4 -TimeoutSeconds 5 | ConvertFrom-Json
if(-not $complete.hashes_complete -or $complete.files[0].path -ne 'tiny.exe' -or $complete.files[0].format_hint -ne 'MZ_candidate'){throw 'Complete bounded catalogue failed'}
[ordered]@{status='passed';checks='hash budget, exclusions, file bound, free-space refusal, deterministic output ordering';fixture=$root;target_execution=$false}|ConvertTo-Json -Compress
