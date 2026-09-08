param(
  [string]$CorpusRoot="$PSScriptRoot/../flare-on-chals/Flare-On-Challenges/Challenges",
  [ValidateRange(1,1024)][int]$MaxFiles=512,
  [ValidateRange(1,60000)][int]$MaxEntries=10000,
  [ValidateRange(1,120)][int]$TimeoutSeconds=60,
  [ValidateRange(0,268435456)][long]$HashBudgetBytes=67108864,
  [ValidateRange(0,67108864)][long]$MaxFileHashBytes=16777216,
  [UInt64]$MinimumFreeBytes=21474836480
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/storage_guard.ps1"
$root=(Resolve-Path -LiteralPath $CorpusRoot).Path
$free=Assert-IndagoStorage -Path $root -MinimumFreeBytes $MinimumFreeBytes -ReserveBytes 2097152
# Do not follow any junction/symlink in the source root or its ancestry.
$ancestor=[IO.DirectoryInfo]::new($root)
while($null -ne $ancestor){
  if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Corpus root traverses a reparse point'}
  $ancestor=$ancestor.Parent
}
$clock=[Diagnostics.Stopwatch]::StartNew()
$queue=[Collections.Generic.Queue[string]]::new()
$queue.Enqueue($root)
$files=[Collections.Generic.List[object]]::new()
$visited=0;$excluded=0;$hashed=0L;$total=0L;$partial=$false;$reason=''
while($queue.Count -gt 0 -and -not $partial){
  $directory=$queue.Dequeue()
  foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)){
    if($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds -or $visited -ge $MaxEntries -or $files.Count -ge $MaxFiles){
      $partial=$true;$reason='time, traversal or file-count budget';break
    }
    ++$visited
    $name=[IO.Path]::GetFileName($entry)
    $attributes=[IO.File]::GetAttributes($entry)
    if(($attributes -band [IO.FileAttributes]::ReparsePoint) -or $name -match '^(?i:write[-_ ]?ups?|solutions?|\.git)$'){
      ++$excluded;continue
    }
    if($attributes -band [IO.FileAttributes]::Directory){$queue.Enqueue($entry);continue}
    if([IO.Path]::GetExtension($entry) -match '^(?i:\.md|\.txt|\.html?|\.pdf|\.url)$'){++$excluded;continue}
    $file=[IO.FileInfo]::new($entry)
    $length=$file.Length;$total+=$length
    $relative=$entry.Substring($root.TrimEnd('\','/').Length+1).Replace('\','/')
    if($relative.Length -gt 4096){++$excluded;continue}
    $digest=$null;$hashStatus='byte_budget';$format='uninspected'
    if($length -le $MaxFileHashBytes -and $length -le ($HashBudgetBytes-$hashed)){
      # Open read-only, deny writers/deletion while bounded hashing is in progress.
      $stream=[IO.File]::Open($entry,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
      $sha=[Security.Cryptography.SHA256]::Create()
      try {
        if($stream.Length -ne $length){throw 'Corpus entry changed before hashing'}
        $header=New-Object byte[] 4
        $n=$stream.Read($header,0,4);$stream.Position=0
        if($n -ge 2 -and $header[0] -eq 77 -and $header[1] -eq 90){$format='MZ_candidate'}
        elseif($n -eq 4 -and $header[0] -eq 127 -and $header[1] -eq 69 -and $header[2] -eq 76 -and $header[3] -eq 70){$format='ELF_candidate'}
        elseif($n -ge 2 -and $header[0] -eq 80 -and $header[1] -eq 75){$format='ZIP_candidate'}
        else{$format='other_bytes'}
        $buffer=New-Object byte[] 65536
        $readTotal=0L
        while(($read=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
          if($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds){$partial=$true;$reason='time budget while hashing';break}
          $readTotal+=$read;$hashed+=$read
          if($readTotal -gt $length){throw 'Corpus entry grew while hashing'}
          [void]$sha.TransformBlock($buffer,0,$read,$null,0)
        }
        if(-not $partial){
          if($readTotal -ne $length){throw 'Corpus entry changed while hashing'}
          [void]$sha.TransformFinalBlock([byte[]]@(),0,0)
          $digest=([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant();$hashStatus='complete'
        }else{$hashStatus='interrupted'}
      }finally{$sha.Dispose();$stream.Dispose()}
    }
    $files.Add([ordered]@{path=$relative;bytes=$length;sha256=$digest;hash_status=$hashStatus;format_hint=$format;execution='not_executed';verifier='not_configured'})
    if($partial){break}
  }
}
$unhashed=@($files.ToArray()|Where-Object {$_['hash_status'] -ne 'complete'}).Count
if($unhashed -gt 0 -and -not $reason){$reason='one or more hashes omitted for byte budget'}
$result=[ordered]@{schema='indago.corpus-catalogue.v1';root=$root;partial=($partial -or $unhashed -gt 0);listing_complete=(-not $partial);hashes_complete=($unhashed -eq 0 -and -not $partial);unhashed_files=$unhashed;limitation=$reason;entries_visited=$visited;excluded=$excluded;bytes_listed=$total;bytes_hashed=$hashed;free_bytes_at_start=$free;elapsed_seconds=$clock.Elapsed.TotalSeconds;archives_extracted=$false;solution_retrieval=$false;selection='bounded filesystem enumeration; not a frozen all-challenges benchmark';files=@($files.ToArray()|Sort-Object {$_['path']})}
$json=$result|ConvertTo-Json -Depth 8 -Compress
if([Text.Encoding]::UTF8.GetByteCount($json) -gt 2097152){throw 'Catalogue exceeds 2 MiB output budget'}
$json
