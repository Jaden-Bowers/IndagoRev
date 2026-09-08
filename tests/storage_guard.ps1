# Shared preflight/poll guard for bounded development checks; not an OS quota.
function Assert-IndagoStorage {
  param([string]$Path, [UInt64]$MinimumFreeBytes=21474836480, [UInt64]$ReserveBytes=536870912)
  $absolute=[IO.Path]::GetFullPath($Path)
  $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($absolute))
  if(-not $drive.IsReady){throw 'Storage volume is not ready'}
  $available=[UInt64]$drive.AvailableFreeSpace
  if($available -lt $MinimumFreeBytes -or $ReserveBytes -gt ($available-$MinimumFreeBytes)){
    throw "Storage budget unavailable: $available bytes free; floor $MinimumFreeBytes plus reservation $ReserveBytes required"
  }
  return $available
}
