param([ValidateSet('windows','linux','both')][string]$Platform='both')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
if((Get-PSDrive C).Free -lt 21GB){throw '20 GiB floor plus build reserve required'}
$pins=@{windows='37285ec7244384ffd382841f93fd23335aae846c92016a132d765c60f27a2f31';linux='83f8122e924745fcd70636e3594bc01c4c47f2d4c8f3c63b5d70d3f83a482677'}
$selected=if($Platform -eq 'both'){@('windows','linux')}else{@($Platform)}
foreach($os in $selected){
 $cache=Join-Path $repo "out/wabt-1.0.41-$os";New-Item -ItemType Directory -Force $cache | Out-Null
 $archive=Join-Path $cache 'package.tar.gz'
 if(!(Test-Path -LiteralPath $archive)){Invoke-WebRequest "https://github.com/WebAssembly/wabt/releases/download/1.0.41/wabt-1.0.41-$os-x64.tar.gz" -OutFile $archive}
 if((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant() -ne $pins[$os]){throw 'WABT archive hash mismatch'}
 & tar -xf $archive -C $cache
 if($LASTEXITCODE -ne 0){throw 'WABT extraction failed'}
 $dest=Join-Path $repo "out/runtime-payload/$os/ilspy/tools/wabt";New-Item -ItemType Directory -Force $dest | Out-Null
 $suffix=if($os -eq 'windows'){'.exe'}else{''}
 $tool=Get-ChildItem $cache -Recurse -File -Filter "wasm2wat$suffix" | Select-Object -First 1
 if(!$tool){throw 'Expected WABT tool missing'}
 Copy-Item -LiteralPath $tool.FullName -Destination $dest
 $license=Join-Path $cache 'LICENSE'
 if(!(Test-Path -LiteralPath $license)){Invoke-WebRequest 'https://raw.githubusercontent.com/WebAssembly/wabt/1.0.41/LICENSE' -OutFile $license}
 if((Get-FileHash -Algorithm SHA256 -LiteralPath $license).Hash.ToLowerInvariant() -ne 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'){throw 'WABT license hash mismatch'}
 Copy-Item -LiteralPath $license -Destination (Join-Path $dest 'LICENSE')
 Copy-Item -LiteralPath (Join-Path $repo 'workers/ilspy/wabt-provenance.json') -Destination $dest
}
