<#
 Builds nat-tunnel natively with all five rendezvous features, the ss/ws/awg carriers and the GUI (= the default feature set),
 then copies the exe and wintun.dll to C:\strait\bin. Source must already be in -Src (run-remote.sh stages it).
 Log: C:\strait\logs\build.log
#>
param([string]$Src = 'C:\strait\src', [string]$Bin = 'C:\strait\bin')
. "$PSScriptRoot\lib.ps1"
$log = 'C:\strait\logs\build.log'
$ErrorActionPreference = 'Continue'
Update-SessionPath
if (-not (Test-Path "$Src\Cargo.toml")) { Write-Log "ERROR: no Cargo.toml in $Src" $log; exit 2 }

& "$PSScriptRoot\fetch-wintun.ps1" -Dest $Bin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (Test-Path 'C:\Program Files\LLVM\bin') { $env:Path += ';C:\Program Files\LLVM\bin' }  # clang for ring on ARM64
$env:CARGO_TARGET_DIR = 'C:\strait\target'
$env:CARGO_TERM_COLOR = 'never'
Push-Location $Src
try {
    Write-Log 'cargo build --release --features gui,rv-sig,rv-trk,rv-nostr,rv-dht,rv-ntfy,rv-mqtt,cr-ss,cr-ws,cr-awg' $log
    & cargo build --release --features 'gui,rv-sig,rv-trk,rv-nostr,rv-dht,rv-ntfy,rv-mqtt,cr-ss,cr-ws,cr-awg' 2>&1 | Tee-Object -FilePath $log -Append
    $rc = $LASTEXITCODE
} finally { Pop-Location }
if ($rc -ne 0) { Write-Log "ERROR: cargo build failed ($rc)" $log; exit 10 }

New-Item -ItemType Directory -Force -Path $Bin | Out-Null
Copy-Item 'C:\strait\target\release\nat-tunnel.exe' $Bin -Force
if (-not (Test-Path "$Bin\wintun.dll")) { Write-Log 'ERROR: wintun.dll missing beside exe' $log; exit 11 }
& "$Bin\nat-tunnel.exe" --version 2>&1 | Tee-Object -FilePath $log -Append
Write-Log "build OK -> $Bin" $log
exit 0
