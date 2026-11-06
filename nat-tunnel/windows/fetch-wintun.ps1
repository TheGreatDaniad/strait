<#
 Downloads Wintun, verifies the pinned SHA-256, and extracts wintun.dll for arm64 and amd64.
 Pin source: https://www.wintun.net (page lists builds/wintun-0.14.1.zip, SHA2-256 below), looked up 2026-11-06.
 Usage: fetch-wintun.ps1 [-Dest C:\strait\bin]   (copies the dll matching this OS's architecture to -Dest)
#>
param([string]$Dest = 'C:\strait\bin')
. "$PSScriptRoot\lib.ps1"
$log = 'C:\strait\logs\fetch-wintun.log'
$ErrorActionPreference = 'Stop'
$version = '0.14.1'
$url = "https://www.wintun.net/builds/wintun-$version.zip"
$sha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'

$zip = "C:\strait\cache\wintun-$version.zip"
$have = $false
if (Test-Path $zip) { $have = ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -eq $sha256) }
if (-not $have) {
    Write-Log "downloading $url" $log
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
}
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $sha256) {
    Remove-Item $zip -Force
    Write-Log "ERROR: SHA-256 mismatch: got $actual, pinned $sha256" $log
    exit 5
}
Write-Log "SHA-256 verified ($sha256)" $log

$ex = "C:\strait\cache\wintun-$version"
if (Test-Path $ex) { Remove-Item $ex -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $ex -Force
foreach ($a in 'arm64', 'amd64') {
    $dll = Join-Path $ex "wintun\bin\$a\wintun.dll"
    if (-not (Test-Path $dll)) { Write-Log "ERROR: missing $dll" $log; exit 6 }
    New-Item -ItemType Directory -Force -Path "C:\strait\wintun\$a" | Out-Null
    Copy-Item $dll "C:\strait\wintun\$a\wintun.dll" -Force
}
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "C:\strait\wintun\$(Get-OsArch)\wintun.dll" (Join-Path $Dest 'wintun.dll') -Force
Write-Log "wintun.dll ($(Get-OsArch)) copied to $Dest" $log
exit 0
