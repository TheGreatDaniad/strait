# Build nat-tunnel for Windows and place wintun.dll next to the executable.
#
# Examples:
#   .\scripts\windows-build.ps1 -Target aarch64-pc-windows-msvc
#   .\scripts\windows-build.ps1 -Target x86_64-pc-windows-msvc -Headless
#
# Wintun is downloaded from wintun.net (0.14.1 is the latest release). The DLL
# must sit beside nat-tunnel.exe or in the working directory.

param(
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")]
    [string]$Target = "aarch64-pc-windows-msvc",

    [string]$WintunVersion = "0.14.1",

    # Build the CLI/TUI binary without the egui desktop UI.
    [switch]$Headless
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Push-Location $root
try {
    rustup target add $Target

    # Link the C runtime statically so a fresh Windows install does not need
    # the VC++ redistributable.
    $env:RUSTFLAGS = "-C target-feature=+crt-static"

    if ($Headless) {
        cargo build --release --target $Target --no-default-features
    } else {
        cargo build --release --target $Target
    }
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    $out = Join-Path $root "target\$Target\release"
    $zip = Join-Path $env:TEMP "wintun-$WintunVersion.zip"
    $extract = Join-Path $env:TEMP "wintun-$WintunVersion"
    $url = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"

    if (-not (Test-Path $zip)) {
        Write-Host "Downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $zip
    }
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $extract -Force

    $arch = if ($Target -like "aarch64*") { "arm64" } else { "amd64" }
    $dll = Join-Path $extract "wintun\bin\$arch\wintun.dll"
    if (-not (Test-Path $dll)) { throw "wintun.dll not found at $dll" }
    Copy-Item $dll $out -Force

    $exe = Join-Path $out "nat-tunnel.exe"
    Write-Host ""
    Write-Host "Built:"
    Write-Host "  $exe"
    Write-Host "  $(Join-Path $out 'wintun.dll')"
    Write-Host ""
    Write-Host "Run the GUI as Administrator:"
    Write-Host "  $exe gui"
} finally {
    Pop-Location
}
