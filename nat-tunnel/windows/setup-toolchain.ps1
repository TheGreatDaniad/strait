<#
 Installs Rust (rustup) and the Visual Studio 2022 Build Tools (C++ workload, ARM64 tools,
 Windows SDK) with winget. Idempotent: every step checks first. Needs an elevated shell.
 Log: C:\strait\logs\setup-toolchain.log
#>
. "$PSScriptRoot\lib.ps1"
$log = 'C:\strait\logs\setup-toolchain.log'
$ErrorActionPreference = 'Continue'
Write-Log "setup-toolchain start (arch $(Get-OsArch))" $log
if (-not (Test-Admin)) { Write-Log 'ERROR: not elevated' $log; exit 2 }

function Find-BuildTools {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { return $false }
    $req = @('Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
             'Microsoft.VisualStudio.Component.VC.Tools.ARM64',
             'Microsoft.VisualStudio.Component.Windows11SDK.22621')
    $args = @('-products', '*', '-latest', '-property', 'installationPath', '-requires') + $req
    $p = & $vswhere @args 2>$null
    return [bool]$p
}

# 1. Visual Studio Build Tools
if (Find-BuildTools) {
    Write-Log 'Build Tools with VC x64+ARM64 and SDK already present' $log
} else {
    Write-Log 'installing Visual Studio 2022 Build Tools (this takes 10-30 min)' $log
    $override = '--quiet --wait --norestart --nocache ' +
        '--add Microsoft.VisualStudio.Workload.VCTools ' +
        '--add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ' +
        '--add Microsoft.VisualStudio.Component.VC.Tools.ARM64 ' +
        '--add Microsoft.VisualStudio.Component.Windows11SDK.22621 ' +
        '--includeRecommended'
    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-source-agreements --accept-package-agreements --override $override 2>&1 | Tee-Object -FilePath $log -Append
    Write-Log "winget BuildTools exit $LASTEXITCODE" $log
    if (-not (Find-BuildTools)) {
        # 3010 = reboot required but installed; anything else with missing components is fatal.
        Write-Log 'ERROR: Build Tools components still missing after install' $log
        exit 3
    }
}

# 1b. LLVM/clang: `ring` (rustls) builds its ARM64 assembly with clang on aarch64-pc-windows-msvc; cl.exe is not enough
# (verified on the VM: "failed to find tool clang"). x64 hosts do not need it.
if ((Get-OsArch) -eq 'arm64' -and -not (Test-Path 'C:\Program Files\LLVM\bin\clang.exe')) {
    Write-Log 'installing LLVM (clang) for ring on ARM64' $log
    winget install --id LLVM.LLVM -e --silent --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $log -Append
    Write-Log "winget LLVM exit $LASTEXITCODE" $log
}

# 2. rustup
Update-SessionPath
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    Write-Log 'installing rustup' $log
    winget install --id Rustlang.Rustup -e --accept-source-agreements --accept-package-agreements 2>&1 | Tee-Object -FilePath $log -Append
    Write-Log "winget rustup exit $LASTEXITCODE" $log
    Update-SessionPath
}
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) { Write-Log 'ERROR: rustup not found after install' $log; exit 4 }

& rustup default stable 2>&1 | Tee-Object -FilePath $log -Append
& rustup target add aarch64-pc-windows-msvc 2>&1 | Tee-Object -FilePath $log -Append
if ((Get-OsArch) -eq 'amd64') { & rustup target add x86_64-pc-windows-msvc 2>&1 | Tee-Object -FilePath $log -Append }

$v = (& rustc --version) 2>&1
$h = (& rustc -vV | Select-String '^host:') 2>&1
Write-Log "rustc: $v ($h)" $log
Write-Log 'setup-toolchain OK' $log
exit 0
