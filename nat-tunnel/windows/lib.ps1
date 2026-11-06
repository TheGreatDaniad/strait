# Shared helpers, dot-sourced by the other scripts. Windows PowerShell 5.1 compatible.
$script:StraitRoot = 'C:\strait'
foreach ($d in 'logs', 'results', 'cache', 'bin', 'src') {
    New-Item -ItemType Directory -Force -Path (Join-Path $script:StraitRoot $d) | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$LogFile)
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    if ($LogFile) { Add-Content -Path $LogFile -Value $line }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Make rustup/cargo and winget-installed tools visible in a fresh (e.g. SSH) session.
function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user;$env:USERPROFILE\.cargo\bin"
}

function Get-OsArch {
    # PROCESSOR_ARCHITEW6432 is set for 32-bit processes on 64-bit Windows.
    $a = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($a -eq 'ARM64') { 'arm64' } else { 'amd64' }
}
