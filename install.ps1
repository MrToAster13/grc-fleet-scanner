#!/usr/bin/env pwsh
# install.ps1: Windows signpost. The scanner's run host must be Linux; this file
# exists so `.\install.ps1` prints a next action instead of a "not recognized"
# error. It installs nothing. The real installer is ./install.sh, run from a
# Linux shell (WSL2, a VM, or a Linux box).

$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    Write-Host "You are not on Windows. Run the bash installer instead:"
    Write-Host "  ./install.sh"
    exit 1
}

Write-Host "grc-fleet-scanner does not run on Windows directly."
Write-Host "The run host has to be Linux. Use WSL2:"
Write-Host ""

$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
$distros = @()
if ($wsl) {
    # -l -q lists installed distros, one per line. No output means WSL is
    # present but has no distro yet. wsl.exe writes UTF-16LE, so read it with a
    # matching console encoding or every name comes back interleaved with nulls.
    $prevEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $distros = @(& wsl.exe -l -q 2>$null |
            ForEach-Object { $_ -replace "`0", '' } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ })
    } catch {
        $distros = @()
    } finally {
        [Console]::OutputEncoding = $prevEncoding
    }
}

if ($distros.Count -eq 0) {
    Write-Host "  1. wsl --install -d Ubuntu     # then reboot if prompted"
    Write-Host "  2. Open the Ubuntu terminal and set a username and password"
    Write-Host "  3. Re-run the install there:"
} else {
    Write-Host "WSL is already installed here ($($distros -join ', '))."
    Write-Host "Open that Linux terminal and run:"
}

Write-Host ""
Write-Host "     git clone https://github.com/MrToAster13/grc-fleet-scanner.git"
Write-Host "     cd grc-fleet-scanner"
Write-Host "     ./install.sh"
Write-Host "     grc-setup"
Write-Host ""
Write-Host "Full instructions: README.md, section 'Install (run host)'."

# Non-zero: nothing was installed, so no caller should treat this as success.
exit 1
