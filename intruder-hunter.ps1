#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Intruder Hunter - Windows Security Diagnostic & Hardening Tool

.DESCRIPTION
    Scans your Windows system for intruders, malware, and vulnerabilities.
    Companion to intruder-hunter.sh for Linux/WSL.

.EXAMPLE
    .\intruder-hunter.ps1

.LINK
    https://github.com/creativeprofit22/intruder-hunter

.NOTES
    Run as Administrator for full functionality.
#>

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptRoot 'lib/windows/Common.ps1')
. (Join-Path $ScriptRoot 'lib/windows/System.ps1')
. (Join-Path $ScriptRoot 'lib/windows/Processes.ps1')
. (Join-Path $ScriptRoot 'lib/windows/Network.ps1')
. (Join-Path $ScriptRoot 'lib/windows/Users.ps1')
. (Join-Path $ScriptRoot 'lib/windows/Malware.ps1')
. (Join-Path $ScriptRoot 'lib/windows/ScheduledTasks.ps1')
. (Join-Path $ScriptRoot 'lib/windows/Defender.ps1')
. (Join-Path $ScriptRoot 'lib/windows/Vulnerabilities.ps1')
. (Join-Path $ScriptRoot 'lib/windows/Report.ps1')
. (Join-Path $ScriptRoot 'lib/windows/Hardening.ps1')

#===============================================================================
#   Main
#===============================================================================

function Main {
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "  ERROR: This script must be run as Administrator" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }

    Write-Banner

    Write-Info "Starting security scan... This may take a few minutes."
    Write-Host ""

    Show-SystemInfo
    Test-Processes
    Test-Network
    Test-Users
    Test-Malware
    Test-ScheduledTasks
    Test-Defender
    Test-Vulnerabilities
    Show-Summary
    Start-Hardening

    Write-Host ""
    Write-Info "Scan complete!"
    Write-Host ""
}

# Run
Main
