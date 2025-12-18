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

#===============================================================================
#   Configuration
#===============================================================================

$Script:IssuesFound = 0
$Script:WarningsFound = 0

# Known suspicious ports (common backdoor/RAT ports)
$SuspiciousPorts = @(4444, 5555, 6666, 1337, 31337, 9999, 8080, 3389)

# Known crypto miner process patterns
$MinerPatterns = @('xmrig', 'xmr', 'miner', 'coinminer', 'nicehash', 'ethminer', 'cgminer', 'bfgminer', 'cpuminer')

# Known PUP/adware patterns
$PUPPatterns = @('web companion', 'lavasoft', 'conduit', 'ask toolbar', 'babylon', 'delta-homes', 'sweetim')

#===============================================================================
#   Helper Functions
#===============================================================================

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ___       _                  _             _   _             _            " -ForegroundColor Magenta
    Write-Host " |_ _|_ __ | |_ _ __ _   _  __| | ___ _ __  | | | |_   _ _ __ | |_ ___ _ __ " -ForegroundColor Magenta
    Write-Host "  | ||  _ \| __|  __| | | |/ _` |/ _ \  __| | |_| | | | |  _ \| __/ _ \  __|" -ForegroundColor Magenta
    Write-Host "  | || | | | |_| |  | |_| | (_| |  __/ |    |  _  | |_| | | | | ||  __/ |   " -ForegroundColor Magenta
    Write-Host " |___|_| |_|\__|_|   \__,_|\__,_|\___|_|    |_| |_|\__,_|_| |_|\__\___|_|   " -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Windows Security Diagnostic & Hardening Tool" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  ✓ $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  ✗ $Message" -ForegroundColor Red
    $Script:IssuesFound++
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  ! $Message" -ForegroundColor Yellow
    $Script:WarningsFound++
}

function Write-Info {
    param([string]$Message)
    Write-Host "  ℹ $Message" -ForegroundColor Blue
}

#===============================================================================
#   System Information
#===============================================================================

function Show-SystemInfo {
    Write-Section "SYSTEM INFORMATION"

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem

    Write-Host "  Hostname:    $($env:COMPUTERNAME)" -ForegroundColor White
    Write-Host "  OS:          $($os.Caption) $($os.Version)" -ForegroundColor White
    Write-Host "  User:        $($env:USERNAME)" -ForegroundColor White
    Write-Host "  Uptime:      $((Get-Date) - $os.LastBootUpTime)" -ForegroundColor White
    Write-Host "  Scan Date:   $(Get-Date)" -ForegroundColor White
}

#===============================================================================
#   1. Process Analysis
#===============================================================================

function Test-Processes {
    Write-Section "1. PROCESS ANALYSIS"

    Write-Host "  Checking for suspicious processes..." -ForegroundColor White
    Write-Host ""

    $processes = Get-Process -ErrorAction SilentlyContinue

    # Check for crypto miners
    $miners = $processes | Where-Object {
        $name = $_.Name.ToLower()
        $MinerPatterns | ForEach-Object { $name -match $_ }
    }

    if ($miners) {
        Write-Fail "Potential crypto miners detected!"
        $miners | Format-Table Name, Id, CPU, Path -AutoSize
    } else {
        Write-Ok "No crypto miners detected"
    }

    # Check processes running from temp directories
    $tempProcesses = $processes | Where-Object {
        $_.Path -match 'Temp|\\AppData\\Local\\Temp'
    }

    if ($tempProcesses.Count -gt 0) {
        Write-Warn "Processes running from temp directories: $($tempProcesses.Count)"
        $tempProcesses | Select-Object Name, Id, Path | Format-Table -AutoSize
    } else {
        Write-Ok "No processes running from temp directories"
    }

    # High CPU processes
    Write-Host ""
    Write-Host "  Top 5 CPU-consuming processes:" -ForegroundColor White
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, CPU, Id | Format-Table -AutoSize
}

#===============================================================================
#   2. Network Analysis
#===============================================================================

function Test-Network {
    Write-Section "2. NETWORK ANALYSIS"

    Write-Host "  Checking listening ports..." -ForegroundColor White
    Write-Host ""

    # Check for suspicious listening ports
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    $suspiciousListeners = $listeners | Where-Object { $_.LocalPort -in $SuspiciousPorts }

    if ($suspiciousListeners) {
        Write-Fail "Suspicious ports detected (common backdoor ports):"
        $suspiciousListeners | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
    } else {
        Write-Ok "No suspicious listening ports detected"
    }

    # Firewall status
    Write-Host ""
    Write-Host "  Firewall status:" -ForegroundColor White
    $firewallProfiles = Get-NetFirewallProfile

    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled) {
            Write-Ok "$($profile.Name) firewall is enabled"
        } else {
            Write-Fail "$($profile.Name) firewall is DISABLED"
        }
    }

    # Show listening services summary
    Write-Host ""
    Write-Host "  Listening services (top 10):" -ForegroundColor White
    $listeners | Select-Object -First 10 LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
}

#===============================================================================
#   3. User Analysis
#===============================================================================

function Test-Users {
    Write-Section "3. USER & AUTHENTICATION ANALYSIS"

    Write-Host "  Checking user accounts..." -ForegroundColor White
    Write-Host ""

    # List all users
    Write-Host "  Local users:" -ForegroundColor White
    Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize

    # Check administrator group
    Write-Host ""
    Write-Host "  Administrator group members:" -ForegroundColor White
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if (-not $admins) {
            $admins = Get-LocalGroupMember -Group "Administradores" -ErrorAction SilentlyContinue
        }
        $admins | Select-Object Name, ObjectClass | Format-Table -AutoSize

        $adminCount = ($admins | Measure-Object).Count
        if ($adminCount -gt 2) {
            Write-Warn "Multiple administrator accounts: $adminCount"
        } else {
            Write-Ok "Administrator count is normal: $adminCount"
        }
    } catch {
        Write-Info "Could not enumerate administrator group"
    }

    # Check for hidden users ($ suffix)
    $hiddenUsers = Get-LocalUser | Where-Object { $_.Name -match '\$$' -and $_.Enabled }
    if ($hiddenUsers) {
        Write-Fail "Hidden user accounts detected:"
        $hiddenUsers | Format-Table Name, Enabled
    } else {
        Write-Ok "No hidden user accounts"
    }
}

#===============================================================================
#   4. Malware & PUP Detection
#===============================================================================

function Test-Malware {
    Write-Section "4. MALWARE & PUP DETECTION"

    Write-Host "  Checking for potentially unwanted programs..." -ForegroundColor White
    Write-Host ""

    # Check for PUPs in running processes
    $processes = Get-Process -ErrorAction SilentlyContinue
    $pups = @()

    foreach ($pattern in $PUPPatterns) {
        $found = $processes | Where-Object {
            $_.Name -match $pattern -or $_.Path -match $pattern
        }
        if ($found) { $pups += $found }
    }

    if ($pups) {
        Write-Warn "Potentially Unwanted Programs (PUPs) detected:"
        $pups | Select-Object Name, Id, Path | Format-Table -AutoSize
    } else {
        Write-Ok "No known PUPs detected in running processes"
    }

    # Check services for PUPs
    $services = Get-Service -ErrorAction SilentlyContinue
    $pupServices = @()

    foreach ($pattern in $PUPPatterns) {
        $found = $services | Where-Object {
            $_.Name -match $pattern -or $_.DisplayName -match $pattern
        }
        if ($found) { $pupServices += $found }
    }

    if ($pupServices) {
        Write-Warn "PUP services detected:"
        $pupServices | Select-Object Name, DisplayName, Status | Format-Table -AutoSize
    } else {
        Write-Ok "No known PUP services detected"
    }

    # Check startup for suspicious entries
    Write-Host ""
    Write-Host "  Checking startup programs..." -ForegroundColor White

    $startupItems = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue
    $suspiciousStartup = $startupItems | Where-Object {
        $cmd = $_.Command.ToLower()
        $cmd -match 'temp' -or $cmd -match 'appdata\\local\\temp' -or
        ($PUPPatterns | ForEach-Object { $cmd -match $_ })
    }

    if ($suspiciousStartup) {
        Write-Warn "Suspicious startup entries:"
        $suspiciousStartup | Select-Object Name, Command | Format-Table -AutoSize
    } else {
        Write-Ok "No suspicious startup entries"
    }
}

#===============================================================================
#   5. Scheduled Tasks Analysis
#===============================================================================

function Test-ScheduledTasks {
    Write-Section "5. SCHEDULED TASKS ANALYSIS"

    Write-Host "  Checking for suspicious scheduled tasks..." -ForegroundColor White
    Write-Host ""

    # Get non-Microsoft tasks
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Author -notmatch 'Microsoft' -and
        $_.State -eq 'Ready' -and
        $_.TaskPath -notmatch '^\\Microsoft'
    }

    # Check for tasks running scripts from unusual locations
    $suspiciousTasks = @()

    foreach ($task in $tasks) {
        try {
            $actions = $task.Actions
            foreach ($action in $actions) {
                if ($action.Execute -match 'powershell|cmd|wscript|cscript|mshta') {
                    if ($action.Arguments -match 'http|temp|appdata\\local\\temp') {
                        $suspiciousTasks += [PSCustomObject]@{
                            Name = $task.TaskName
                            Path = $task.TaskPath
                            Command = "$($action.Execute) $($action.Arguments)"
                        }
                    }
                }
            }
        } catch {}
    }

    if ($suspiciousTasks) {
        Write-Warn "Suspicious scheduled tasks (scripts from unusual locations):"
        $suspiciousTasks | Format-Table -AutoSize
    } else {
        Write-Ok "No suspicious scheduled tasks detected"
    }

    # Show non-Microsoft tasks count
    $taskCount = ($tasks | Measure-Object).Count
    Write-Info "Non-Microsoft scheduled tasks: $taskCount"
}

#===============================================================================
#   6. Windows Defender Status
#===============================================================================

function Test-Defender {
    Write-Section "6. WINDOWS DEFENDER STATUS"

    Write-Host "  Checking Windows Defender status..." -ForegroundColor White
    Write-Host ""

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop

        if ($status.AntivirusEnabled) {
            Write-Ok "Antivirus is enabled"
        } else {
            Write-Fail "Antivirus is DISABLED"
        }

        if ($status.RealTimeProtectionEnabled) {
            Write-Ok "Real-time protection is enabled"
        } else {
            Write-Fail "Real-time protection is DISABLED"
        }

        Write-Info "Signature last updated: $($status.AntivirusSignatureLastUpdated)"

        # Check for threats
        $threats = Get-MpThreat -ErrorAction SilentlyContinue
        if ($threats) {
            Write-Fail "Active threats detected: $(($threats | Measure-Object).Count)"
            $threats | Select-Object ThreatName, IsActive | Format-Table -AutoSize
        } else {
            Write-Ok "No active threats detected"
        }

        # Scan age
        Write-Info "Quick scan age: $($status.QuickScanAge) days"
        if ($status.QuickScanAge -gt 7) {
            Write-Warn "Quick scan is more than 7 days old"
        }

    } catch {
        Write-Warn "Windows Defender not available or another AV is installed"
    }
}

#===============================================================================
#   7. Vulnerability Assessment
#===============================================================================

function Test-Vulnerabilities {
    Write-Section "7. VULNERABILITY ASSESSMENT"

    Write-Host "  Checking for common vulnerabilities..." -ForegroundColor White
    Write-Host ""

    # Check Windows Update
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $pendingUpdates = $updateSearcher.Search("IsInstalled=0").Updates

        $updateCount = $pendingUpdates.Count
        if ($updateCount -gt 10) {
            Write-Warn "Pending Windows updates: $updateCount"
        } elseif ($updateCount -gt 0) {
            Write-Info "Pending Windows updates: $updateCount"
        } else {
            Write-Ok "Windows is up to date"
        }
    } catch {
        Write-Info "Could not check Windows Update status"
    }

    # Check UAC
    $uacKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    if ($uacKey.EnableLUA -eq 1) {
        Write-Ok "User Account Control (UAC) is enabled"
    } else {
        Write-Fail "User Account Control (UAC) is DISABLED"
    }

    # Check Remote Desktop
    $rdpKey = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
    if ($rdpKey.fDenyTSConnections -eq 1) {
        Write-Ok "Remote Desktop is disabled"
    } else {
        Write-Warn "Remote Desktop is enabled - ensure it's intentional"
    }

    # Check SMBv1 (vulnerable protocol)
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1.State -eq 'Enabled') {
            Write-Warn "SMBv1 is enabled (vulnerable protocol - consider disabling)"
        } else {
            Write-Ok "SMBv1 is disabled (good)"
        }
    } catch {
        Write-Info "Could not check SMBv1 status"
    }
}

#===============================================================================
#   Summary
#===============================================================================

function Show-Summary {
    Write-Section "SCAN COMPLETE - SUMMARY"

    Write-Host ""
    if ($Script:IssuesFound -eq 0 -and $Script:WarningsFound -eq 0) {
        Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║          SYSTEM APPEARS CLEAN                ║" -ForegroundColor Green
        Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Green
    } elseif ($Script:IssuesFound -eq 0) {
        Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "  ║     CLEAN - BUT SOME WARNINGS FOUND          ║" -ForegroundColor Yellow
        Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Yellow
    } else {
        Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║         ISSUES DETECTED - REVIEW ABOVE       ║" -ForegroundColor Red
        Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  Results:" -ForegroundColor White
    Write-Host "    ✗ Critical issues: $Script:IssuesFound" -ForegroundColor Red
    Write-Host "    ! Warnings:        $Script:WarningsFound" -ForegroundColor Yellow
    Write-Host ""
}

#===============================================================================
#   Hardening Functions
#===============================================================================

function Start-Hardening {
    Write-Section "SYSTEM HARDENING"

    Write-Host "  Available hardening options:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Enable Windows Firewall (all profiles)" -ForegroundColor Yellow
    Write-Host "  2. Run Windows Defender quick scan" -ForegroundColor Yellow
    Write-Host "  3. Disable SMBv1 (if enabled)" -ForegroundColor Yellow
    Write-Host "  4. Check for Windows Updates" -ForegroundColor Yellow
    Write-Host ""

    $choice = Read-Host "  Apply all recommended hardening? (y/n)"

    if ($choice -eq 'y' -or $choice -eq 'Y') {
        Write-Host ""

        # Enable firewall
        Write-Info "Enabling Windows Firewall..."
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Ok "Firewall enabled for all profiles"

        # Run Defender scan
        Write-Info "Starting Windows Defender quick scan..."
        Start-MpScan -ScanType QuickScan -AsJob | Out-Null
        Write-Ok "Defender scan started in background"

        # Disable SMBv1
        try {
            $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($smb1.State -eq 'Enabled') {
                Write-Info "Disabling SMBv1..."
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Write-Ok "SMBv1 disabled (restart required to complete)"
            } else {
                Write-Ok "SMBv1 already disabled"
            }
        } catch {
            Write-Info "Could not modify SMBv1 status"
        }

        # Check updates
        Write-Info "Opening Windows Update..."
        Start-Process "ms-settings:windowsupdate"

        Write-Host ""
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
        Write-Host "  HARDENING COMPLETE - Review Windows Update for pending patches" -ForegroundColor Green
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Info "Skipping hardening. You can run these commands manually:"
        Write-Host ""
        Write-Host "    # Enable firewall" -ForegroundColor Cyan
        Write-Host "    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
        Write-Host ""
        Write-Host "    # Run Defender scan" -ForegroundColor Cyan
        Write-Host "    Start-MpScan -ScanType QuickScan"
        Write-Host ""
        Write-Host "    # Disable SMBv1" -ForegroundColor Cyan
        Write-Host "    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
        Write-Host ""
    }
}

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
