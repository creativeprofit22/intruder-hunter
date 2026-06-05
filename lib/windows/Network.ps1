#===============================================================================
#   Network Analysis
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
