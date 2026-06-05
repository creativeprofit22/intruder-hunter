#===============================================================================
#   Windows Defender Status
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
