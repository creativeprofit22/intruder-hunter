#===============================================================================
#   Vulnerability Assessment
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
