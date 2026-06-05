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
