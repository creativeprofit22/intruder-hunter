#===============================================================================
#   User Analysis
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
