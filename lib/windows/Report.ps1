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
