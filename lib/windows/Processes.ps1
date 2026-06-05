#===============================================================================
#   Process Analysis
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
