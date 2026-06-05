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
