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
