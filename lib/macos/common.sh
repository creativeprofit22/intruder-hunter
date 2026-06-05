# shellcheck shell=bash

#===============================================================================
#   Intruder Hunter macOS shared UI and runtime helpers
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Symbols
CHECK="${GREEN}✓${NC}"
CROSS="${RED}✗${NC}"
WARN="${YELLOW}!${NC}"
INFO="${BLUE}ℹ${NC}"

# Shared scan state
ISSUES_FOUND=0
WARNINGS_FOUND=0
# Updated by vulnerabilities.sh and consumed by hardening.sh.
# shellcheck disable=SC2034
PENDING_UPDATES=0
# Updated by security.sh and consumed by hardening.sh.
# shellcheck disable=SC2034
FIREWALL_ACTIVE=1
# shellcheck disable=SC2034
FILEVAULT_ACTIVE=1
# shellcheck disable=SC2034
REMOTE_LOGIN_ACTIVE=0

banner() {
    clear
    echo -e "${PURPLE}"
    echo '  ___       _                  _             _   _             _            '
    echo ' |_ _|_ __ | |_ _ __ _   _  __| | ___ _ __  | | | |_   _ _ __ | |_ ___ _ __ '
    echo '  | ||  _ \| __|  __| | | |/ _` |/ _ \  __| | |_| | | | |  _ \| __/ _ \  __|'
    echo '  | || | | | |_| |  | |_| | (_| |  __/ |    |  _  | |_| | | | | ||  __/ |   '
    echo ' |___|_| |_|\__|_|   \__,_|\__,_|\___|_|    |_| |_|\__,_|_| |_|\__\___|_|   '
    echo -e "${NC}"
    echo -e "${WHITE}  macOS Security Diagnostic & Hardening Tool${NC}"
    echo -e "${CYAN}  ─────────────────────────────────────────────────────────────────${NC}"
    echo ""
}

section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

ok() {
    echo -e "  ${CHECK} $1"
}

fail() {
    echo -e "  ${CROSS} $1"
    ((ISSUES_FOUND += 1))
}

warn() {
    echo -e "  ${WARN} $1"
    ((WARNINGS_FOUND += 1))
}

info() {
    echo -e "  ${INFO} $1"
}

ask_yes_no() {
    local prompt="$1"
    local response
    echo ""
    echo -e -n "${YELLOW}  $prompt (y/n): ${NC}"
    read -r response
    [[ "$response" =~ ^[Yy]$ ]]
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
        echo ""
        echo "  Usage: sudo ./intruder-hunter-macos.sh"
        echo ""
        exit 1
    fi
}

check_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        echo -e "${RED}Error: This script is for macOS only${NC}"
        echo ""
        echo "  For Linux, use: intruder-hunter.sh"
        echo "  For Windows, use: intruder-hunter.ps1"
        echo ""
        exit 1
    fi
}
