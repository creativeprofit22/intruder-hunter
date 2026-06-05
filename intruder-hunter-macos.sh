#!/bin/bash

#===============================================================================
#
#   INTRUDER HUNTER - macOS Security Diagnostic & Hardening Tool
#
#   Scans your Mac for intruders, malware, and vulnerabilities.
#   Then offers to fix issues found.
#
#   Usage: sudo ./intruder-hunter-macos.sh
#
#   GitHub: https://github.com/creativeprofit22/intruder-hunter
#
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/macos/common.sh
source "${SCRIPT_DIR}/lib/macos/common.sh"
# shellcheck source=lib/macos/system.sh
source "${SCRIPT_DIR}/lib/macos/system.sh"
# shellcheck source=lib/macos/processes.sh
source "${SCRIPT_DIR}/lib/macos/processes.sh"
# shellcheck source=lib/macos/network.sh
source "${SCRIPT_DIR}/lib/macos/network.sh"
# shellcheck source=lib/macos/users.sh
source "${SCRIPT_DIR}/lib/macos/users.sh"
# shellcheck source=lib/macos/malware.sh
source "${SCRIPT_DIR}/lib/macos/malware.sh"
# shellcheck source=lib/macos/security.sh
source "${SCRIPT_DIR}/lib/macos/security.sh"
# shellcheck source=lib/macos/vulnerabilities.sh
source "${SCRIPT_DIR}/lib/macos/vulnerabilities.sh"
# shellcheck source=lib/macos/logs.sh
source "${SCRIPT_DIR}/lib/macos/logs.sh"
# shellcheck source=lib/macos/report.sh
source "${SCRIPT_DIR}/lib/macos/report.sh"
# shellcheck source=lib/macos/hardening.sh
source "${SCRIPT_DIR}/lib/macos/hardening.sh"

main() {
    check_macos
    check_root
    banner

    echo -e "  ${INFO} Starting security scan... This may take a few minutes."
    echo ""

    show_system_info
    check_processes
    check_network
    check_users
    check_malware
    check_security_settings
    check_vulnerabilities
    check_logs
    show_summary
    offer_hardening

    echo ""
    echo -e "  ${INFO} Scan complete!"
    echo ""
}

LOG_FILE="/var/log/intruder-hunter-macos.log"
if [[ $EUID -ne 0 ]]; then
    main
else
    main 2>&1 | tee "$LOG_FILE"
    echo -e "  ${INFO} Scan results saved to: $LOG_FILE"
    echo ""
fi
