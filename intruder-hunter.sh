#!/bin/bash

#===============================================================================
#
#   INTRUDER HUNTER - Linux Security Diagnostic & Hardening Tool
#
#   Scans your system for intruders, malware, and vulnerabilities.
#   Then offers to fix issues found.
#
#   Usage: sudo ./intruder-hunter.sh
#
#   GitHub: https://github.com/YOUR_USERNAME/intruder-hunter
#
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/linux/common.sh
source "${SCRIPT_DIR}/lib/linux/common.sh"
# shellcheck source=lib/linux/system.sh
source "${SCRIPT_DIR}/lib/linux/system.sh"
# shellcheck source=lib/linux/processes.sh
source "${SCRIPT_DIR}/lib/linux/processes.sh"
# shellcheck source=lib/linux/network.sh
source "${SCRIPT_DIR}/lib/linux/network.sh"
# shellcheck source=lib/linux/users.sh
source "${SCRIPT_DIR}/lib/linux/users.sh"
# shellcheck source=lib/linux/malware.sh
source "${SCRIPT_DIR}/lib/linux/malware.sh"
# shellcheck source=lib/linux/vulnerabilities.sh
source "${SCRIPT_DIR}/lib/linux/vulnerabilities.sh"
# shellcheck source=lib/linux/logs.sh
source "${SCRIPT_DIR}/lib/linux/logs.sh"
# shellcheck source=lib/linux/report.sh
source "${SCRIPT_DIR}/lib/linux/report.sh"
# shellcheck source=lib/linux/hardening.sh
source "${SCRIPT_DIR}/lib/linux/hardening.sh"

main() {
    check_root
    banner

    echo -e "  ${INFO} Starting security scan... This may take a few minutes."
    echo ""

    show_system_info
    check_processes
    check_network
    check_users
    check_malware
    check_vulnerabilities
    check_logs
    show_summary
    offer_hardening

    echo ""
    echo -e "  ${INFO} Scan results saved to: /var/log/intruder-hunter.log"
    echo ""
}

if [[ $EUID -ne 0 ]]; then
    main
else
    main 2>&1 | tee /var/log/intruder-hunter.log
fi
