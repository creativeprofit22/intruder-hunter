# shellcheck shell=bash

check_logs() {
    section "7. LOG ANALYSIS"

    echo -e "  ${WHITE}Checking authentication logs...${NC}"
    echo ""

    # Check for failed SSH attempts
    local ssh_failures
    ssh_failures=$(log show --predicate 'eventMessage contains "Failed password" OR eventMessage contains "authentication failure"' --last 24h 2>/dev/null | wc -l | tr -d ' ')

    if [[ $ssh_failures -gt 100 ]]; then
        warn "High number of authentication failures in last 24h: $ssh_failures"
    elif [[ $ssh_failures -gt 0 ]]; then
        info "Authentication failures in last 24h: $ssh_failures"
    else
        ok "No authentication failures in last 24h"
    fi

    # Check for sudo usage
    echo ""
    echo -e "  ${WHITE}Recent sudo usage:${NC}"
    log show --predicate 'eventMessage contains "sudo"' --last 1h 2>/dev/null | tail -5 | while read -r line; do
        echo -e "    ${INFO} $line"
    done

    # Check for kernel panics
    echo ""
    local panics
    panics=$(find /Library/Logs/DiagnosticReports -name "*.panic" -mtime -7 2>/dev/null | wc -l | tr -d ' ')
    if [[ $panics -gt 0 ]]; then
        warn "Kernel panics in last 7 days: $panics"
    else
        ok "No kernel panics in last 7 days"
    fi

    # Recent logins
    echo ""
    echo -e "  ${WHITE}Recent logins:${NC}"
    last -5 2>/dev/null | head -5 | while read -r line; do
        echo -e "    ${INFO} $line"
    done
}
