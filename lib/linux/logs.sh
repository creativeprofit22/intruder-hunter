# shellcheck shell=bash

check_logs() {
    section "6. LOG ANALYSIS"

    echo -e "  ${WHITE}Checking authentication logs...${NC}"
    echo ""

    # Failed login attempts
    if [[ -f /var/log/auth.log ]]; then
        local failed_logins
        failed_logins=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)

        if [[ $failed_logins -gt 100 ]]; then
            warn "High number of failed login attempts: $failed_logins"
            echo -e "    ${INFO} Recent failed attempts:"
            grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 | while read -r line; do
                echo -e "    $line"
            done
        elif [[ $failed_logins -gt 0 ]]; then
            info "Failed login attempts: $failed_logins"
        else
            ok "No failed login attempts in logs"
        fi
    else
        info "Auth log not available (normal for some systems)"
    fi

    # Recent logins
    echo ""
    echo -e "  ${WHITE}Recent logins:${NC}"
    last -n 5 2>/dev/null | head -5 | while read -r line; do
        echo -e "    ${INFO} $line"
    done
}
