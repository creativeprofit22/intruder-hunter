# shellcheck shell=bash

check_vulnerabilities() {
    section "5. VULNERABILITY ASSESSMENT"

    echo -e "  ${WHITE}Checking for common vulnerabilities...${NC}"
    echo ""

    # Pending updates
    if command -v apt &> /dev/null; then
        local updates
        apt update -qq 2>/dev/null
        updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0)

        if [[ $updates -gt 10 ]]; then
            warn "Pending security updates: $updates packages"
            PENDING_UPDATES=$updates
        elif [[ $updates -gt 0 ]]; then
            info "Pending updates: $updates packages"
            PENDING_UPDATES=$updates
        else
            ok "System is up to date"
            # shellcheck disable=SC2034
            PENDING_UPDATES=0
        fi
    fi

    # Firewall status
    echo ""
    echo -e "  ${WHITE}Firewall status:${NC}"

    if command -v ufw &> /dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
            ok "UFW firewall is active"
            FIREWALL_ACTIVE=1
        else
            warn "UFW firewall is inactive"
            FIREWALL_ACTIVE=0
        fi
    else
        warn "UFW not installed"
        # shellcheck disable=SC2034
        FIREWALL_ACTIVE=0
    fi

    # World-writable files in /etc
    echo ""
    echo -e "  ${WHITE}File permissions:${NC}"

    local world_writable
    world_writable=$(find /etc -type f -perm -002 2>/dev/null || true)
    if [[ -n "$world_writable" ]]; then
        warn "World-writable files in /etc:"
        while read -r file_path; do
            echo -e "    ${WARN} $file_path"
        done <<< "$world_writable"
    else
        ok "No world-writable files in /etc"
    fi

    # SSH configuration
    if [[ -f /etc/ssh/sshd_config ]]; then
        echo ""
        echo -e "  ${WHITE}SSH configuration:${NC}"

        local root_login
        root_login=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)
        if [[ "$root_login" == "yes" ]]; then
            warn "SSH allows root login"
        else
            ok "SSH root login is restricted"
        fi

        local pass_auth
        pass_auth=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)
        if [[ "$pass_auth" == "yes" ]]; then
            info "SSH password authentication is enabled"
        fi
    fi
}
