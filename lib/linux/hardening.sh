# shellcheck shell=bash

do_updates() {
    section "APPLYING SECURITY UPDATES"
    echo -e "  ${INFO} Running apt update && apt upgrade..."
    apt update && apt upgrade -y
    ok "Updates applied"
}

do_firewall() {
    section "ENABLING FIREWALL"

    if ! command -v ufw &> /dev/null; then
        echo -e "  ${INFO} Installing UFW..."
        apt install -y ufw
    fi

    echo -e "  ${INFO} Enabling UFW with default deny incoming..."
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ok "Firewall enabled and configured"
}

do_rootkit_scan() {
    section "INSTALLING & RUNNING ROOTKIT SCANNERS"

    echo -e "  ${INFO} Installing rkhunter and chkrootkit..."
    apt install -y rkhunter chkrootkit

    # Fix rkhunter config issue
    sed -i 's|WEB_CMD="/bin/false"|WEB_CMD=""|g' /etc/rkhunter.conf 2>/dev/null

    echo ""
    echo -e "  ${INFO} Running chkrootkit..."
    chkrootkit 2>&1 | grep -E "INFECTED|Checking|Searching" | head -20

    echo ""
    echo -e "  ${INFO} Running rkhunter..."
    rkhunter --check --sk --rwo 2>&1 | head -30

    ok "Rootkit scan complete"
}

do_auto_updates() {
    section "CONFIGURING AUTOMATIC UPDATES"

    if ! dpkg -l | grep -q unattended-upgrades; then
        echo -e "  ${INFO} Installing unattended-upgrades..."
        apt install -y unattended-upgrades
    fi

    echo -e "  ${INFO} Enabling automatic security updates..."
    echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

    ok "Automatic updates configured"
}

offer_hardening() {
    section "SYSTEM HARDENING"

    echo -e "  ${WHITE}Based on the scan, the following hardening steps are recommended:${NC}"
    echo ""

    local has_recommendations=0

    if [[ ${PENDING_UPDATES:-0} -gt 0 ]]; then
        echo -e "  ${YELLOW}1.${NC} Apply $PENDING_UPDATES pending security updates"
        has_recommendations=1
    fi

    if [[ ${FIREWALL_ACTIVE:-1} -eq 0 ]]; then
        echo -e "  ${YELLOW}2.${NC} Enable UFW firewall"
        has_recommendations=1
    fi

    echo -e "  ${YELLOW}3.${NC} Run rootkit scanners (rkhunter + chkrootkit)"
    echo -e "  ${YELLOW}4.${NC} Configure automatic security updates"

    if [[ $has_recommendations -eq 0 ]]; then
        echo ""
        echo -e "  ${GREEN}Your system is already well-configured!${NC}"
    fi

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if ask_yes_no "Apply all recommended hardening steps?"; then
        echo ""

        if [[ ${PENDING_UPDATES:-0} -gt 0 ]]; then
            do_updates
        fi

        if [[ ${FIREWALL_ACTIVE:-1} -eq 0 ]]; then
            do_firewall
        fi

        do_rootkit_scan
        do_auto_updates

        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  HARDENING COMPLETE - Your system is now more secure!${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        echo ""
        echo -e "  ${INFO} Skipping hardening. You can run these commands manually:"
        echo ""
        echo -e "    ${CYAN}# Apply updates${NC}"
        echo "    sudo apt update && sudo apt upgrade -y"
        echo ""
        echo -e "    ${CYAN}# Enable firewall${NC}"
        echo "    sudo ufw enable && sudo ufw default deny incoming"
        echo ""
        echo -e "    ${CYAN}# Run rootkit scan${NC}"
        echo "    sudo apt install rkhunter chkrootkit -y"
        echo "    sudo chkrootkit"
        echo ""
    fi
}
