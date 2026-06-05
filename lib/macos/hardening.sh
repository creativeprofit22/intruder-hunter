# shellcheck shell=bash

do_updates() {
    section "APPLYING SOFTWARE UPDATES"
    echo -e "  ${INFO} Checking for updates..."
    softwareupdate -ia --verbose
    ok "Updates applied"
}

do_firewall() {
    section "ENABLING FIREWALL"

    echo -e "  ${INFO} Enabling macOS Application Firewall..."
    /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

    ok "Firewall enabled with stealth mode"
}

do_filevault() {
    section "ENABLING FILEVAULT"

    echo -e "  ${INFO} Starting FileVault encryption..."
    echo -e "  ${WARN} You will be prompted to create a recovery key."
    echo -e "  ${WARN} SAVE THIS KEY SECURELY - you need it if you forget your password!"
    echo ""

    fdesetup enable

    ok "FileVault encryption started (will complete in background)"
}

do_malware_scan() {
    section "RUNNING MALWARE SCAN"

    echo -e "  ${INFO} Triggering XProtect scan..."

    # Force XProtect to run
    /usr/libexec/XProtectService --scan 2>/dev/null || true

    echo -e "  ${INFO} Running MRT (Malware Removal Tool)..."
    /System/Library/CoreServices/MRT.app/Contents/MacOS/MRT 2>/dev/null || true

    ok "Built-in malware scans triggered"

    if command -v brew &> /dev/null; then
        echo ""
        echo -e "  ${INFO} For deeper scanning, consider installing ClamAV:"
        echo -e "      brew install clamav"
        echo -e "      freshclam && clamscan -r ~/"
    fi
}

do_disable_remote() {
    section "DISABLING REMOTE ACCESS"

    echo -e "  ${INFO} Disabling Remote Login (SSH)..."
    systemsetup -setremotelogin off 2>/dev/null || true

    echo -e "  ${INFO} Disabling Screen Sharing..."
    launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null || true

    ok "Remote access services disabled"
}

offer_hardening() {
    section "SYSTEM HARDENING"

    echo -e "  ${WHITE}Based on the scan, the following hardening steps are recommended:${NC}"
    echo ""

    local has_recommendations=0

    if [[ ${PENDING_UPDATES:-0} -eq 1 ]]; then
        echo -e "  ${YELLOW}1.${NC} Apply pending software updates"
        has_recommendations=1
    fi

    if [[ ${FIREWALL_ACTIVE:-1} -eq 0 ]]; then
        echo -e "  ${YELLOW}2.${NC} Enable macOS Application Firewall"
        has_recommendations=1
    fi

    if [[ ${FILEVAULT_ENABLED:-1} -eq 0 ]]; then
        echo -e "  ${YELLOW}3.${NC} Enable FileVault disk encryption"
        has_recommendations=1
    fi

    echo -e "  ${YELLOW}4.${NC} Run built-in malware scans (XProtect + MRT)"
    echo -e "  ${YELLOW}5.${NC} Disable unnecessary remote access"

    if [[ $has_recommendations -eq 0 ]]; then
        echo ""
        echo -e "  ${GREEN}Your Mac is already well-configured!${NC}"
    fi

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if ask_yes_no "Apply all recommended hardening steps?"; then
        echo ""

        if [[ ${PENDING_UPDATES:-0} -eq 1 ]]; then
            do_updates
        fi

        if [[ ${FIREWALL_ACTIVE:-1} -eq 0 ]]; then
            do_firewall
        fi

        if [[ ${FILEVAULT_ENABLED:-1} -eq 0 ]]; then
            if ask_yes_no "Enable FileVault? (requires restart)"; then
                do_filevault
            fi
        fi

        do_malware_scan
        do_disable_remote

        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  HARDENING COMPLETE - Your Mac is now more secure!${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        echo ""
        echo -e "  ${INFO} Skipping hardening. You can run these commands manually:"
        echo ""
        echo -e "    ${CYAN}# Apply updates${NC}"
        echo "    sudo softwareupdate -ia"
        echo ""
        echo -e "    ${CYAN}# Enable firewall${NC}"
        echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
        echo ""
        echo -e "    ${CYAN}# Enable FileVault${NC}"
        echo "    sudo fdesetup enable"
        echo ""
        echo -e "    ${CYAN}# Disable remote login${NC}"
        echo "    sudo systemsetup -setremotelogin off"
        echo ""
    fi
}
