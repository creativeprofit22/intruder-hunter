# shellcheck shell=bash

check_security_settings() {
    section "5. SECURITY SETTINGS"

    echo -e "  ${WHITE}Checking macOS security features...${NC}"
    echo ""

    # System Integrity Protection (SIP)
    local sip_status
    sip_status=$(csrutil status 2>/dev/null | grep -o "enabled\|disabled" || true)
    if [[ "$sip_status" == "enabled" ]]; then
        ok "System Integrity Protection (SIP) is enabled"
    else
        fail "System Integrity Protection (SIP) is DISABLED"
    fi

    # Gatekeeper
    local gatekeeper
    gatekeeper=$(spctl --status 2>/dev/null | grep -o "enabled\|disabled" || true)
    if [[ "$gatekeeper" == "enabled" ]]; then
        ok "Gatekeeper is enabled"
    else
        warn "Gatekeeper is disabled"
    fi

    # FileVault
    local filevault
    filevault=$(fdesetup status 2>/dev/null | grep -o "On\|Off" || true)
    if [[ "$filevault" == "On" ]]; then
        ok "FileVault disk encryption is enabled"
        FILEVAULT_ENABLED=1
    else
        warn "FileVault disk encryption is OFF"
        # shellcheck disable=SC2034
        FILEVAULT_ENABLED=0
    fi

    # macOS Firewall (Application Firewall)
    echo ""
    echo -e "  ${WHITE}Firewall status:${NC}"

    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -o "enabled\|disabled" || true)
    if [[ "$fw_status" == "enabled" ]]; then
        ok "macOS Application Firewall is enabled"
        FIREWALL_ACTIVE=1
    else
        warn "macOS Application Firewall is disabled"
        # shellcheck disable=SC2034
        FIREWALL_ACTIVE=0
    fi

    # Stealth mode
    local stealth
    stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -o "enabled\|disabled" || true)
    if [[ "$stealth" == "enabled" ]]; then
        ok "Stealth mode is enabled"
    else
        info "Stealth mode is disabled (optional)"
    fi

    # Remote login (SSH)
    echo ""
    echo -e "  ${WHITE}Remote access:${NC}"

    local remote_login
    remote_login=$(systemsetup -getremotelogin 2>/dev/null | grep -o "On\|Off" || true)
    if [[ "$remote_login" == "On" ]]; then
        warn "Remote Login (SSH) is enabled - ensure this is intentional"
    else
        ok "Remote Login (SSH) is disabled"
    fi

    # Remote management (ARD)
    local remote_mgmt
    remote_mgmt=$(launchctl list 2>/dev/null | grep -c "com.apple.RemoteDesktop" || echo 0)
    if [[ $remote_mgmt -gt 0 ]]; then
        warn "Apple Remote Desktop is running"
    else
        ok "Apple Remote Desktop is not running"
    fi

    # Screen sharing
    local screen_sharing
    screen_sharing=$(launchctl list 2>/dev/null | grep -c "com.apple.screensharing" || echo 0)
    if [[ $screen_sharing -gt 0 ]]; then
        warn "Screen Sharing is enabled"
    else
        ok "Screen Sharing is disabled"
    fi
}
