# shellcheck shell=bash

check_vulnerabilities() {
    section "6. VULNERABILITY ASSESSMENT"

    echo -e "  ${WHITE}Checking for common vulnerabilities...${NC}"
    echo ""

    # Check for software updates
    local updates
    updates=$(softwareupdate -l 2>&1 | grep -c "recommended\|restart" || echo 0)
    if [[ $updates -gt 0 ]]; then
        warn "Pending software updates available"
        PENDING_UPDATES=1
    else
        ok "No critical updates pending"
        # shellcheck disable=SC2034
        PENDING_UPDATES=0
    fi

    # Check XProtect version
    echo ""
    echo -e "  ${WHITE}XProtect (built-in malware protection):${NC}"
    local xprotect_version
    xprotect_version=$(defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist Version 2>/dev/null || echo "Unknown")
    info "XProtect version: $xprotect_version"

    # Check MRT (Malware Removal Tool)
    local mrt_version
    mrt_version=$(defaults read /System/Library/CoreServices/MRT.app/Contents/version.plist CFBundleShortVersionString 2>/dev/null || echo "Unknown")
    info "MRT version: $mrt_version"

    # Check for world-writable directories in PATH
    echo ""
    echo -e "  ${WHITE}PATH security:${NC}"

    local path_vuln=0
    local dir
    IFS=':' read -ra PATHDIR <<< "$PATH"
    for dir in "${PATHDIR[@]}"; do
        if [[ -d "$dir" ]]; then
            local other_write
            other_write=$(stat -f "%Sp" "$dir" 2>/dev/null | cut -c9 || true)
            if [[ "$other_write" == "w" ]]; then
                warn "World-writable directory in PATH: $dir"
                path_vuln=1
            fi
        fi
    done

    if [[ $path_vuln -eq 0 ]]; then
        ok "No world-writable directories in PATH"
    fi

    # Check for outdated Homebrew packages (if brew is installed)
    if command -v brew &> /dev/null; then
        echo ""
        echo -e "  ${WHITE}Homebrew packages:${NC}"
        local outdated
        outdated=$(brew outdated 2>/dev/null | wc -l | tr -d ' ')
        if [[ $outdated -gt 10 ]]; then
            warn "Outdated Homebrew packages: $outdated"
        elif [[ $outdated -gt 0 ]]; then
            info "Outdated Homebrew packages: $outdated"
        else
            ok "All Homebrew packages up to date"
        fi
    fi
}
