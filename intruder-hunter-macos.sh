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

# Global counters
ISSUES_FOUND=0
WARNINGS_FOUND=0

#-------------------------------------------------------------------------------
# Helper Functions
#-------------------------------------------------------------------------------

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
    ((ISSUES_FOUND++)) || true
}

warn() {
    echo -e "  ${WARN} $1"
    ((WARNINGS_FOUND++)) || true
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

#-------------------------------------------------------------------------------
# Check if running as root
#-------------------------------------------------------------------------------

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
        echo ""
        echo "  Usage: sudo ./intruder-hunter-macos.sh"
        echo ""
        exit 1
    fi
}

#-------------------------------------------------------------------------------
# Check if running on macOS
#-------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------
# System Information
#-------------------------------------------------------------------------------

show_system_info() {
    section "SYSTEM INFORMATION"

    local os_name=$(sw_vers -productName 2>/dev/null || echo "macOS")
    local os_version=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
    local build=$(sw_vers -buildVersion 2>/dev/null || echo "Unknown")
    local hostname=$(hostname)
    local uptime_info=$(uptime | sed 's/.*up //' | sed 's/,.*//')
    local chip=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")

    echo -e "  ${WHITE}Hostname:${NC}    $hostname"
    echo -e "  ${WHITE}OS:${NC}          $os_name $os_version ($build)"
    echo -e "  ${WHITE}Chip:${NC}        $chip"
    echo -e "  ${WHITE}Uptime:${NC}      $uptime_info"
    echo -e "  ${WHITE}Scan Date:${NC}   $(date)"
}

#-------------------------------------------------------------------------------
# 1. Check for suspicious processes
#-------------------------------------------------------------------------------

check_processes() {
    section "1. PROCESS ANALYSIS"

    echo -e "  ${WHITE}Checking for suspicious processes...${NC}"
    echo ""

    # Check for crypto miners
    local miners=$(ps aux 2>/dev/null | grep -iE '(miner|xmrig|xmr|monero|coinminer|kdevtmpfsi|kinsing)' | grep -v grep | wc -l | tr -d ' ')
    if [[ $miners -gt 0 ]]; then
        fail "Potential crypto miners detected!"
        ps aux | grep -iE '(miner|xmrig|xmr|monero|coinminer|kdevtmpfsi|kinsing)' | grep -v grep
    else
        ok "No crypto miners detected"
    fi

    # Check for suspicious process locations
    local suspicious=$(ps aux 2>/dev/null | awk '{print $11}' | grep -E '^/tmp/|^/var/tmp/|^/private/tmp/' | wc -l | tr -d ' ')
    if [[ $suspicious -gt 0 ]]; then
        warn "Processes running from suspicious locations (tmp):"
        ps aux | awk '$11 ~ /^\/tmp\/|^\/var\/tmp\/|^\/private\/tmp\//'
    else
        ok "No processes running from suspicious locations"
    fi

    # High CPU processes
    echo ""
    echo -e "  ${WHITE}Top 5 CPU-consuming processes:${NC}"
    ps aux -r 2>/dev/null | head -6 | tail -5 | awk '{printf "    %-10s %5s%% CPU  %s\n", $1, $3, $11}'
}

#-------------------------------------------------------------------------------
# 2. Check network connections
#-------------------------------------------------------------------------------

check_network() {
    section "2. NETWORK ANALYSIS"

    echo -e "  ${WHITE}Checking listening ports...${NC}"
    echo ""

    # Get listening ports using lsof
    local listeners=$(lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | tail -n +2)

    if [[ -n "$listeners" ]]; then
        echo -e "  ${WHITE}Listening services:${NC}"
        echo "$listeners" | while read line; do
            local process=$(echo "$line" | awk '{print $1}')
            local port=$(echo "$line" | awk '{print $9}' | rev | cut -d: -f1 | rev)
            local bind=$(echo "$line" | awk '{print $9}')

            if [[ "$bind" == "*:"* ]]; then
                if [[ "$port" == "22" ]]; then
                    warn "SSH (port 22) exposed to all interfaces"
                else
                    info "Port $port ($process) - exposed to network"
                fi
            else
                ok "Port $port ($process) - localhost only"
            fi
        done
    else
        ok "No listening services found"
    fi

    echo ""
    echo -e "  ${WHITE}Checking active connections...${NC}"

    # Check for established connections
    local established=$(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l | tr -d ' ')
    echo -e "  ${INFO} Active connections: $established"

    # Check for connections to suspicious ports
    local suspicious_ports=$(netstat -an 2>/dev/null | grep -E ':4444|:5555|:6666|:1337|:31337' | wc -l | tr -d ' ')
    if [[ $suspicious_ports -gt 0 ]]; then
        warn "Connections to known suspicious ports detected!"
        netstat -an | grep -E ':4444|:5555|:6666|:1337|:31337'
    fi
}

#-------------------------------------------------------------------------------
# 3. Check users and authentication
#-------------------------------------------------------------------------------

check_users() {
    section "3. USER & AUTHENTICATION ANALYSIS"

    echo -e "  ${WHITE}Checking user accounts...${NC}"
    echo ""

    # List all users with shells
    echo -e "  ${WHITE}Users with shell access:${NC}"
    dscl . -list /Users UserShell 2>/dev/null | grep -E '(/bin/bash|/bin/zsh|/bin/sh)$' | while read line; do
        local username=$(echo "$line" | awk '{print $1}')
        local shell=$(echo "$line" | awk '{print $2}')
        local uid=$(dscl . -read /Users/"$username" UniqueID 2>/dev/null | awk '{print $2}')
        echo -e "    ${INFO} $username (UID: $uid) - $shell"
    done

    echo ""

    # Check admin users
    echo -e "  ${WHITE}Admin users:${NC}"
    local admin_users=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //')
    local admin_count=$(echo "$admin_users" | wc -w | tr -d ' ')

    echo "$admin_users" | tr ' ' '\n' | while read user; do
        if [[ -n "$user" ]]; then
            echo -e "    ${INFO} $user"
        fi
    done

    if [[ $admin_count -gt 2 ]]; then
        warn "Multiple admin users: $admin_count (review if intentional)"
    else
        ok "Admin user count is normal: $admin_count"
    fi

    # Check for SSH authorized_keys
    echo ""
    echo -e "  ${WHITE}SSH authorized keys:${NC}"
    local found_keys=0
    for home in /Users/*; do
        if [[ -f "$home/.ssh/authorized_keys" ]]; then
            local keycount=$(wc -l < "$home/.ssh/authorized_keys" 2>/dev/null | tr -d ' ' || echo 0)
            local username=$(basename "$home")
            if [[ $keycount -gt 0 ]]; then
                info "$username: $keycount authorized key(s)"
                found_keys=1
            fi
        fi
    done
    if [[ $found_keys -eq 0 ]]; then
        ok "No SSH authorized keys found"
    fi

    # Check for hidden admin accounts
    echo ""
    local hidden=$(dscl . -list /Users | grep -E '^\.' | grep -v '.localized')
    if [[ -n "$hidden" ]]; then
        warn "Hidden user accounts (starting with .):"
        echo "$hidden" | while read user; do
            echo -e "    ${WARN} $user"
        done
    else
        ok "No hidden user accounts"
    fi
}

#-------------------------------------------------------------------------------
# 4. Check for malware indicators
#-------------------------------------------------------------------------------

check_malware() {
    section "4. MALWARE & ROOTKIT INDICATORS"

    echo -e "  ${WHITE}Checking for common indicators...${NC}"
    echo ""

    # Check for suspicious files in /tmp
    local tmp_executables=$(find /tmp /private/tmp -type f -perm +111 2>/dev/null | grep -v "com.apple" | head -20)
    local tmp_exec_count=$(echo "$tmp_executables" | grep -v "^$" | wc -l | tr -d ' ')

    if [[ $tmp_exec_count -gt 0 ]]; then
        warn "Executable files in temp directories: $tmp_exec_count"
        echo -e "    ${INFO} (May include legitimate files - review if unsure)"
    else
        ok "No suspicious executables in temp directories"
    fi

    # Check for hidden files in common locations
    local hidden_suspicious=$(find /tmp /private/tmp -name ".*" -type f 2>/dev/null | grep -v ".DS_Store" | head -10)
    if [[ -n "$hidden_suspicious" ]]; then
        warn "Hidden files in temp directories:"
        echo "$hidden_suspicious" | head -5 | while read f; do
            echo -e "    ${WARN} $f"
        done
    else
        ok "No suspicious hidden files in temp directories"
    fi

    # Check for suspicious LaunchAgents/LaunchDaemons
    echo ""
    echo -e "  ${WHITE}Checking Launch Agents/Daemons...${NC}"

    local suspicious_agents=0

    # User LaunchAgents
    for dir in /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents; do
        if [[ -d "$dir" ]]; then
            local agents=$(ls "$dir" 2>/dev/null | grep -v "com.apple" | grep -v "com.microsoft" | grep -v "com.google")
            if [[ -n "$agents" ]]; then
                info "Third-party items in $dir:"
                echo "$agents" | head -5 | while read agent; do
                    echo -e "      ${INFO} $agent"
                done
                suspicious_agents=1
            fi
        fi
    done

    if [[ $suspicious_agents -eq 0 ]]; then
        ok "No suspicious Launch Agents/Daemons detected"
    fi

    # Check for known macOS malware locations
    echo ""
    echo -e "  ${WHITE}Checking known malware locations...${NC}"

    local malware_paths=(
        "/Library/Application Support/macs"
        "/private/var/root/.macs"
        "/Library/LaunchAgents/com.pcv.hlpramc.plist"
        "/Library/LaunchDaemons/com.startup.plist"
        "/Users/Shared/.com.apple.autoUpdate"
    )

    local malware_found=0
    for path in "${malware_paths[@]}"; do
        if [[ -e "$path" ]]; then
            fail "Known malware location found: $path"
            malware_found=1
        fi
    done

    if [[ $malware_found -eq 0 ]]; then
        ok "No known malware locations found"
    fi

    # Check for cron jobs
    echo ""
    echo -e "  ${WHITE}Checking scheduled tasks (cron)...${NC}"

    local user_cron=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$")
    if [[ -n "$user_cron" ]]; then
        if echo "$user_cron" | grep -qiE '(curl|wget|bash|sh|python).*http'; then
            warn "Suspicious cron entry (downloads and executes):"
            echo "$user_cron" | grep -iE '(curl|wget|bash|sh|python).*http'
        else
            info "Cron jobs found (review if unfamiliar):"
            echo "$user_cron" | head -5
        fi
    else
        ok "No user cron jobs"
    fi
}

#-------------------------------------------------------------------------------
# 5. Check system security settings
#-------------------------------------------------------------------------------

check_security_settings() {
    section "5. SECURITY SETTINGS"

    echo -e "  ${WHITE}Checking macOS security features...${NC}"
    echo ""

    # System Integrity Protection (SIP)
    local sip_status=$(csrutil status 2>/dev/null | grep -o "enabled\|disabled")
    if [[ "$sip_status" == "enabled" ]]; then
        ok "System Integrity Protection (SIP) is enabled"
    else
        fail "System Integrity Protection (SIP) is DISABLED"
    fi

    # Gatekeeper
    local gatekeeper=$(spctl --status 2>/dev/null | grep -o "enabled\|disabled")
    if [[ "$gatekeeper" == "enabled" ]]; then
        ok "Gatekeeper is enabled"
    else
        warn "Gatekeeper is disabled"
    fi

    # FileVault
    local filevault=$(fdesetup status 2>/dev/null | grep -o "On\|Off")
    if [[ "$filevault" == "On" ]]; then
        ok "FileVault disk encryption is enabled"
        FILEVAULT_ENABLED=1
    else
        warn "FileVault disk encryption is OFF"
        FILEVAULT_ENABLED=0
    fi

    # macOS Firewall (Application Firewall)
    echo ""
    echo -e "  ${WHITE}Firewall status:${NC}"

    local fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -o "enabled\|disabled")
    if [[ "$fw_status" == "enabled" ]]; then
        ok "macOS Application Firewall is enabled"
        FIREWALL_ACTIVE=1
    else
        warn "macOS Application Firewall is disabled"
        FIREWALL_ACTIVE=0
    fi

    # Stealth mode
    local stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -o "enabled\|disabled")
    if [[ "$stealth" == "enabled" ]]; then
        ok "Stealth mode is enabled"
    else
        info "Stealth mode is disabled (optional)"
    fi

    # Remote login (SSH)
    echo ""
    echo -e "  ${WHITE}Remote access:${NC}"

    local remote_login=$(systemsetup -getremotelogin 2>/dev/null | grep -o "On\|Off")
    if [[ "$remote_login" == "On" ]]; then
        warn "Remote Login (SSH) is enabled - ensure this is intentional"
    else
        ok "Remote Login (SSH) is disabled"
    fi

    # Remote management (ARD)
    local remote_mgmt=$(launchctl list 2>/dev/null | grep -c "com.apple.RemoteDesktop" || echo 0)
    if [[ $remote_mgmt -gt 0 ]]; then
        warn "Apple Remote Desktop is running"
    else
        ok "Apple Remote Desktop is not running"
    fi

    # Screen sharing
    local screen_sharing=$(launchctl list 2>/dev/null | grep -c "com.apple.screensharing" || echo 0)
    if [[ $screen_sharing -gt 0 ]]; then
        warn "Screen Sharing is enabled"
    else
        ok "Screen Sharing is disabled"
    fi
}

#-------------------------------------------------------------------------------
# 6. Check for vulnerabilities
#-------------------------------------------------------------------------------

check_vulnerabilities() {
    section "6. VULNERABILITY ASSESSMENT"

    echo -e "  ${WHITE}Checking for common vulnerabilities...${NC}"
    echo ""

    # Check for software updates
    local updates=$(softwareupdate -l 2>&1 | grep -c "recommended\|restart" || echo 0)
    if [[ $updates -gt 0 ]]; then
        warn "Pending software updates available"
        PENDING_UPDATES=1
    else
        ok "No critical updates pending"
        PENDING_UPDATES=0
    fi

    # Check XProtect version
    echo ""
    echo -e "  ${WHITE}XProtect (built-in malware protection):${NC}"
    local xprotect_version=$(defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist Version 2>/dev/null || echo "Unknown")
    info "XProtect version: $xprotect_version"

    # Check MRT (Malware Removal Tool)
    local mrt_version=$(defaults read /System/Library/CoreServices/MRT.app/Contents/version.plist CFBundleShortVersionString 2>/dev/null || echo "Unknown")
    info "MRT version: $mrt_version"

    # Check for world-writable directories in PATH
    echo ""
    echo -e "  ${WHITE}PATH security:${NC}"

    local path_vuln=0
    IFS=':' read -ra PATHDIR <<< "$PATH"
    for dir in "${PATHDIR[@]}"; do
        if [[ -d "$dir" ]]; then
            local perms=$(ls -ld "$dir" 2>/dev/null | awk '{print $1}')
            if [[ "$perms" == *"w"* ]] && [[ "$perms" != *"t"* ]]; then
                # Check if world-writable (others have write)
                local other_write=$(stat -f "%Sp" "$dir" 2>/dev/null | cut -c9)
                if [[ "$other_write" == "w" ]]; then
                    warn "World-writable directory in PATH: $dir"
                    path_vuln=1
                fi
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
        local outdated=$(brew outdated 2>/dev/null | wc -l | tr -d ' ')
        if [[ $outdated -gt 10 ]]; then
            warn "Outdated Homebrew packages: $outdated"
        elif [[ $outdated -gt 0 ]]; then
            info "Outdated Homebrew packages: $outdated"
        else
            ok "All Homebrew packages up to date"
        fi
    fi
}

#-------------------------------------------------------------------------------
# 7. Check logs for suspicious activity
#-------------------------------------------------------------------------------

check_logs() {
    section "7. LOG ANALYSIS"

    echo -e "  ${WHITE}Checking authentication logs...${NC}"
    echo ""

    # Check for failed SSH attempts
    local ssh_failures=$(log show --predicate 'eventMessage contains "Failed password" OR eventMessage contains "authentication failure"' --last 24h 2>/dev/null | wc -l | tr -d ' ')

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
    log show --predicate 'eventMessage contains "sudo"' --last 1h 2>/dev/null | tail -5 | while read line; do
        echo -e "    ${INFO} $line"
    done

    # Check for kernel panics
    echo ""
    local panics=$(find /Library/Logs/DiagnosticReports -name "*.panic" -mtime -7 2>/dev/null | wc -l | tr -d ' ')
    if [[ $panics -gt 0 ]]; then
        warn "Kernel panics in last 7 days: $panics"
    else
        ok "No kernel panics in last 7 days"
    fi

    # Recent logins
    echo ""
    echo -e "  ${WHITE}Recent logins:${NC}"
    last -5 2>/dev/null | head -5 | while read line; do
        echo -e "    ${INFO} $line"
    done
}

#-------------------------------------------------------------------------------
# Generate Report Summary
#-------------------------------------------------------------------------------

show_summary() {
    section "SCAN COMPLETE - SUMMARY"

    echo ""
    if [[ $ISSUES_FOUND -eq 0 ]] && [[ $WARNINGS_FOUND -eq 0 ]]; then
        echo -e "  ${GREEN}╔══════════════════════════════════════════════╗${NC}"
        echo -e "  ${GREEN}║          SYSTEM APPEARS CLEAN                ║${NC}"
        echo -e "  ${GREEN}╚══════════════════════════════════════════════╝${NC}"
    elif [[ $ISSUES_FOUND -eq 0 ]]; then
        echo -e "  ${YELLOW}╔══════════════════════════════════════════════╗${NC}"
        echo -e "  ${YELLOW}║     CLEAN - BUT SOME WARNINGS FOUND          ║${NC}"
        echo -e "  ${YELLOW}╚══════════════════════════════════════════════╝${NC}"
    else
        echo -e "  ${RED}╔══════════════════════════════════════════════╗${NC}"
        echo -e "  ${RED}║         ISSUES DETECTED - REVIEW BELOW       ║${NC}"
        echo -e "  ${RED}╚══════════════════════════════════════════════╝${NC}"
    fi

    echo ""
    echo -e "  ${WHITE}Results:${NC}"
    echo -e "    ${CROSS} Critical issues: ${RED}$ISSUES_FOUND${NC}"
    echo -e "    ${WARN} Warnings:        ${YELLOW}$WARNINGS_FOUND${NC}"
    echo ""
}

#-------------------------------------------------------------------------------
# Hardening Functions
#-------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------
# Hardening Menu
#-------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

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

# Run main and log output
LOG_FILE="/var/log/intruder-hunter-macos.log"
main 2>&1 | tee "$LOG_FILE"
echo -e "  ${INFO} Scan results saved to: $LOG_FILE"
echo ""
