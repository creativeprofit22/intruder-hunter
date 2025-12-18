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
    echo -e "${WHITE}  Linux Security Diagnostic & Hardening Tool${NC}"
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
    ((ISSUES_FOUND++))
}

warn() {
    echo -e "  ${WARN} $1"
    ((WARNINGS_FOUND++))
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

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p $pid > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "      \b\b\b\b\b\b"
}

#-------------------------------------------------------------------------------
# Check if running as root
#-------------------------------------------------------------------------------

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
        echo ""
        echo "  Usage: sudo ./intruder-hunter.sh"
        echo ""
        exit 1
    fi
}

#-------------------------------------------------------------------------------
# System Information
#-------------------------------------------------------------------------------

show_system_info() {
    section "SYSTEM INFORMATION"

    local os_name=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
    local kernel=$(uname -r)
    local hostname=$(hostname)
    local uptime=$(uptime -p 2>/dev/null || echo "unknown")

    echo -e "  ${WHITE}Hostname:${NC}    $hostname"
    echo -e "  ${WHITE}OS:${NC}          $os_name"
    echo -e "  ${WHITE}Kernel:${NC}      $kernel"
    echo -e "  ${WHITE}Uptime:${NC}      $uptime"
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
    local miners=$(ps aux 2>/dev/null | grep -iE '(miner|xmrig|xmr|monero|coinminer|kdevtmpfsi|kinsing)' | grep -v grep | wc -l)
    if [[ $miners -gt 0 ]]; then
        fail "Potential crypto miners detected!"
        ps aux | grep -iE '(miner|xmrig|xmr|monero|coinminer|kdevtmpfsi|kinsing)' | grep -v grep
    else
        ok "No crypto miners detected"
    fi

    # Check for suspicious process names
    local suspicious=$(ps aux 2>/dev/null | awk '{print $11}' | grep -E '^\./|^/tmp/|^/var/tmp/|^/dev/shm/' | wc -l)
    if [[ $suspicious -gt 0 ]]; then
        warn "Processes running from suspicious locations (tmp/dev):"
        ps aux | awk '$11 ~ /^\.\/|^\/tmp\/|^\/var\/tmp\/|^\/dev\/shm\//'
    else
        ok "No processes running from suspicious locations"
    fi

    # High CPU processes
    echo ""
    echo -e "  ${WHITE}Top 5 CPU-consuming processes:${NC}"
    ps aux --sort=-%cpu 2>/dev/null | head -6 | tail -5 | awk '{printf "    %-10s %5s%% CPU  %s\n", $1, $3, $11}'
}

#-------------------------------------------------------------------------------
# 2. Check network connections
#-------------------------------------------------------------------------------

check_network() {
    section "2. NETWORK ANALYSIS"

    echo -e "  ${WHITE}Checking listening ports...${NC}"
    echo ""

    # Get listening ports
    local listeners=$(ss -tulpn 2>/dev/null | grep LISTEN)

    if [[ -n "$listeners" ]]; then
        echo -e "  ${WHITE}Listening services:${NC}"
        echo "$listeners" | while read line; do
            local port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
            local process=$(echo "$line" | awk '{print $7}' | cut -d'"' -f2)
            local bind=$(echo "$line" | awk '{print $5}')

            if [[ "$bind" == *"0.0.0.0"* ]] || [[ "$bind" == *"::"* ]]; then
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

    # Check for connections to suspicious IPs (simplified check)
    local established=$(ss -antp 2>/dev/null | grep ESTAB | wc -l)
    echo -e "  ${INFO} Active connections: $established"
}

#-------------------------------------------------------------------------------
# 3. Check users and authentication
#-------------------------------------------------------------------------------

check_users() {
    section "3. USER & AUTHENTICATION ANALYSIS"

    echo -e "  ${WHITE}Checking user accounts...${NC}"
    echo ""

    # Users with shell access
    echo -e "  ${WHITE}Users with shell access:${NC}"
    local shell_users=$(grep -E '(/bin/bash|/bin/sh|/bin/zsh)$' /etc/passwd)
    echo "$shell_users" | while read line; do
        local username=$(echo "$line" | cut -d: -f1)
        local uid=$(echo "$line" | cut -d: -f3)
        local shell=$(echo "$line" | cut -d: -f7)
        echo -e "    ${INFO} $username (UID: $uid) - $shell"
    done

    echo ""

    # Check for multiple UID 0 users
    local root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    local root_count=$(echo "$root_users" | wc -l)

    if [[ $root_count -gt 1 ]]; then
        fail "Multiple users with UID 0 (root privileges):"
        echo "$root_users" | while read user; do
            echo -e "    ${CROSS} $user"
        done
    else
        ok "Only 'root' has UID 0"
    fi

    # Check for empty passwords
    local empty_pass=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$empty_pass" ]]; then
        warn "Users with empty/no password:"
        echo "$empty_pass" | while read user; do
            echo -e "    ${WARN} $user"
        done
    else
        ok "No users with empty passwords"
    fi

    # Check sudo group
    echo ""
    echo -e "  ${WHITE}Sudo access:${NC}"
    local sudo_users=$(getent group sudo 2>/dev/null | cut -d: -f4)
    if [[ -n "$sudo_users" ]]; then
        echo -e "    ${INFO} Users in sudo group: $sudo_users"
    fi

    # Check for NOPASSWD in sudoers
    local nopasswd=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#")
    if [[ -n "$nopasswd" ]]; then
        warn "NOPASSWD entries found in sudoers (passwordless sudo):"
        echo "$nopasswd" | while read line; do
            echo -e "    ${WARN} $line"
        done
    else
        ok "No dangerous NOPASSWD entries"
    fi

    # Check SSH authorized_keys
    echo ""
    echo -e "  ${WHITE}SSH authorized keys:${NC}"
    local found_keys=0
    for home in /home/* /root; do
        if [[ -f "$home/.ssh/authorized_keys" ]]; then
            local keycount=$(wc -l < "$home/.ssh/authorized_keys" 2>/dev/null || echo 0)
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
}

#-------------------------------------------------------------------------------
# 4. Check for rootkits and malware indicators
#-------------------------------------------------------------------------------

check_malware() {
    section "4. MALWARE & ROOTKIT INDICATORS"

    echo -e "  ${WHITE}Checking for common indicators...${NC}"
    echo ""

    # Check for suspicious files in /tmp
    local tmp_executables=$(find /tmp /var/tmp -type f -executable 2>/dev/null | grep -v node_modules | grep -v ".git" | head -20)
    local tmp_exec_count=$(echo "$tmp_executables" | grep -v "^$" | wc -l)

    if [[ $tmp_exec_count -gt 0 ]]; then
        warn "Executable files in temp directories: $tmp_exec_count"
        echo -e "    ${INFO} (May include legitimate dev files - review if unsure)"
    else
        ok "No suspicious executables in temp directories"
    fi

    # Check for hidden files in common locations
    local hidden_suspicious=$(find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null | grep -v ".gitignore" | grep -v ".env" | head -10)
    if [[ -n "$hidden_suspicious" ]]; then
        warn "Hidden files in temp/shm directories:"
        echo "$hidden_suspicious" | head -5 | while read f; do
            echo -e "    ${WARN} $f"
        done
    else
        ok "No suspicious hidden files in temp directories"
    fi

    # Check for LD_PRELOAD rootkits
    if [[ -f /etc/ld.so.preload ]]; then
        local preload_content=$(cat /etc/ld.so.preload 2>/dev/null | grep -v "^#" | grep -v "^$")
        if [[ -n "$preload_content" ]]; then
            fail "LD_PRELOAD rootkit indicator - /etc/ld.so.preload contains:"
            echo "$preload_content"
        else
            ok "/etc/ld.so.preload is empty"
        fi
    else
        ok "No /etc/ld.so.preload file (good)"
    fi

    # Check cron for suspicious entries
    echo ""
    echo -e "  ${WHITE}Checking scheduled tasks (cron)...${NC}"

    local suspicious_cron=0

    # User crontabs
    for user in $(cut -d: -f1 /etc/passwd); do
        local user_cron=$(crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$")
        if [[ -n "$user_cron" ]]; then
            if echo "$user_cron" | grep -qiE '(curl|wget|bash|sh|python).*http'; then
                warn "Suspicious cron entry for $user (downloads and executes):"
                echo "$user_cron" | grep -iE '(curl|wget|bash|sh|python).*http'
                suspicious_cron=1
            fi
        fi
    done

    if [[ $suspicious_cron -eq 0 ]]; then
        ok "No suspicious cron jobs detected"
    fi

    # Check SUID binaries
    echo ""
    echo -e "  ${WHITE}Checking SUID binaries...${NC}"

    local known_suid="/usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/mount /usr/bin/umount /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/pkexec /usr/bin/fusermount3 /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/libexec/polkit-agent-helper-1"

    local suid_files=$(find / -perm -4000 -type f 2>/dev/null)
    local unknown_suid=0

    while read suid; do
        if [[ ! " $known_suid " =~ " $suid " ]]; then
            # Check if it's a known system binary
            if [[ "$suid" != *"/snap/"* ]] && [[ "$suid" != *"/usr/lib/"* ]]; then
                warn "Unusual SUID binary: $suid"
                unknown_suid=1
            fi
        fi
    done <<< "$suid_files"

    if [[ $unknown_suid -eq 0 ]]; then
        ok "All SUID binaries are standard system files"
    fi
}

#-------------------------------------------------------------------------------
# 5. Check system vulnerabilities
#-------------------------------------------------------------------------------

check_vulnerabilities() {
    section "5. VULNERABILITY ASSESSMENT"

    echo -e "  ${WHITE}Checking for common vulnerabilities...${NC}"
    echo ""

    # Pending updates
    if command -v apt &> /dev/null; then
        apt update -qq 2>/dev/null
        local updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0)

        if [[ $updates -gt 10 ]]; then
            warn "Pending security updates: $updates packages"
            PENDING_UPDATES=$updates
        elif [[ $updates -gt 0 ]]; then
            info "Pending updates: $updates packages"
            PENDING_UPDATES=$updates
        else
            ok "System is up to date"
            PENDING_UPDATES=0
        fi
    fi

    # Firewall status
    echo ""
    echo -e "  ${WHITE}Firewall status:${NC}"

    if command -v ufw &> /dev/null; then
        local ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
            ok "UFW firewall is active"
            FIREWALL_ACTIVE=1
        else
            warn "UFW firewall is inactive"
            FIREWALL_ACTIVE=0
        fi
    else
        warn "UFW not installed"
        FIREWALL_ACTIVE=0
    fi

    # World-writable files in /etc
    echo ""
    echo -e "  ${WHITE}File permissions:${NC}"

    local world_writable=$(find /etc -type f -perm -002 2>/dev/null)
    if [[ -n "$world_writable" ]]; then
        warn "World-writable files in /etc:"
        echo "$world_writable" | while read f; do
            echo -e "    ${WARN} $f"
        done
    else
        ok "No world-writable files in /etc"
    fi

    # SSH configuration
    if [[ -f /etc/ssh/sshd_config ]]; then
        echo ""
        echo -e "  ${WHITE}SSH configuration:${NC}"

        local root_login=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        if [[ "$root_login" == "yes" ]]; then
            warn "SSH allows root login"
        else
            ok "SSH root login is restricted"
        fi

        local pass_auth=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        if [[ "$pass_auth" == "yes" ]]; then
            info "SSH password authentication is enabled"
        fi
    fi
}

#-------------------------------------------------------------------------------
# 6. Check logs for suspicious activity
#-------------------------------------------------------------------------------

check_logs() {
    section "6. LOG ANALYSIS"

    echo -e "  ${WHITE}Checking authentication logs...${NC}"
    echo ""

    # Failed login attempts
    if [[ -f /var/log/auth.log ]]; then
        local failed_logins=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)

        if [[ $failed_logins -gt 100 ]]; then
            warn "High number of failed login attempts: $failed_logins"
            echo -e "    ${INFO} Recent failed attempts:"
            grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 | while read line; do
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
    last -n 5 2>/dev/null | head -5 | while read line; do
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

#-------------------------------------------------------------------------------
# Hardening Menu
#-------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

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

# Run main and log output
main 2>&1 | tee /var/log/intruder-hunter.log
