# shellcheck shell=bash

check_users() {
    section "3. USER & AUTHENTICATION ANALYSIS"

    echo -e "  ${WHITE}Checking user accounts...${NC}"
    echo ""

    # Users with shell access
    echo -e "  ${WHITE}Users with shell access:${NC}"
    local shell_users
    shell_users=$(grep -E '(/bin/bash|/bin/sh|/bin/zsh)$' /etc/passwd || true)
    while read -r line; do
        [[ -z "$line" ]] && continue
        local username
        local uid
        local shell
        username=$(cut -d: -f1 <<< "$line")
        uid=$(cut -d: -f3 <<< "$line")
        shell=$(cut -d: -f7 <<< "$line")
        echo -e "    ${INFO} $username (UID: $uid) - $shell"
    done <<< "$shell_users"

    echo ""

    # Check for multiple UID 0 users
    local root_users
    local root_count
    root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    root_count=$(wc -l <<< "$root_users")

    if [[ $root_count -gt 1 ]]; then
        fail "Multiple users with UID 0 (root privileges):"
        while read -r user; do
            echo -e "    ${CROSS} $user"
        done <<< "$root_users"
    else
        ok "Only 'root' has UID 0"
    fi

    # Check for empty passwords
    local empty_pass
    empty_pass=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "$empty_pass" ]]; then
        warn "Users with empty/no password:"
        while read -r user; do
            echo -e "    ${WARN} $user"
        done <<< "$empty_pass"
    else
        ok "No users with empty passwords"
    fi

    # Check sudo group
    echo ""
    echo -e "  ${WHITE}Sudo access:${NC}"
    local sudo_users
    sudo_users=$(getent group sudo 2>/dev/null | cut -d: -f4 || true)
    if [[ -n "$sudo_users" ]]; then
        echo -e "    ${INFO} Users in sudo group: $sudo_users"
    fi

    # Check for NOPASSWD in sudoers
    local nopasswd
    nopasswd=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" || true)
    if [[ -n "$nopasswd" ]]; then
        warn "NOPASSWD entries found in sudoers (passwordless sudo):"
        while read -r line; do
            echo -e "    ${WARN} $line"
        done <<< "$nopasswd"
    else
        ok "No dangerous NOPASSWD entries"
    fi

    # Check SSH authorized_keys
    echo ""
    echo -e "  ${WHITE}SSH authorized keys:${NC}"
    local found_keys=0
    for home in /home/* /root; do
        if [[ -f "$home/.ssh/authorized_keys" ]]; then
            local keycount
            local username
            keycount=$(wc -l < "$home/.ssh/authorized_keys" 2>/dev/null || echo 0)
            username=$(basename "$home")
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
