# shellcheck shell=bash

check_users() {
    section "3. USER & AUTHENTICATION ANALYSIS"

    echo -e "  ${WHITE}Checking user accounts...${NC}"
    echo ""

    # List all users with shells
    echo -e "  ${WHITE}Users with shell access:${NC}"
    dscl . -list /Users UserShell 2>/dev/null | grep -E '(/bin/bash|/bin/zsh|/bin/sh)$' | while read -r line; do
        local username
        local shell
        local uid
        username=$(awk '{print $1}' <<< "$line")
        shell=$(awk '{print $2}' <<< "$line")
        uid=$(dscl . -read /Users/"$username" UniqueID 2>/dev/null | awk '{print $2}' || true)
        echo -e "    ${INFO} $username (UID: $uid) - $shell"
    done

    echo ""

    # Check admin users
    echo -e "  ${WHITE}Admin users:${NC}"
    local admin_users
    local admin_count
    admin_users=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' || true)
    admin_count=$(wc -w <<< "$admin_users" | tr -d ' ')

    tr ' ' '\n' <<< "$admin_users" | while read -r user; do
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
            local keycount
            local username
            keycount=$(wc -l < "$home/.ssh/authorized_keys" 2>/dev/null | tr -d ' ' || echo 0)
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

    # Check for hidden admin accounts
    echo ""
    local hidden
    hidden=$(dscl . -list /Users 2>/dev/null | grep -E '^\.' | grep -v '.localized' || true)
    if [[ -n "$hidden" ]]; then
        warn "Hidden user accounts (starting with .):"
        while read -r user; do
            echo -e "    ${WARN} $user"
        done <<< "$hidden"
    else
        ok "No hidden user accounts"
    fi
}
