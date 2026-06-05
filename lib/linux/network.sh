# shellcheck shell=bash

check_network() {
    section "2. NETWORK ANALYSIS"

    echo -e "  ${WHITE}Checking listening ports...${NC}"
    echo ""

    local listeners
    listeners=$(ss -tulpn 2>/dev/null | grep LISTEN || true)

    if [[ -n "$listeners" ]]; then
        echo -e "  ${WHITE}Listening services:${NC}"
        while read -r line; do
            local port
            local process
            local bind

            port=$(awk '{print $5}' <<< "$line" | rev | cut -d: -f1 | rev)
            process=$(awk '{print $7}' <<< "$line" | cut -d'"' -f2)
            bind=$(awk '{print $5}' <<< "$line")

            if [[ "$bind" == *"0.0.0.0"* ]] || [[ "$bind" == *"::"* ]]; then
                if [[ "$port" == "22" ]]; then
                    warn "SSH (port 22) exposed to all interfaces"
                else
                    info "Port $port ($process) - exposed to network"
                fi
            else
                ok "Port $port ($process) - localhost only"
            fi
        done <<< "$listeners"
    else
        ok "No listening services found"
    fi

    echo ""
    echo -e "  ${WHITE}Checking active connections...${NC}"

    # Check for connections to suspicious IPs (simplified check)
    local established
    established=$(ss -antp 2>/dev/null | grep -c ESTAB || true)
    echo -e "  ${INFO} Active connections: $established"
}
