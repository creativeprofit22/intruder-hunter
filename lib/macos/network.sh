# shellcheck shell=bash

check_network() {
    section "2. NETWORK ANALYSIS"

    echo -e "  ${WHITE}Checking listening ports...${NC}"
    echo ""

    # Get listening ports using lsof
    local listeners
    listeners=$(lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | tail -n +2 || true)

    if [[ -n "$listeners" ]]; then
        echo -e "  ${WHITE}Listening services:${NC}"
        while read -r line; do
            local process
            local port
            local bind

            process=$(awk '{print $1}' <<< "$line")
            port=$(awk '{print $9}' <<< "$line" | rev | cut -d: -f1 | rev)
            bind=$(awk '{print $9}' <<< "$line")

            if [[ "$bind" == "*:"* ]]; then
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

    # Check for established connections
    local established
    established=$(netstat -an 2>/dev/null | grep -c ESTABLISHED || true)
    echo -e "  ${INFO} Active connections: $established"

    # Check for connections to suspicious ports
    local suspicious_ports
    suspicious_ports=$(netstat -an 2>/dev/null | grep -cE ':4444|:5555|:6666|:1337|:31337' || true)
    if [[ $suspicious_ports -gt 0 ]]; then
        warn "Connections to known suspicious ports detected!"
        netstat -an | grep -E ':4444|:5555|:6666|:1337|:31337'
    fi
}
