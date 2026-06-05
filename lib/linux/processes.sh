# shellcheck shell=bash

check_processes() {
    section "1. PROCESS ANALYSIS"

    echo -e "  ${WHITE}Checking for suspicious processes...${NC}"
    echo ""

    local process_list
    local miners
    local suspicious
    process_list=$(ps aux 2>/dev/null || true)

    # Check for crypto miners
    miners=$(printf '%s\n' "$process_list" | grep -Eiv 'grep|intruder-hunter' | grep -ciE '(miner|xmrig|xmr|monero|coinminer|kdevtmpfsi|kinsing)' || true)
    if [[ $miners -gt 0 ]]; then
        fail "Potential crypto miners detected!"
        printf '%s\n' "$process_list" | grep -Eiv 'grep|intruder-hunter' | grep -iE '(miner|xmrig|xmr|monero|coinminer|kdevtmpfsi|kinsing)' || true
    else
        ok "No crypto miners detected"
    fi

    # Check for suspicious process names
    suspicious=$(printf '%s\n' "$process_list" | awk '{print $11}' | grep -cE '^\./|^/tmp/|^/var/tmp/|^/dev/shm/' || true)
    if [[ $suspicious -gt 0 ]]; then
        warn "Processes running from suspicious locations (tmp/dev):"
        printf '%s\n' "$process_list" | awk '$11 ~ /^\.\/|^\/tmp\/|^\/var\/tmp\/|^\/dev\/shm\//'
    else
        ok "No processes running from suspicious locations"
    fi

    # High CPU processes
    echo ""
    echo -e "  ${WHITE}Top 5 CPU-consuming processes:${NC}"
    ps aux --sort=-%cpu 2>/dev/null | head -6 | tail -5 | awk '{printf "    %-10s %5s%% CPU  %s\n", $1, $3, $11}'
}
