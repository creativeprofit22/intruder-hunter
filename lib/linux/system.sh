# shellcheck shell=bash

show_system_info() {
    section "SYSTEM INFORMATION"

    local os_name="unknown"
    local kernel
    local hostname
    local uptime_info

    if [[ -r /etc/os-release ]]; then
        os_name=$(awk -F= '/^PRETTY_NAME=/ {gsub(/^"|"$/, "", $2); print $2; exit}' /etc/os-release)
    fi

    kernel=$(uname -r)
    hostname=$(hostname)
    uptime_info=$(uptime -p 2>/dev/null || echo "unknown")

    echo -e "  ${WHITE}Hostname:${NC}    $hostname"
    echo -e "  ${WHITE}OS:${NC}          $os_name"
    echo -e "  ${WHITE}Kernel:${NC}      $kernel"
    echo -e "  ${WHITE}Uptime:${NC}      $uptime_info"
    echo -e "  ${WHITE}Scan Date:${NC}   $(date)"
}
