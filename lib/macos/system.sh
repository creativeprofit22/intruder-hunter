# shellcheck shell=bash

show_system_info() {
    section "SYSTEM INFORMATION"

    local os_name
    local os_version
    local build
    local hostname
    local uptime_info
    local chip

    os_name=$(sw_vers -productName 2>/dev/null || echo "macOS")
    os_version=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
    build=$(sw_vers -buildVersion 2>/dev/null || echo "Unknown")
    hostname=$(hostname)
    uptime_info=$(uptime | sed 's/.*up //' | sed 's/,.*//')
    chip=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")

    echo -e "  ${WHITE}Hostname:${NC}    $hostname"
    echo -e "  ${WHITE}OS:${NC}          $os_name $os_version ($build)"
    echo -e "  ${WHITE}Chip:${NC}        $chip"
    echo -e "  ${WHITE}Uptime:${NC}      $uptime_info"
    echo -e "  ${WHITE}Scan Date:${NC}   $(date)"
}
