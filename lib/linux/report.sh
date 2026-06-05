# shellcheck shell=bash

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
