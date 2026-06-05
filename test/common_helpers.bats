#!/usr/bin/env bats

setup() {
    TEST_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")" >/dev/null 2>&1 && pwd)"
    ROOT_DIR="$(cd "$TEST_DIR/.." >/dev/null 2>&1 && pwd)"
}

@test "Linux UI helpers update issue and warning counters" {
    # shellcheck source=../lib/linux/common.sh
    source "$ROOT_DIR/lib/linux/common.sh"

    fail "critical problem"
    warn "warning problem"
    ok "healthy state"
    info "context only"

    [[ "$ISSUES_FOUND" -eq 1 ]]
    [[ "$WARNINGS_FOUND" -eq 1 ]]
}

@test "Linux ask_yes_no accepts only a single y or Y" {
    run bash -c 'source "$1"; ask_yes_no "Apply fix?" <<<"$2"' _ "$ROOT_DIR/lib/linux/common.sh" "y"
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"Apply fix?"* ]]

    run bash -c 'source "$1"; ask_yes_no "Apply fix?" <<<"$2"' _ "$ROOT_DIR/lib/linux/common.sh" "yes"
    [[ "$status" -ne 0 ]]
}

@test "macOS UI helpers update issue and warning counters" {
    # shellcheck source=../lib/macos/common.sh
    source "$ROOT_DIR/lib/macos/common.sh"

    fail "critical problem"
    warn "warning problem"
    ok "healthy state"
    info "context only"

    [[ "$ISSUES_FOUND" -eq 1 ]]
    [[ "$WARNINGS_FOUND" -eq 1 ]]
}

@test "macOS check_macos rejects non-Darwin hosts without mutation" {
    if [[ "$(uname)" == "Darwin" ]]; then
        skip "host is Darwin; rejection path is Linux/non-Darwin only"
    fi

    run bash -c 'source "$1"; check_macos' _ "$ROOT_DIR/lib/macos/common.sh"
    [[ "$status" -eq 1 ]]
    [[ "$output" == *"This script is for macOS only"* ]]
}
