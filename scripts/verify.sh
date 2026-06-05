#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SCRIPT_DIR ROOT_DIR

shopt -s nullglob

SHELL_FILES=(
    "${ROOT_DIR}/intruder-hunter.sh"
    "${ROOT_DIR}/intruder-hunter-macos.sh"
    "${ROOT_DIR}/lib/linux/"*.sh
    "${ROOT_DIR}/lib/macos/"*.sh
    "${ROOT_DIR}/scripts/"*.sh
)

BATS_TEST_FILES=(
    "${ROOT_DIR}/test/"*.bats
)

POWERSHELL_FILES=(
    "${ROOT_DIR}/intruder-hunter.ps1"
    "${ROOT_DIR}/lib/windows/"*.ps1
    "${ROOT_DIR}/dist/intruder-hunter.ps1"
)

POWERSHELL_ANALYZER_SETTINGS="${ROOT_DIR}/PSScriptAnalyzerSettings.psd1"
readonly POWERSHELL_ANALYZER_SETTINGS

read -r -d '' POWERSHELL_PARSE_COMMAND <<'POWERSHELL' || true
$path = $args[0]
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count -gt 0) {
    foreach ($parseError in $parseErrors) {
        [Console]::Error.WriteLine(("{0}:{1}:{2}: {3}" -f $path, $parseError.Extent.StartLineNumber, $parseError.Extent.StartColumnNumber, $parseError.Message))
    }
    exit 1
}
POWERSHELL
readonly POWERSHELL_PARSE_COMMAND

read -r -d '' POWERSHELL_MODULE_AVAILABLE_COMMAND <<'POWERSHELL' || true
$moduleName = $args[0]
if (Get-Module -ListAvailable -Name $moduleName) {
    exit 0
}
exit 1
POWERSHELL
readonly POWERSHELL_MODULE_AVAILABLE_COMMAND

read -r -d '' POWERSHELL_ANALYZER_COMMAND <<'POWERSHELL' || true
$settingsPath = $args[0]
$paths = @($args | Select-Object -Skip 1)
Import-Module PSScriptAnalyzer -ErrorAction Stop
$diagnostics = foreach ($path in $paths) {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Invoke-ScriptAnalyzer -Path $path -Settings $settingsPath
    }
}
if ($diagnostics) {
    $diagnostics | Format-Table -AutoSize | Out-String -Width 240 | Write-Error
    exit 1
}
POWERSHELL
readonly POWERSHELL_ANALYZER_COMMAND
relative_path() {
    local path="$1"
    printf '%s\n' "${path#"${ROOT_DIR}/"}"
}

module_go_version() {
    awk '$1 == "go" { print $2; exit }' "${ROOT_DIR}/go.mod"
}

parse_go_minor_version() {
    local version="$1"
    version="${version#go}"
    awk -F. '{ print $2 }' <<<"$version"
}

golangci_lint_supports_module_go_version() {
    local module_version
    module_version="$(module_go_version)"

    local version_output
    version_output="$(golangci-lint version 2>/dev/null || true)"

    local built_version
    built_version="$(sed -n 's/.*built with \(go[0-9][0-9]*\.[0-9][0-9]*\(\.[0-9][0-9]*\)*\).*/\1/p' <<<"$version_output" | head -n 1)"
    if [[ -z "$built_version" ]]; then
        return 0
    fi

    local module_minor built_minor
    module_minor="$(parse_go_minor_version "$module_version")"
    built_minor="$(parse_go_minor_version "$built_version")"
    if [[ "$module_minor" =~ ^[0-9]+$ && "$built_minor" =~ ^[0-9]+$ && "$built_minor" -lt "$module_minor" ]]; then
        echo "SKIP golangci-lint run ./...: golangci-lint was built with ${built_version}, which is older than module go ${module_version}"
        return 1
    fi

    return 0
}

run_bash_syntax_checks() {
    echo "== Bash syntax checks =="

    local failed=0
    local file
    for file in "${SHELL_FILES[@]}"; do
        if [[ ! -f "$file" ]]; then
            continue
        fi

        if bash -n "$file"; then
            echo "PASS bash -n $(relative_path "$file")"
        else
            echo "FAIL bash -n $(relative_path "$file")"
            failed=1
        fi
    done

    return "$failed"
}

run_shellcheck_checks() {
    echo ""
    echo "== ShellCheck =="

    if ! command -v shellcheck >/dev/null 2>&1; then
        echo "SKIP shellcheck: shellcheck is not installed"
        return 0
    fi

    if shellcheck -x "${SHELL_FILES[@]}"; then
        echo "PASS shellcheck -x"
        return 0
    fi

    echo "FAIL shellcheck -x"
    return 1
}

run_bash_format_checks() {
    echo ""
    echo "== Bash format checks =="

    if ! command -v shfmt >/dev/null 2>&1; then
        echo "SKIP shfmt -d -i 4 -ln bash: shfmt is not installed"
        return 0
    fi

    if shfmt -d -i 4 -ln bash "${SHELL_FILES[@]}"; then
        echo "PASS shfmt -d -i 4 -ln bash"
        return 0
    fi

    echo "FAIL shfmt -d -i 4 -ln bash"
    return 1
}

run_bash_tests() {
    echo ""
    echo "== Bash tests =="

    if [[ ${#BATS_TEST_FILES[@]} -eq 0 ]]; then
        echo "SKIP bats test/*.bats: no Bats tests found"
        return 0
    fi

    if ! command -v bats >/dev/null 2>&1; then
        echo "SKIP bats test/*.bats: bats-core is not installed"
        return 0
    fi

    if (cd "$ROOT_DIR" && bats "${BATS_TEST_FILES[@]}"); then
        echo "PASS bats test/*.bats"
        return 0
    fi

    echo "FAIL bats test/*.bats"
    return 1
}

powershell_module_available() {
    local module_name="$1"
    pwsh -NoLogo -NoProfile -NonInteractive -Command "$POWERSHELL_MODULE_AVAILABLE_COMMAND" "$module_name" >/dev/null 2>&1
}

powershell_test_files_exist() {
    [[ -d "${ROOT_DIR}/test" ]] && find "${ROOT_DIR}/test" -type f -name '*.Tests.ps1' -print -quit | grep -q .
}

run_powershell_parser_checks() {
    echo ""
    echo "== PowerShell parser checks =="

    if ! command -v pwsh >/dev/null 2>&1; then
        echo "SKIP PowerShell parser checks: pwsh is not installed"
        return 0
    fi

    if [[ ${#POWERSHELL_FILES[@]} -eq 0 ]]; then
        echo "SKIP PowerShell parser checks: no PowerShell files found"
        return 0
    fi

    local failed=0
    local file
    for file in "${POWERSHELL_FILES[@]}"; do
        if [[ ! -f "$file" ]]; then
            continue
        fi

        if pwsh -NoLogo -NoProfile -NonInteractive -Command "$POWERSHELL_PARSE_COMMAND" "$file"; then
            echo "PASS pwsh parser $(relative_path "$file")"
        else
            echo "FAIL pwsh parser $(relative_path "$file")"
            failed=1
        fi
    done

    return "$failed"
}

run_powershell_analyzer_checks() {
    echo ""
    echo "== PSScriptAnalyzer =="

    if ! command -v pwsh >/dev/null 2>&1; then
        echo "SKIP Invoke-ScriptAnalyzer: pwsh is not installed"
        return 0
    fi

    if [[ ! -f "$POWERSHELL_ANALYZER_SETTINGS" ]]; then
        echo "SKIP Invoke-ScriptAnalyzer: PSScriptAnalyzerSettings.psd1 not found"
        return 0
    fi

    if ! powershell_module_available PSScriptAnalyzer; then
        echo "SKIP Invoke-ScriptAnalyzer: PSScriptAnalyzer module is not installed"
        return 0
    fi

    local existing_files=()
    local file
    for file in "${POWERSHELL_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            existing_files+=("$file")
        fi
    done

    if [[ ${#existing_files[@]} -eq 0 ]]; then
        echo "SKIP Invoke-ScriptAnalyzer: no PowerShell files found"
        return 0
    fi

    if pwsh -NoLogo -NoProfile -NonInteractive -Command "$POWERSHELL_ANALYZER_COMMAND" "$POWERSHELL_ANALYZER_SETTINGS" "${existing_files[@]}"; then
        echo "PASS Invoke-ScriptAnalyzer"
        return 0
    fi

    echo "FAIL Invoke-ScriptAnalyzer"
    return 1
}

run_pester_tests() {
    echo ""
    echo "== Pester tests =="

    if ! command -v pwsh >/dev/null 2>&1; then
        echo "SKIP Invoke-Pester test/*.Tests.ps1: pwsh is not installed"
        return 0
    fi

    if ! powershell_test_files_exist; then
        echo "SKIP Invoke-Pester test/*.Tests.ps1: no Pester tests found"
        return 0
    fi

    if ! powershell_module_available Pester; then
        echo "SKIP Invoke-Pester test/*.Tests.ps1: Pester module is not installed"
        return 0
    fi

    if (cd "$ROOT_DIR" && pwsh -NoLogo -NoProfile -NonInteractive -Command "Import-Module Pester -ErrorAction Stop; Invoke-Pester -Path './test' -EnableExit"); then
        echo "PASS Invoke-Pester test/*.Tests.ps1"
        return 0
    fi

    echo "FAIL Invoke-Pester test/*.Tests.ps1"
    return 1
}

run_go_format_checks() {
    echo ""
    echo "== Go format checks =="

    if [[ ! -f "${ROOT_DIR}/go.mod" ]]; then
        echo "SKIP gofmt -l .: go.mod not found"
        return 0
    fi

    if ! command -v gofmt >/dev/null 2>&1; then
        echo "SKIP gofmt -l .: gofmt is not installed"
        return 0
    fi

    local unformatted
    unformatted="$(cd "$ROOT_DIR" && gofmt -l .)"
    if [[ -z "$unformatted" ]]; then
        echo "PASS gofmt -l ."
        return 0
    fi

    printf '%s\n' "$unformatted"
    echo "FAIL gofmt -l ."
    return 1
}

run_go_vet_checks() {
    echo ""
    echo "== Go vet =="

    if [[ ! -f "${ROOT_DIR}/go.mod" ]]; then
        echo "SKIP go vet ./...: go.mod not found"
        return 0
    fi

    if ! command -v go >/dev/null 2>&1; then
        echo "SKIP go vet ./...: go is not installed"
        return 0
    fi

    if (cd "$ROOT_DIR" && go vet ./...); then
        echo "PASS go vet ./..."
        return 0
    fi

    echo "FAIL go vet ./..."
    return 1
}

run_staticcheck_checks() {
    echo ""
    echo "== Staticcheck =="

    if [[ ! -f "${ROOT_DIR}/go.mod" ]]; then
        echo "SKIP staticcheck ./...: go.mod not found"
        return 0
    fi

    if ! command -v staticcheck >/dev/null 2>&1; then
        echo "SKIP staticcheck ./...: staticcheck is not installed"
        return 0
    fi

    if (cd "$ROOT_DIR" && staticcheck ./...); then
        echo "PASS staticcheck ./..."
        return 0
    fi

    echo "FAIL staticcheck ./..."
    return 1
}

run_golangci_lint_checks() {
    echo ""
    echo "== golangci-lint =="

    if [[ ! -f "${ROOT_DIR}/go.mod" ]]; then
        echo "SKIP golangci-lint run ./...: go.mod not found"
        return 0
    fi

    if ! command -v golangci-lint >/dev/null 2>&1; then
        echo "SKIP golangci-lint run ./...: golangci-lint is not installed"
        return 0
    fi

    if ! golangci_lint_supports_module_go_version; then
        return 0
    fi

    if (cd "$ROOT_DIR" && golangci-lint run ./...); then
        echo "PASS golangci-lint run ./..."
        return 0
    fi

    echo "FAIL golangci-lint run ./..."
    return 1
}

run_go_tests() {
    echo ""
    echo "== Go tests =="

    if [[ ! -f "${ROOT_DIR}/go.mod" ]]; then
        echo "SKIP go test ./...: go.mod not found"
        return 0
    fi

    if ! command -v go >/dev/null 2>&1; then
        echo "SKIP go test ./...: go is not installed"
        return 0
    fi

    if (cd "$ROOT_DIR" && go test ./...); then
        echo "PASS go test ./..."
        return 0
    fi

    echo "FAIL go test ./..."
    return 1
}

run_powershell_checks() {
    local status=0

    if ! run_powershell_parser_checks; then
        status=1
    fi

    if ! run_powershell_analyzer_checks; then
        status=1
    fi

    if ! run_pester_tests; then
        status=1
    fi

    return "$status"
}

run_powershell_lint_checks() {
    local status=0

    if ! run_powershell_parser_checks; then
        status=1
    fi

    if ! run_powershell_analyzer_checks; then
        status=1
    fi

    return "$status"
}

run_bash_lint_checks() {
    local status=0

    if ! run_bash_syntax_checks; then
        status=1
    fi

    if ! run_shellcheck_checks; then
        status=1
    fi

    return "$status"
}

run_go_lint_checks() {
    local status=0

    if ! run_go_vet_checks; then
        status=1
    fi

    if ! run_staticcheck_checks; then
        status=1
    fi

    if ! run_golangci_lint_checks; then
        status=1
    fi

    return "$status"
}

run_all_lint_checks() {
    local status=0

    if ! run_bash_lint_checks; then
        status=1
    fi

    if ! run_powershell_lint_checks; then
        status=1
    fi

    if ! run_go_lint_checks; then
        status=1
    fi

    echo ""
    if [[ $status -eq 0 ]]; then
        echo "Lint complete: all available checks passed"
    else
        echo "Lint complete: one or more checks failed"
    fi

    return "$status"
}

run_all_verification_checks() {
    local status=0

    if ! run_bash_lint_checks; then
        status=1
    fi

    if ! run_bash_format_checks; then
        status=1
    fi

    if ! run_bash_tests; then
        status=1
    fi

    if ! run_powershell_checks; then
        status=1
    fi

    if ! run_go_format_checks; then
        status=1
    fi

    if ! run_go_lint_checks; then
        status=1
    fi

    if ! run_go_tests; then
        status=1
    fi

    echo ""
    if [[ $status -eq 0 ]]; then
        echo "Verification complete: all available checks passed"
    else
        echo "Verification complete: one or more checks failed"
    fi

    return "$status"
}

main() {
    case "${1:-}" in
        --powershell-only)
            run_powershell_checks
            return $?
            ;;
        --lint-only)
            run_all_lint_checks
            return $?
            ;;
        "")
            run_all_verification_checks
            return $?
            ;;
        *)
            echo "Usage: $(basename "$0") [--lint-only|--powershell-only]" >&2
            return 2
            ;;
    esac
}

main "$@"
