#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly DIST_DIR="${ROOT_DIR}/dist"
readonly BINARY_NAME="intruder-hunter"
readonly VERSION_PACKAGE="github.com/creativeprofit22/intruder-hunter/internal/version"

VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
readonly VERSION
readonly COMMIT
readonly LDFLAGS="-s -w -X ${VERSION_PACKAGE}.Version=${VERSION} -X ${VERSION_PACKAGE}.Commit=${COMMIT}"

readonly PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

build_binary() {
    local platform="$1"
    local goos="${platform%/*}"
    local goarch="${platform#*/}"
    local output="${DIST_DIR}/${BINARY_NAME}-${goos}-${goarch}"

    if [[ "$goos" == "windows" ]]; then
        output="${output}.exe"
    fi

    echo "Building ${goos}/${goarch} -> ${output#"${ROOT_DIR}/"}"
    (cd "$ROOT_DIR" && GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$output" ./cmd/intruder-hunter)
}

main() {
    if ! command -v go >/dev/null 2>&1; then
        echo "go is required to build release binaries" >&2
        return 1
    fi

    mkdir -p "$DIST_DIR"

    local platform
    for platform in "${PLATFORMS[@]}"; do
        build_binary "$platform"
    done
}

main "$@"
