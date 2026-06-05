---
name: update
description: Update dependencies, fix deprecations and warnings
---

## Step 1: Check for Updates

Detected project type: Go module (`go.mod` + `go.sum`).

```bash
go list -m -u all
go list -u -m -json all
```

Review direct and indirect module updates. Pay special attention to major-version changes that require import-path or API changes.

## Step 2: Update Dependencies

```bash
# Update all Go module dependencies within their current major versions.
go get -u ./...

# Clean up module requirements and checksums.
go mod tidy

# Security audit for known Go vulnerabilities.
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

If `go get -u ./...` reports conflicts or skipped major versions, research the affected module release notes before making code changes.

## Step 3: Check for Deprecations & Warnings

Run a clean dependency download and read ALL output carefully. Look for:
- Deprecation warnings
- Security vulnerabilities
- Module retractions
- Toolchain/version warnings
- Breaking changes

```bash
go clean -cache -testcache
go mod download -x
go test ./...
go vet ./...
```

## Step 4: Fix Issues

For each warning/deprecation:
1. Research the recommended replacement or fix in the module's release notes or Go package documentation
2. Update code/dependencies accordingly
3. Re-run `go mod tidy`, `go test ./...`, and `go vet ./...`
4. Verify no warnings remain

## Step 5: Run Quality Checks

```bash
gofmt -l .
make verify
make build-go
```

Fix all errors before completing. If `gofmt -l .` prints any files, run `gofmt -w` on those files and repeat the checks.

## Step 6: Verify Clean Install

Go modules do not use a project-local dependency folder like `node_modules`, so verify with fresh Go caches instead:

```bash
go clean -cache -testcache -modcache
go mod download -x
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
make verify
```

Complete only after the fresh download, tests, vet, vulnerability scan, and project verification finish with ZERO warnings/errors or after every remaining warning has a documented reason and remediation plan.
