# Intruder Hunter

Intruder Hunter is a cross-platform local security diagnostics toolkit: a Cobra-based Go CLI plus retained Linux/macOS Bash and Windows PowerShell diagnostic scripts.

## Structure

- `cmd/intruder-hunter/main.go` is the Go executable entry point; it delegates to `internal/cli.Execute`.
- `internal/cli/` wires CLI commands: `version`, `doctor`, `scan`, and `legacy`; `--output/-o` supports `text` and `json`.
- `internal/check/` defines the diagnostic check contract and deterministic registry.
- `internal/platform/linux/`, `internal/platform/macos/`, and `internal/platform/windows/` contain Go-native checks for system, process, network, users, malware/persistence, vulnerability, logs, and platform-specific security/Defender/task signals.
- `internal/scan/` orchestrates Go-native checks, aggregates findings, writes optional report JSON, and stores snapshots unless disabled.
- `internal/report/` and `internal/output/` define/render the normalized report/envelope model (`schema_version: 1.0`, severities `critical`, `warning`, `ok`, `info`).
- `internal/state/` writes scan snapshots under `.intruder-hunter/runs/<utc-ts>/` and updates `.intruder-hunter/latest/report.json`.
- `internal/doctor/` implements environment/prerequisite checks; `internal/legacy/` bridges to retained platform scripts after platform/admin checks.
- `lib/linux/`, `lib/macos/`, and `lib/windows/` are support modules for the retained scripts; the top-level `intruder-hunter.sh`, `intruder-hunter-macos.sh`, and `intruder-hunter.ps1` launch them.
- `scripts/` contains verification, bundling, and release helpers; `test/` contains Bats/PowerShell script tests; `dist/` contains generated build/bundle artifacts and is not source-of-truth.

## CLI workflows

```bash
go run ./cmd/intruder-hunter version
go run ./cmd/intruder-hunter doctor
go run ./cmd/intruder-hunter doctor --output json
go run ./cmd/intruder-hunter scan
go run ./cmd/intruder-hunter scan --report-json report.json
go run ./cmd/intruder-hunter scan --no-snapshot --timeout 30s
```

Retained-script bridge commands must run on the matching platform and require administrator/root privileges:

```bash
sudo go run ./cmd/intruder-hunter legacy linux-script
sudo go run ./cmd/intruder-hunter legacy macos-script
```

```powershell
go run ./cmd/intruder-hunter legacy windows-script
```

The legacy bridge also accepts `--repo-root` when the retained scripts are not discoverable from the current working directory. Legacy scripts are interactive and may offer hardening; the Go CLI does not auto-accept those prompts.

## Build, release, and project commands

The project is Go module `github.com/creativeprofit22/intruder-hunter` (`go 1.26`) and depends on `github.com/spf13/cobra`.

```bash
make test              # go test ./...
make vet               # go vet ./...
make lint              # bash scripts/verify.sh --lint-only
make verify            # bash scripts/verify.sh
make bash-tests        # bash scripts/verify.sh --bash-tests-only
make powershell-checks # bash scripts/verify.sh --powershell-only
make format-check      # gofmt plus shfmt diff checks
make build-go          # dist/intruder-hunter-<host-os>-<host-arch>
make bundle            # scripts/bundle.sh
make release-go        # scripts/release-go.sh
make release           # bundle + cross-platform Go release builds
make clean             # removes dist/
```

Release builds target `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, and `windows/arm64` via `scripts/release-go.sh`.

## Output and storage notes

- Go-native `scan` writes snapshots by default; use `--no-snapshot` to avoid `.intruder-hunter` state.
- `--report-json PATH` writes a normalized report separate from the snapshot layout.
- Windows Go-native checks invoke PowerShell only on Windows; on non-Windows runtimes those checks report unavailable/skipped evidence.
- The retained scripts and the Go-native platform checks coexist during the migration, so keep behavior changes aligned between `internal/platform/<os>/` and `lib/<os>/` when they cover the same diagnostic area.
