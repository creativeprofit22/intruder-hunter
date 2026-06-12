# Intruder Hunter

**Beginner-friendly security diagnostics for Linux, macOS, and Windows**

Intruder Hunter helps you review a computer for common signs of compromise, risky exposure, and security hygiene gaps. The repository now contains a Go CLI foundation plus retained platform scripts while native scan checks continue to migrate.

```
  ___       _                  _             _   _             _
 |_ _|_ __ | |_ _ __ _   _  __| | ___ _ __  | | | |_   _ _ __ | |_ ___ _ __
  | ||  _ \| __|  __| | | |/ _` |/ _ \  __| | |_| | | | |  _ \| __/ _ \  __|
  | || | | | |_| |  | |_| | (_| |  __/ |    |  _  | |_| | | | | ||  __/ |
 |___|_| |_|\__|_|   \__,_|\__,_|\___|_|    |_| |_|\__,_|_| |_|\__\___|_|
```

## Status at a glance

- **Go CLI:** buildable on Linux, macOS, and Windows. It implements `version`, read-only `doctor`, JSON/text output, first-pass `scan` orchestration, and a guarded `legacy` script bridge.
- **Native Go scan:** the command runs registered Go-native checks for the current platform. Linux retained-script diagnostic signal coverage is complete; macOS and Windows parity work is still in progress.
- **Full diagnostics today:** on Linux, use the Go-native `scan` for normalized retained-signal coverage; retained Bash/PowerShell scripts remain available directly or through the Go CLI `legacy` bridge from a repository checkout.
- **Reports:** Go scan output can be text or JSON, can write `--report-json PATH`, and writes private `.intruder-hunter/` snapshots by default unless `--no-snapshot` is set.

## Install and build

### Build from source

```bash
git clone https://github.com/creativeprofit22/intruder-hunter.git
cd intruder-hunter

# Requires Go 1.26+ from go.mod
go run ./cmd/intruder-hunter version
go run ./cmd/intruder-hunter doctor

# Build a host-platform binary in dist/
make build-go
# or override embedded version metadata:
VERSION=1.2.3 COMMIT=abc123 make build-go
```

Maintainers can build release binaries for Linux, macOS, and Windows on `amd64` and `arm64`:

```bash
make release-go
# or: bash scripts/release-go.sh
# VERSION and COMMIT environment variables override the Git-derived metadata.
```

Generated binaries are written to `dist/` as names such as `intruder-hunter-linux-amd64`, `intruder-hunter-darwin-arm64`, and `intruder-hunter-windows-amd64.exe`.

### Run a built binary

```bash
./dist/intruder-hunter-linux-amd64 version
./dist/intruder-hunter-linux-amd64 doctor
./dist/intruder-hunter-linux-amd64 doctor --output json
```

On Windows, run the `.exe` from PowerShell:

```powershell
.\dist\intruder-hunter-windows-amd64.exe version
.\dist\intruder-hunter-windows-amd64.exe doctor --output json
```

## Go CLI usage

| Command | Current behavior |
|---------|------------------|
| `intruder-hunter version` | Prints the CLI version, commit, OS, and architecture. Supports `--output json`. |
| `intruder-hunter doctor` | Read-only prerequisite check for platform, admin/root capability, Go runtime/tooling, and platform tools. Supports `--output json`. |
| `intruder-hunter scan` | Runs registered Go-native checks for the current platform, writes a snapshot by default, and supports `--output`, `--report-json`, `--no-snapshot`, and `--timeout`. Linux covers retained-script diagnostic signals; macOS and Windows checks are still migrating. |
| `intruder-hunter legacy linux-script` | Runs `intruder-hunter.sh` on Linux after checking the current platform and root/admin status. |
| `intruder-hunter legacy macos-script` | Runs `intruder-hunter-macos.sh` on macOS after checking the current platform and root/admin status. |
| `intruder-hunter legacy windows-script` | Runs `intruder-hunter.ps1` on Windows after checking Administrator status. |

Examples:

```bash
# Human-readable output is the default
go run ./cmd/intruder-hunter version
go run ./cmd/intruder-hunter doctor

# Machine-readable CLI envelope
go run ./cmd/intruder-hunter version --output json
go run ./cmd/intruder-hunter doctor --output json

# Run the current Go-native scan orchestrator
go run ./cmd/intruder-hunter scan

# Machine-readable scan output and an additional report file
go run ./cmd/intruder-hunter scan --output json --report-json scan-report.json

# Skip local snapshot files or bound runtime
go run ./cmd/intruder-hunter scan --no-snapshot --timeout 2m
```

The global output flag accepts only `text` and `json`:

```bash
go run ./cmd/intruder-hunter doctor --output json
# shorthand:
go run ./cmd/intruder-hunter doctor -o json
```

## Full scan fallback with legacy scripts

Linux retained-script diagnostic signal coverage is available through the Go-native scan. For macOS and Windows parity gaps, or when you need the original script output, use the retained scripts.

### Linux / WSL2

```bash
git clone https://github.com/creativeprofit22/intruder-hunter.git
cd intruder-hunter
sudo ./intruder-hunter.sh
```

Or through the Go bridge from a checkout:

```bash
sudo go run ./cmd/intruder-hunter legacy linux-script
```

### macOS

```bash
git clone https://github.com/creativeprofit22/intruder-hunter.git
cd intruder-hunter
sudo ./intruder-hunter-macos.sh
```

Or through the Go bridge from a checkout:

```bash
sudo go run ./cmd/intruder-hunter legacy macos-script
```

### Windows

Run PowerShell as Administrator:

```powershell
git clone https://github.com/creativeprofit22/intruder-hunter.git
cd intruder-hunter
.\intruder-hunter.ps1
```

Or through the Go bridge from a checkout:

```powershell
go run ./cmd/intruder-hunter legacy windows-script
```

If you launch the Go binary outside the repository checkout, pass the checkout path before the script subcommand:

```bash
sudo intruder-hunter legacy --repo-root /path/to/intruder-hunter linux-script
```

The legacy bridge does **not** auto-approve hardening. If a script asks whether to apply fixes, answer only after you understand the changes.

## Supported platforms

| Area | Linux | macOS | Windows |
|------|-------|-------|---------|
| Go `version` | Supported | Supported | Supported |
| Go `doctor` | Supported prerequisite profile | Supported prerequisite profile | Supported prerequisite profile |
| Go `scan` | Retained-script diagnostic signals covered in native Go | Orchestrator ready; checks still migrating | Orchestrator ready; checks still migrating |
| Legacy full scan | Bash script | Bash script | PowerShell script |
| Best-tested targets | Ubuntu/Debian and WSL2 | macOS 10.15+ | Windows 10/11 and Windows Server 2016+ |

Linux note: the current script works best on Debian/Ubuntu-style systems. Some scan output works elsewhere, but update and hardening actions still assume tools such as `apt` and `ufw`; RHEL/Fedora, Arch, SUSE, NixOS, and minimal containers may need manual interpretation.

## What the legacy scripts check

### Linux

| Category | Checks performed |
|----------|------------------|
| Processes | Crypto-miner name hints, processes running from `/tmp`, high CPU usage |
| Network | Listening ports, exposed SSH, active connections |
| Users | UID 0 accounts, empty passwords, sudo group, `NOPASSWD` entries, SSH keys |
| Malware | `LD_PRELOAD` hooks, suspicious cron jobs, unusual SUID binaries |
| Files | World-writable `/etc` files, hidden files in `/tmp` |
| Updates | Pending package updates using Debian/Ubuntu-style tools |
| Firewall | UFW status when available |
| Logs | Failed login attempts and recent logins |

### macOS

| Category | Checks performed |
|----------|------------------|
| Processes | Crypto-miner name hints, processes running from temporary paths, high CPU usage |
| Network | Listening ports and active connections |
| Users | Admin users, hidden accounts, SSH authorized keys |
| Security | SIP, Gatekeeper, FileVault, Application Firewall, remote access |
| Malware | LaunchAgents/Daemons, known suspicious paths, cron jobs |
| Vulnerabilities | Pending updates, XProtect/MRT version display, PATH security |
| Logs | Authentication failures, sudo usage, kernel panic hints |

### Windows

| Category | Checks performed |
|----------|------------------|
| Processes | Crypto-miner name hints, Temp-folder processes, high CPU usage |
| Network | Listening ports, selected backdoor-port hints, active connections |
| Users | Hidden accounts, administrator group members, disabled accounts |
| Defender | AV status, real-time protection, known threat detections, scan age |
| Malware | PUP/adware strings, suspicious services, suspicious startup entries |
| Tasks | Scheduled tasks running script hosts from unusual locations |
| Vulnerabilities | UAC, Remote Desktop, SMBv1, pending updates |
| Firewall | Windows Firewall status for profiles |

## Reports, logs, and snapshots

### Current CLI output

The Go CLI writes text or JSON to stdout. The scan command can also write a normalized report file:

```bash
go run ./cmd/intruder-hunter doctor --output json > doctor-report.json
go run ./cmd/intruder-hunter scan --output json --report-json scan-report.json
```

Implemented JSON commands use a stable envelope with:

- `schema_version`
- `tool`
- `platform`
- `started_at` / `completed_at`
- `summary`
- `findings`
- optional `error`

See [docs/json-reporting.md](docs/json-reporting.md) for the schema and current limitations.

### Legacy script logs

| Platform | Current location |
|----------|------------------|
| Linux | `/var/log/intruder-hunter.log` |
| macOS | `/var/log/intruder-hunter-macos.log` |
| Windows | Console output from the current PowerShell session |

### Snapshot storage model

The Go scan command writes a private snapshot by default. The layout under the current directory is:

```text
.intruder-hunter/runs/<utc-timestamp>/metadata.json
.intruder-hunter/runs/<utc-timestamp>/report.json
.intruder-hunter/runs/<utc-timestamp>/raw/...
.intruder-hunter/latest/report.json
```

Use `intruder-hunter scan --no-snapshot` to skip these files. `.intruder-hunter/` is ignored by git so local diagnostic artifacts are not committed accidentally.

## May 2026 detection model changes

The May 2026 migration added the Go-side model that future native checks will use:

- Shared severity names: `critical`, `warning`, `ok`, and `info`.
- Structured finding fields: stable ID, platform, module, check name, title, evidence, remediation, references, and metadata.
- Deterministic report JSON and snapshot helpers.
- A check registry/context contract for platform-specific Go checks.
- A read-only `doctor` command that reports prerequisites without changing system settings.

What did **not** change yet: the legacy scripts still contain several script-era detections. They are useful for triage, but they do not replace a full incident-response investigation. See [docs/detection-refresh-audit.md](docs/detection-refresh-audit.md) for the detailed refresh backlog.

Remaining script-era limitations include:

- Miner detection still relies heavily on process names and simple strings.
- Some network checks still use static suspicious-port lists or do not fully resolve process trust context.
- Linux update/firewall/hardening checks are still strongest on Debian/Ubuntu with `apt` and `ufw`.
- macOS LaunchAgent review is still filename/path oriented and does not fully score plist contents, signatures, or all user homes.
- Windows PUP/miner/persistence checks need richer command-line, signer, registry, service, scheduled-task, and Defender-exclusion context.

## Understanding results and false positives

Treat Intruder Hunter as a guided checklist, not a guarantee that a system is clean.

- **Critical issue:** review promptly. It may indicate compromise, unsafe exposure, or a high-risk configuration.
- **Warning:** needs context. It can be a real problem, a policy choice, or a normal setting for your environment.
- **OK/info:** useful inventory, not proof that no attacker exists.

Common false-positive examples:

- WSL2 may not run a traditional syslog daemon.
- SSH root login can be less relevant if SSH is disabled or blocked by a firewall.
- Developers often run local web servers on ports like `3000`, `5000`, `8000`, `8080`, or `9000`.
- Security labs may intentionally keep miner samples, malware strings, or suspicious filenames.
- Enterprise Macs and Windows PCs may have MDM/GPO-managed security settings that users cannot change locally.

If you are worried about a finding, collect the exact evidence shown by the tool, identify whether the program/account/service is expected, and avoid deleting files until you understand what owns them.

## Hardening steps

Some legacy scripts offer hardening after scanning. Typical actions include applying updates, enabling a firewall, running rootkit scanners, configuring automatic updates, enabling macOS firewall/stealth mode, enabling FileVault, or opening Windows security settings.

These actions are usually helpful on personal machines, but they can affect production servers, remote access, VPNs, backups, or managed corporate devices. Use a maintenance window and backups for important systems, and do not enable a firewall until you know which ports must stay reachable.

## Developer verification

Run the local non-destructive verifier before opening a PR or publishing release artifacts:

```bash
make verify
# or: bash scripts/verify.sh
```

The verifier runs Bash syntax checks, uses ShellCheck when installed, checks Bash formatting with `shfmt -d -i 4 -ln bash` when `shfmt` is installed, runs Bats smoke/unit tests from `test/*.bats` when `bats` is installed, parses PowerShell files when `pwsh` is installed, runs PSScriptAnalyzer and Pester when their PowerShell modules are installed, and runs Go format, vet, lint, and test checks when Go tooling is available. Missing optional tools such as ShellCheck, `shfmt`, `bats`, `pwsh`, PSScriptAnalyzer, Pester, `staticcheck`, and `golangci-lint` are reported as skipped checks instead of failures.

Dedicated lint checks are available for all active languages:

```bash
make lint
# or: bash scripts/verify.sh --lint-only
```

`make lint` runs Bash syntax checks plus ShellCheck when installed, PowerShell parser checks plus PSScriptAnalyzer when `pwsh` and the module are installed, and Go `vet`, `staticcheck`, and `golangci-lint run ./...` when available. It does not run format checks or test suites.

Dedicated format checks are available without rewriting files:

```bash
make format-check
# or directly:
gofmt -l .
shfmt -d -i 4 -ln bash intruder-hunter.sh intruder-hunter-macos.sh lib/linux/*.sh lib/macos/*.sh scripts/*.sh
```

Bash-only smoke/unit tests are available through the optional target below. It runs `bats test/*.bats` when Bats is installed and otherwise reports a skip.

```bash
make bash-tests
```

PowerShell-only checks are available through the optional target below. It performs the parser checks and, when available, runs `Invoke-ScriptAnalyzer` with `PSScriptAnalyzerSettings.psd1` plus `Invoke-Pester -Path './test' -EnableExit` for `*.Tests.ps1` files.

```bash
make powershell-checks
```

Go-only checks are available through these commands:

```bash
make test
# or: go test ./...

make vet
# or: go vet ./...

make staticcheck
# or, when installed: staticcheck ./...

make golangci-lint
# or, when installed: golangci-lint run ./...
```

The repository includes `test/common_helpers.bats` for additive, non-root Bash helper coverage, `PSScriptAnalyzerSettings.psd1` for optional PowerShell linting, and `test/PowerShell.Tests.ps1` for additive Pester coverage of the Windows script sources. It also includes a `.golangci.yml` config using golangci-lint's current `version: "2"` format and the standard linter set, including `govet` and `staticcheck`.

## Maintainer release artifacts

Build standalone Linux/macOS/Windows script bundles:

```bash
make bundle
# or: bash scripts/bundle.sh
bash -n dist/intruder-hunter.sh dist/intruder-hunter-macos.sh
# If pwsh is installed, scripts/verify.sh also parser-checks dist/intruder-hunter.ps1.
```

Build Go CLI release binaries:

```bash
make release-go
# or: bash scripts/release-go.sh
# VERSION and COMMIT environment variables override the Git-derived metadata.
```

Build both standalone scripts and Go CLI binaries:

```bash
make release
```

Generated files are written to `dist/` and intentionally ignored by git.

## Project structure

| Path | Purpose |
|------|---------|
| `cmd/intruder-hunter/` | Go CLI entrypoint |
| `internal/cli/` | Cobra command wiring for `version`, `doctor`, `scan`, and `legacy` |
| `internal/doctor/` | Read-only prerequisite checks for the Go CLI |
| `internal/check/` | Go-native diagnostic check contract and deterministic registry used by `scan` |
| `internal/report/` | Structured report types and JSON serialization |
| `internal/state/` | Private scan snapshot storage helpers used by the CLI by default |
| `internal/legacy/` | Guarded bridge for running retained platform scripts |
| `internal/output/` | CLI text/JSON envelope and stable error codes |
| `intruder-hunter.sh` | Linux legacy scan/hardening entrypoint |
| `intruder-hunter-macos.sh` | macOS legacy scan/hardening entrypoint |
| `intruder-hunter.ps1` | Windows legacy scan/hardening entrypoint |
| `lib/linux/`, `lib/macos/`, `lib/windows/` | Platform script modules |
| `scripts/verify.sh` | Local verification harness |
| `docs/json-reporting.md` | JSON report and snapshot documentation |
| `docs/detection-refresh-audit.md` | May 2026 detection refresh audit and backlog |

## Contributing ideas

- [x] Windows script support
- [x] macOS script support
- [x] Go CLI foundation for version/doctor/JSON envelopes
- [x] JSON report model and snapshot helpers
- [x] Native Go scan checks for Linux retained-script diagnostic signal coverage
- [x] Persisted scan snapshots from the CLI
- [ ] Better distro-aware Linux package/firewall checks
- [ ] Context-aware miner, network, persistence, and PUP detections
- [ ] Scheduled scans via cron/Task Scheduler

## License

MIT License - use freely, no warranty.

---

**Stay safe out there.**
