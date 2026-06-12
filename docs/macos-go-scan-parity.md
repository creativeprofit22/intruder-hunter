# macOS Go Scan Parity

This is the starting parity matrix for retained macOS Bash diagnostics in `lib/macos/*.sh` versus Go-native checks in `internal/platform/macos/*.go`. It is a planning document only; do not treat macOS retained-script signal parity as complete until the open gaps are implemented and verified.

## Current parity matrix

| Retained script source | Retained macOS signal | Go-native location | Status | Notes |
|---|---|---|---|---|
| `lib/macos/system.sh` | Product name/version/build, hostname, chip, uptime, scan date | `internal/platform/macos/system.go` | Covered | Go collects `sw_vers`, hostname, chip, uptime, and includes `scan_started_at` evidence. |
| `lib/macos/processes.sh` | Miner-name hints | `internal/platform/macos/processes.go` | Covered/enhanced | Go includes miner/tool names plus miner CLI and pool indicators. |
| `lib/macos/processes.sh` | Processes from `/tmp`, `/var/tmp`, `/private/tmp` | `internal/platform/macos/processes.go` | Covered/enhanced | Go includes these temp paths plus `/Users/Shared`, Downloads, and relative execution. |
| `lib/macos/processes.sh` | Top 5 CPU processes | `internal/platform/macos/processes.go` | Covered | `topCPU(processes, 5)` emits evidence. |
| `lib/macos/network.sh` | Listening services from `lsof -iTCP -sTCP:LISTEN -n -P` | `internal/platform/macos/network.go` | Covered/enhanced | Go emits normalized listener findings and classifies exposed/high-risk services. |
| `lib/macos/network.sh` | Port 22 exposed warning | `internal/platform/macos/network.go` | Covered | `highRiskService(22)` returns SSH warning when exposed. |
| `lib/macos/network.sh` | Active established connection count | `internal/platform/macos/network.go` | Covered | Go counts `ESTABLISHED` lines from `netstat -an`. |
| `lib/macos/network.sh` | Connections to suspicious ports `4444`, `5555`, `6666`, `1337`, `31337` | None yet | Gap | Go currently summarizes established connections but does not flag these retained suspicious-port indicators. |
| `lib/macos/users.sh` | Users with bash/zsh/sh shell access | `internal/platform/macos/users.go` | Covered | Go parses `dscl . -list /Users UserShell`. |
| `lib/macos/users.sh` | Admin group members and admin count >2 warning | `internal/platform/macos/users.go` | Covered | Go warns when more than two admin group members are reported. |
| `lib/macos/users.sh` | SSH authorized key counts under `/Users/*` | `internal/platform/macos/users.go` | Covered | Go counts non-comment keys in `/Users/*/.ssh/authorized_keys`. |
| `lib/macos/users.sh` | Hidden dot-prefixed local users excluding `.localized` | `internal/platform/macos/users.go` | Covered | Go reports dot-prefixed users from `dscl . -list /Users`. |
| `lib/macos/malware.sh` | Executable files in `/tmp` and `/private/tmp` excluding common Apple noise | `internal/platform/macos/malware.go` | Covered/enhanced | Go scans both paths and filters Apple, `node_modules`, and `.git` noise. |
| `lib/macos/malware.sh` | Hidden files in `/tmp` and `/private/tmp` excluding `.DS_Store` | None yet | Gap | Go does not currently emit a hidden temp-file finding for macOS. |
| `lib/macos/malware.sh` | Third-party LaunchAgents/LaunchDaemons in system and current-user launch locations | `internal/platform/macos/malware.go` | Partially covered/enhanced | Go enumerates system and per-user launch plists and flags suspicious traits; it may not emit info-only evidence for benign third-party launch items that Bash listed. |
| `lib/macos/malware.sh` | Known malware/adware paths | `internal/platform/macos/malware.go` | Covered | Go checks the retained path list and reports critical findings. |
| `lib/macos/malware.sh` | User cron jobs, including downloader/interpreter/http patterns | `internal/platform/macos/malware.go` | Covered/enhanced | Go reports cron presence and flags downloader, URL, encoded-command, and temp-path indicators. |
| `lib/macos/security.sh` | SIP enabled/disabled | `internal/platform/macos/security.go` | Covered | Go uses `csrutil status` and reports critical when disabled. |
| `lib/macos/security.sh` | Gatekeeper enabled/disabled | `internal/platform/macos/security.go` | Covered | Go uses `spctl --status`. |
| `lib/macos/security.sh` | FileVault on/off | `internal/platform/macos/security.go` | Covered | Go uses `fdesetup status`. |
| `lib/macos/security.sh` | Application Firewall enabled/disabled | `internal/platform/macos/security.go` | Covered | Go uses `socketfilterfw --getglobalstate`. |
| `lib/macos/security.sh` | Firewall stealth mode enabled/disabled | `internal/platform/macos/security.go` | Covered | Go uses `socketfilterfw --getstealthmode`. |
| `lib/macos/security.sh` | Remote Login SSH on/off | `internal/platform/macos/security.go` | Covered | Go uses `systemsetup -getremotelogin`. |
| `lib/macos/security.sh` | Apple Remote Desktop running | `internal/platform/macos/security.go` | Covered | Go checks `launchctl list` for `com.apple.RemoteDesktop`. |
| `lib/macos/security.sh` | Screen Sharing running | `internal/platform/macos/security.go` | Covered | Go checks `launchctl list` for `com.apple.screensharing`. |
| `lib/macos/vulnerabilities.sh` | Pending Apple software updates | `internal/platform/macos/vulnerabilities.go` | Covered | Go parses `softwareupdate --list`. |
| `lib/macos/vulnerabilities.sh` | XProtect version | `internal/platform/macos/vulnerabilities.go` | Covered/enhanced | Go reports XProtect version and security data update context where available. |
| `lib/macos/vulnerabilities.sh` | MRT version | `internal/platform/macos/vulnerabilities.go` | Covered | Go reports MRT version where available. |
| `lib/macos/vulnerabilities.sh` | World-writable directories in `PATH` | `internal/platform/macos/vulnerabilities.go` | Covered | Go checks visible PATH directory mode bits directly. |
| `lib/macos/vulnerabilities.sh` | Outdated Homebrew package count and >10 warning | `internal/platform/macos/vulnerabilities.go` | Covered | Go parses `brew outdated` output and escalates above ten packages. |
| `lib/macos/logs.sh` | Authentication failures in last 24h, high threshold >100 | `internal/platform/macos/logs.go` | Covered | Go uses the retained `log show` predicate and threshold. |
| `lib/macos/logs.sh` | Recent sudo usage from last hour, last five lines | `internal/platform/macos/logs.go` | Covered | Go collects up to five matching log lines. |
| `lib/macos/logs.sh` | Kernel panic reports from last 7 days | `internal/platform/macos/logs.go` | Covered | Go scans `/Library/Logs/DiagnosticReports` for recent `.panic` files. |
| `lib/macos/logs.sh` | Recent logins via `last -5` | `internal/platform/macos/logs.go` | Covered | Go collects up to five `last` rows. |

## Open gaps before macOS parity completion

1. Add Go-native detection for retained suspicious network ports `4444`, `5555`, `6666`, `1337`, and `31337` from `netstat -an` evidence.
2. Add Go-native hidden temp-file findings for `/tmp` and `/private/tmp`, excluding `.DS_Store` and comparable development noise.
3. Decide whether benign third-party LaunchAgents/LaunchDaemons should be emitted as info evidence to match the retained script's review list, or document the stricter suspicious-only behavior as intentional.

## Verification path

Before marking macOS retained-script diagnostic signal parity complete:

- Add focused parser/unit tests for any implemented gap that can be tested without host-specific macOS files.
- Run `go test ./internal/platform/macos`.
- Run `go test ./...`.
- Update this matrix and README status language only after all retained macOS diagnostic rows are covered or intentionally documented as different.
