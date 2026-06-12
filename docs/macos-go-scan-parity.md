# macOS Go Scan Parity

This document tracks retained macOS Bash diagnostics in `lib/macos/*.sh` versus Go-native checks in `internal/platform/macos/*.go`.

macOS parity here means retained diagnostic signal coverage, not byte-for-byte output compatibility. The Go scan emits normalized findings with structured severities, evidence, remediation text, and metadata, so several checks are intentionally broader or less noisy than the retained script.

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
| `lib/macos/network.sh` | Connections to suspicious ports `4444`, `5555`, `6666`, `1337`, `31337` | `internal/platform/macos/network.go` | Covered | `suspiciousPortConnections` flags retained suspicious-port indicators from `netstat -an` evidence. |
| `lib/macos/users.sh` | Users with bash/zsh/sh shell access | `internal/platform/macos/users.go` | Covered | Go parses `dscl . -list /Users UserShell`. |
| `lib/macos/users.sh` | Admin group members and admin count >2 warning | `internal/platform/macos/users.go` | Covered | Go warns when more than two admin group members are reported. |
| `lib/macos/users.sh` | SSH authorized key counts under `/Users/*` | `internal/platform/macos/users.go` | Covered | Go counts non-comment keys in `/Users/*/.ssh/authorized_keys`. |
| `lib/macos/users.sh` | Hidden dot-prefixed local users excluding `.localized` | `internal/platform/macos/users.go` | Covered | Go reports dot-prefixed users from `dscl . -list /Users`. |
| `lib/macos/malware.sh` | Executable files in `/tmp` and `/private/tmp` excluding common Apple noise | `internal/platform/macos/malware.go` | Covered/enhanced | Go scans both paths and filters Apple, `node_modules`, and `.git` noise. |
| `lib/macos/malware.sh` | Hidden files in `/tmp` and `/private/tmp` excluding `.DS_Store` | `internal/platform/macos/malware.go` | Covered/enhanced | `hiddenTempFileFindings` reports dot-prefixed temp files and filters `.DS_Store`, development, Apple, `node_modules`, and `.git` noise. |
| `lib/macos/malware.sh` | Third-party LaunchAgents/LaunchDaemons in system and current-user launch locations | `internal/platform/macos/malware.go` | Covered/intentionally different | Go enumerates system and per-user launch plists and flags suspicious traits. Benign third-party launch items are summarized as reviewed rather than emitted one-by-one to reduce noisy normalized reports. |
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

## Intentional differences from the retained script

- Go checks use normalized findings and richer severities instead of matching Bash output text byte-for-byte.
- Listener and process checks classify risk with additional context rather than reproducing Bash color output.
- Benign third-party LaunchAgents/LaunchDaemons are summarized after review; suspicious launch traits still produce dedicated warning or critical findings.
- Hidden temporary-file and executable checks filter common development, Apple, `node_modules`, and `.git` noise to reduce false positives.
- Report metadata carries scan timing, so individual checks do not duplicate scan-date output.

## Verification path

macOS retained-script diagnostic signal parity is considered complete when:

- `go test ./internal/platform/macos` passes.
- `go test ./...` passes.
- Every retained macOS diagnostic row above traces to a Go-native finding path or an intentional difference.
