# Linux Go Scan Parity

This document tracks retained Linux Bash diagnostics from `lib/linux/*.sh` against the Go-native Linux scan implementation in `internal/platform/linux/*.go`.

Linux parity here means retained diagnostic signal coverage, not byte-for-byte output compatibility. The Go scan emits normalized findings with structured severities, evidence, remediation text, and metadata, so several checks are intentionally broader or less noisy than the retained script.

## Parity matrix

| Retained script source | Retained Linux signal | Go-native location | Status | Notes |
|---|---|---|---|---|
| `lib/linux/system.sh` | Hostname, OS release, kernel, uptime, scan date | `internal/platform/linux/system.go` | Mostly covered | Go includes hostname, OS, kernel, uptime, and architecture. Scan date is covered by report metadata rather than the Linux system check. |
| `lib/linux/processes.sh` | Miner-name hints | `internal/platform/linux/processes.go` | Covered/enhanced | Go includes miner/tool names plus miner CLI and pool indicators. |
| `lib/linux/processes.sh` | Processes from `./`, `/tmp`, `/var/tmp`, `/dev/shm` | `internal/platform/linux/processes.go` | Covered/enhanced | Go includes these paths plus `/home/`; severity is score-based. |
| `lib/linux/processes.sh` | Top 5 CPU processes | `internal/platform/linux/processes.go` | Covered | `topCPU(processes, 5)` produces evidence. |
| `lib/linux/network.sh` | Listening services from `ss -tulpn` | `internal/platform/linux/network.go` | Covered/enhanced | Go emits one finding per listener and classifies exposed or high-risk services. |
| `lib/linux/network.sh` | Port 22 exposed warning | `internal/platform/linux/network.go` | Covered | `highRiskService(22)` returns an SSH warning when exposed. |
| `lib/linux/network.sh` | Active connection count from `ss -antp` | `internal/platform/linux/network.go` | Covered | Go reports established connection count. |
| `lib/linux/users.sh` | Login-shell users | `internal/platform/linux/users.go` | Covered | Go reports common shell users as info evidence. |
| `lib/linux/users.sh` | Multiple UID 0 accounts | `internal/platform/linux/users.go` | Covered | Go reports critical for more than one UID 0 account. |
| `lib/linux/users.sh` | Empty/no-password shadow entries (`""` or `!`) | `internal/platform/linux/users.go` | Covered | `readNoPasswordUsers` and `parseNoPasswordUsers` cover the retained script signal. |
| `lib/linux/users.sh` | `sudo` group members | `internal/platform/linux/users.go` | Covered/enhanced | Go reads `sudo` and `wheel` from `/etc/group`; Bash used `getent group sudo`. |
| `lib/linux/users.sh` | Un-commented `NOPASSWD` sudoers entries | `internal/platform/linux/users.go` | Covered | Go recursively reads `/etc/sudoers` and `/etc/sudoers.d`. |
| `lib/linux/users.sh` | SSH authorized key counts in `/home/*` and `/root` | `internal/platform/linux/users.go` | Covered/enhanced | Go enumerates homes from `/etc/passwd` plus `/root`, then counts non-comment keys. |
| `lib/linux/malware.sh` | Executable files in `/tmp` and `/var/tmp` | `internal/platform/linux/malware.go` | Covered/enhanced | Go scans `/tmp`, `/var/tmp`, and `/dev/shm`; it filters development noise. |
| `lib/linux/malware.sh` | Hidden files in `/tmp`, `/var/tmp`, `/dev/shm` | `internal/platform/linux/malware.go` | Covered | `hiddenTempFileFindings` reports retained hidden temporary-file signals. |
| `lib/linux/malware.sh` | Active `/etc/ld.so.preload` entries | `internal/platform/linux/malware.go` | Covered | Go reports critical for uncommented entries. |
| `lib/linux/malware.sh` | Suspicious user crontabs with downloader/interpreter/http patterns | `internal/platform/linux/malware.go` | Covered/enhanced | Go reads user crontabs plus system cron and includes broader suspicious persistence patterns. |
| `lib/linux/malware.sh` | Unusual SUID binaries | `internal/platform/linux/malware.go` | Covered/enhanced | Go uses a baseline plus package ownership (`dpkg`, `rpm`, `pacman`) and risky-path checks. |
| `lib/linux/vulnerabilities.sh` | Pending apt updates | `internal/platform/linux/vulnerabilities.go` | Covered/enhanced | Go uses non-mutating checks and supports `apt`, `dnf`, `yum`, and `pacman`; it intentionally does not run `apt update`. |
| `lib/linux/vulnerabilities.sh` | UFW status active/inactive/not installed | `internal/platform/linux/vulnerabilities.go` | Covered/enhanced | Go checks UFW, firewalld, and nftables. |
| `lib/linux/vulnerabilities.sh` | World-writable regular files under `/etc` | `internal/platform/linux/vulnerabilities.go` | Covered | `etcWritableFinding` covers the retained Bash diagnostic. |
| `lib/linux/vulnerabilities.sh` | SSH `PermitRootLogin yes` | `internal/platform/linux/vulnerabilities.go` | Covered | Go reports warning when explicitly set to `yes`. |
| `lib/linux/vulnerabilities.sh` | SSH `PasswordAuthentication yes` | `internal/platform/linux/vulnerabilities.go` | Covered | Go reports info when explicitly set to `yes`. |
| `lib/linux/logs.sh` | Failed password count in `/var/log/auth.log` | `internal/platform/linux/logs.go` | Covered/enhanced | Go supports `/var/log/auth.log` and `/var/log/secure`; it also counts `authentication failure`. |
| `lib/linux/logs.sh` | High failed-login threshold >100 with recent five attempts | `internal/platform/linux/logs.go` | Covered | `summarizeFailedLogins` returns count and the last five matching lines. |
| `lib/linux/logs.sh` | Recent logins via `last -n 5` | `internal/platform/linux/logs.go` | Covered | Go collects up to five `last` records. |

## Intentional differences from the retained script

- Go checks use normalized findings and richer severities instead of matching Bash output text byte-for-byte.
- Package update checks avoid mutating host package metadata; the Go scan does not run `apt update`.
- Firewall coverage is broader than UFW-only and includes firewalld and nftables signals.
- SUID review is intentionally less naive than the Bash baseline because package ownership reduces false positives.
- Report metadata carries scan timing, so the Linux system check does not duplicate scan-date output.

## Operational caveats

Some Linux findings depend on privileged files such as `/etc/shadow`, sudoers, and auth logs. Non-root scans may therefore produce unavailable, info, or OK findings where a root scan can collect stronger evidence.

User crontab enumeration and recursive scans of `/` for SUID files or `/etc` for world-writable files can be permission-limited or slower on unusual mounts. Command timeouts mitigate hangs but may result in unavailable/info findings rather than complete evidence.

## Verification path

Linux retained-script diagnostic signal parity is considered complete when:

- `go test ./internal/platform/linux` passes.
- `go test ./...` passes.
- Every retained Linux diagnostic row above traces to a Go-native finding path.
- README language scopes any Linux completion claim to retained Linux diagnostic signal coverage, not complete cross-platform native parity.
