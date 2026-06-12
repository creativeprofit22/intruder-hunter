# Windows Go Scan Parity

This document tracks retained Windows PowerShell diagnostics from `lib/windows/*.ps1` against the Go-native Windows scan implementation in `internal/platform/windows/*.go`.

Windows parity here means retained diagnostic signal coverage, not byte-for-byte output compatibility. The Go scan emits normalized findings with structured severities, evidence, remediation text, and metadata, so several checks are intentionally broader or less noisy than the retained script.

## Parity matrix

| Retained script source | Retained Windows signal | Go-native location | Status | Notes |
|---|---|---|---|---|
| `lib/windows/System.ps1` | Hostname, OS caption/version, current user, uptime/boot time, scan date | `internal/platform/windows/system.go` | Covered | Go collects computer name, OS version/build, current user, install date, and boot time. Scan date is covered by report metadata. |
| `lib/windows/Processes.ps1` | Miner-name process hints | `internal/platform/windows/processes.go` | Covered/enhanced | Go includes retained miner names plus pool, CLI, high-CPU, and user-writable path scoring. |
| `lib/windows/Processes.ps1` | Processes running from temp directories | `internal/platform/windows/processes.go` | Covered/enhanced | Go flags user-writable paths including temp, user profile, and Downloads context. |
| `lib/windows/Processes.ps1` | Top 5 CPU processes | `internal/platform/windows/processes.go` | Covered | `topWindowsCPU(processes, 5)` emits normalized evidence. |
| `lib/windows/Network.ps1` | Listening ports from `Get-NetTCPConnection -State Listen` | `internal/platform/windows/network.go` | Covered/enhanced | Go collects listener owner process, service, path, and emits a top-10 summary. |
| `lib/windows/Network.ps1` | Suspicious listening ports `4444`, `5555`, `6666`, `1337`, `31337`, `9999`, `8080`, `3389` | `internal/platform/windows/network.go` | Covered/enhanced | Go flags retained suspicious ports; `3389` is also classified as RDP/high-risk remote access. |
| `lib/windows/Network.ps1` | Firewall profile enabled/disabled status | `internal/platform/windows/vulnerabilities.go` | Covered | Go emits warnings for disabled profiles and OK evidence when all returned profiles are enabled. |
| `lib/windows/Users.ps1` | Local users with enabled/last-logon context | `internal/platform/windows/users.go` | Covered/enhanced | Go collects local users and summarizes disabled accounts; hidden-style users get dedicated findings. |
| `lib/windows/Users.ps1` | Administrators group members and count >2 warning | `internal/platform/windows/users.go` | Covered | Go emits administrator membership evidence and warns when more than two principals are present. |
| `lib/windows/Users.ps1` | Hidden enabled local users ending with `$` | `internal/platform/windows/users.go` | Covered/enhanced | Go flags `$` suffix and dot-prefixed local users. |
| `lib/windows/Malware.ps1` | Known PUP/adware patterns in running processes | `internal/platform/windows/malware.go` | Covered | Go matches retained PUP patterns against running process name/path evidence. |
| `lib/windows/Malware.ps1` | Known PUP/adware patterns in services | `internal/platform/windows/malware.go` | Covered | Go matches retained PUP patterns against service name/display-name evidence. |
| `lib/windows/Malware.ps1` | Suspicious startup commands from temp/PUP indicators | `internal/platform/windows/malware.go` | Covered/enhanced | Go reviews Run keys, `Win32_StartupCommand`, automatic services, and WMI persistence for user-writable paths and miner indicators. |
| `lib/windows/ScheduledTasks.ps1` | Non-Microsoft ready scheduled task count | `internal/platform/windows/tasks.go` | Covered/enhanced | Go emits a scheduled task inventory summary for review. |
| `lib/windows/ScheduledTasks.ps1` | Script actions using PowerShell/cmd/wscript/cscript/mshta with http/temp indicators | `internal/platform/windows/tasks.go` | Covered/enhanced | Go flags user-writable paths, encoded shell/download indicators, and miner context in task actions. |
| `lib/windows/Defender.ps1` | Defender antivirus and real-time protection status | `internal/platform/windows/defender.go` | Covered/enhanced | Go also checks behavior monitor, IOAV, NIS, signature update time, and scan ages. |
| `lib/windows/Defender.ps1` | Active threats from `Get-MpThreat` | `internal/platform/windows/defender.go` | Covered | Go reports active threat records as critical and emits OK evidence when none are active. |
| `lib/windows/Defender.ps1` | Quick scan age >7 days | `internal/platform/windows/defender.go` | Covered | Go warns when `QuickScanAge` exceeds seven days. |
| `lib/windows/Vulnerabilities.ps1` | Pending Windows Update count | `internal/platform/windows/vulnerabilities.go` | Covered/enhanced | Go uses Windows Update COM search and warns for any pending software updates rather than waiting for more than ten. |
| `lib/windows/Vulnerabilities.ps1` | UAC enabled/disabled | `internal/platform/windows/vulnerabilities.go` | Covered | Go emits warning for disabled UAC and OK evidence when enabled. |
| `lib/windows/Vulnerabilities.ps1` | Remote Desktop enabled/disabled | `internal/platform/windows/vulnerabilities.go` | Covered | Go emits warning when RDP is enabled and OK evidence when disabled. |
| `lib/windows/Vulnerabilities.ps1` | SMBv1 enabled/disabled | `internal/platform/windows/vulnerabilities.go` | Covered | Go emits critical when SMBv1 server support is enabled and OK evidence when disabled. |

## Intentional differences from the retained script

- Go checks use normalized findings and richer severities instead of matching PowerShell output text byte-for-byte.
- Process, startup, scheduled task, and listener checks combine multiple context signals before escalating severity.
- Windows Update coverage warns for any pending software update count, which is stricter than the retained script's `>10` warning threshold.
- Firewall posture is implemented in the Windows vulnerability/security posture check rather than the network check.
- Report metadata carries scan timing, so the Windows system check does not duplicate scan-date output.

## Verification path

Windows retained-script diagnostic signal parity is considered complete when:

- `go test ./internal/platform/windows` passes.
- `go test ./...` passes.
- Every retained Windows diagnostic row above traces to a Go-native finding path or an intentional difference.
