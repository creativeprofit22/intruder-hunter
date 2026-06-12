# Detection Refresh Audit

## Scope and method

This audit reviews the current detection and hardening assumptions in:

- `README.md`
- `CLAUDE.md`
- `intruder-hunter.sh`
- `intruder-hunter-macos.sh`
- `intruder-hunter.ps1`
- `lib/linux/*.sh`
- `lib/macos/*.sh`
- `lib/windows/*.ps1`
- the Go CLI/report/check foundation under `cmd/` and `internal/`

This document was originally refreshed for the May 2026 Go CLI migration and now includes current scan-status notes. The migration added a structured CLI/report model, a read-only `doctor` command, Go-native `scan` orchestration with registered checks, and a guarded legacy script bridge; it does **not** mean every detection below has been reimplemented in Go yet.

## Current Go CLI migration status

| Area | Status | Notes |
|---|---|---|
| Install/build | Implemented | Build with Go 1.26+ using `go run ./cmd/intruder-hunter ...`, `make build-go`, or `make release-go`. |
| `version` | Implemented | Supports text and JSON output. |
| `doctor` | Implemented | Read-only prerequisite profile for Linux, macOS, and Windows. It checks local capability and tool availability, not compromise. |
| `scan` | Implemented with scoped parity | Runs registered Go-native checks for the current platform. Linux retained-script diagnostic signal coverage is complete; macOS and Windows parity work is still migrating. |
| JSON envelope | Implemented for Go CLI commands | Uses `schema_version`, `tool`, `platform`, timestamps, `summary`, `findings`, and optional `error`; `scan --output json` emits this envelope. |
| Snapshot storage | Implemented in CLI | Default scan layout is `.intruder-hunter/runs/<utc-ts>/report.json`, metadata, optional raw artifacts, and `.intruder-hunter/latest/report.json`; use `scan --no-snapshot` to disable it. |
| Legacy fallback | Implemented | `legacy linux-script`, `legacy macos-script`, and `legacy windows-script` check platform/admin status and then run retained scripts without auto-approving hardening prompts. |

## May 2026 detection model changes

The Go foundation introduces the model future native detections should follow:

- Shared severities: `critical`, `warning`, `ok`, and `info`.
- Structured findings with stable IDs, platform, module, check name, evidence, remediation, references, and metadata.
- Deterministic report JSON and private snapshot helpers.
- A check registry/context contract for platform-specific native checks.
- Clear separation between prerequisite checks (`doctor`) and diagnostic checks (`scan`, implemented with Linux retained-signal coverage while macOS/Windows parity continues).

The legacy scripts remain useful for triage, but their script-era limitations remain. A warning may be a true issue, a normal setting, or a policy decision; a clean-looking summary is not proof that no attacker is present.

## Priority summary

| Priority | Area | Why it matters | Primary files |
|---|---|---|---|
| P0 | Replace single-token miner/PUP matching with normalized signature lists and context checks | Current process matching is easy to evade and can false-positive on benign strings like `miner` or `xmr` | `lib/linux/processes.sh`, `lib/macos/processes.sh`, `lib/windows/Common.ps1`, `lib/windows/Processes.ps1`, `lib/windows/Malware.ps1` |
| P0 | Rework Linux SUID allowlisting to be distro-aware and package-backed | Current blanket exclusions for `/usr/lib/` and `/snap/` can miss real privilege-escalation persistence | `lib/linux/malware.sh` |
| P1 | Improve macOS LaunchAgent/Daemon filtering by parsing plist contents and trust context | Current vendor-name filtering only lists third-party items and misses suspicious `ProgramArguments` behavior | `lib/macos/malware.sh` |
| P1 | Revisit suspicious port logic across platforms | Static backdoor-port lists are outdated and noisy; exposure, owning process, and service context matter more | `lib/linux/network.sh`, `lib/macos/network.sh`, `lib/windows/Common.ps1`, `lib/windows/Network.ps1` |
| P1 | Make update and firewall checks platform/distro/profile aware | Current checks assume apt/UFW on Linux, simple Application Firewall on macOS, and all Windows profiles equally | `lib/linux/vulnerabilities.sh`, `lib/linux/hardening.sh`, `lib/macos/security.sh`, `lib/macos/vulnerabilities.sh`, `lib/windows/Network.ps1`, `lib/windows/Vulnerabilities.ps1`, `lib/windows/Hardening.ps1` |
| P2 | Add explicit false-positive guidance and severity tiers | Current summary can overstate or understate risk because warnings are mixed with hygiene findings | `lib/*/report.*`, `README.md`, `CLAUDE.md` |

## Findings and recommended updates

### 1. Crypto miner detection is narrow, string-based, and easy to evade

**Current behavior**

- Linux and macOS scan `ps aux` and grep process text for `(miner|xmrig|xmr|monero|coinminer|kdevtmpfsi|kinsing)` in `lib/linux/processes.sh` and `lib/macos/processes.sh`.
- Windows defines `$MinerPatterns = @('xmrig', 'xmr', 'miner', 'coinminer', 'nicehash', 'ethminer', 'cgminer', 'bfgminer', 'cpuminer')` in `lib/windows/Common.ps1` and applies those patterns to process names in `lib/windows/Processes.ps1`.

**Weaknesses**

- Process names are attacker-controlled and commonly renamed to benign names such as `systemd`, `kworker`, `java`, `python`, `nginx`, `svchost`, or random strings.
- The token `miner` causes false positives for benign software, source paths, usernames, package names, and documentation opened in terminals.
- The token `xmr` can match unrelated process names or command lines.
- Current checks do not inspect command-line flags commonly associated with miners, such as pool URLs, wallet-like identifiers, `stratum+tcp`, `--donate-level`, `--algo`, `--coin`, `--url`, `--user`, `--pass`, `--cpu-priority`, `--randomx`, or `--opencl`.
- Current Linux/macOS checks do not inspect executable path metadata, deleted executable mappings, parent process, listening/egress behavior, or high sustained CPU combined with suspicious origin.
- Windows uses `Get-Process`; on many systems `Path` can be empty without elevated or provider-specific access, and command line is not collected. This reduces visibility into renamed miners.

**Recommended updates**

1. Add a central signature model per platform with:
   - `name_patterns` for known tools/families.
   - `command_line_patterns` for mining flags and pool protocols.
   - `path_patterns` for temp/user-writable execution.
   - `network_patterns` for common mining pool protocols and ports.
   - `severity` and `rationale` fields.
2. Expand miner indicators to include, at minimum, both tool names and behavior:
   - Tool/family names: `xmrig`, `xmrig-proxy`, `kdevtmpfsi`, `kinsing`, `watchdog`, `sysrv`, `kinsing`, `teamtnt`, `masscan` paired with downloader/persistence behavior, `kinsing`, `hildegard`, `lemonduck`, `nicehash`, `nanominer`, `nanopool`, `cpuminer`, `cpuminer-multi`, `ethminer`, `nbminer`, `lolminer`, `t-rex`, `phoenixminer`, `bfgminer`, `cgminer`, `minerd`.
   - Command-line indicators: `stratum+tcp`, `stratum+ssl`, `pool.minexmr`, `supportxmr`, `nanopool`, `nicehash`, `moneroocean`, `2miners`, `f2pool`, `miningpoolhub`, `--donate-level`, `--coin`, `--algo`, `randomx`, `rx/0`, wallet-like arguments adjacent to pool configuration.
3. Combine weak signals before warning or failing. For example:
   - Critical: known miner name plus pool command line, or temp executable plus mining-pool connection, or known malware family path.
   - Warning: generic `miner` token only, high CPU only, or process from temp without network evidence.
4. On Linux/macOS, prefer process command and executable path fields from `ps -axo pid,ppid,user,%cpu,etime,comm,args` rather than parsing `$11` from `ps aux`.
5. On Windows, use `Get-CimInstance Win32_Process` to collect `Name`, `ExecutablePath`, `CommandLine`, `ParentProcessId`, and creation date. Keep `Get-Process` only for CPU/resource summary.
6. Report exact matching reason. Example: `matched command-line indicator stratum+tcp and executable path /tmp/.x/kinsing`.

**False-positive risks**

- Cryptocurrency users may intentionally run miners, wallets, benchmarking tools, or NiceHash.
- Security labs and developers may keep miner samples, YARA rules, or pool strings in paths or arguments.
- Generic names like `miner`, `watchdog`, `sysrv`, and `svchost` require context before being treated as critical.

### 2. Suspicious port checks rely on outdated static lists

**Current behavior**

- Linux lists listening services and warns only when SSH listens on all interfaces in `lib/linux/network.sh`; other exposed ports are informational.
- macOS lists listeners and checks active connections for `:4444|:5555|:6666|:1337|:31337` in `lib/macos/network.sh`.
- Windows defines `$SuspiciousPorts = @(4444, 5555, 6666, 1337, 31337, 9999, 8080, 3389)` in `lib/windows/Common.ps1`; `lib/windows/Network.ps1` treats listeners on those ports as failures.

**Weaknesses**

- Backdoors and RATs commonly use ordinary ports such as 80, 443, 53, 123, 8080, 8443, or cloud service endpoints. Static backdoor lists miss these.
- Ports like 8080 and 3389 are common legitimate services. Treating them as automatically suspicious creates false positives.
- Linux does not highlight high-risk exposed services beyond SSH.
- macOS checks suspicious ports only in `netstat` output and does not connect the port to owning process metadata.
- Windows reports `OwningProcess` but does not resolve it to process name, path, signer, command line, or service.

**Recommended updates**

1. Replace `suspicious port == bad` with a risk model:
   - Publicly exposed administrative service: SSH, RDP, VNC, WinRM, SMB, database ports.
   - Publicly exposed uncommon listener owned by user-writable or temp-path executable.
   - Listener owned by unsigned, recently created, or unknown process.
   - Listener bound to all interfaces vs loopback only.
2. Maintain a small `high_risk_services` table rather than a backdoor-only port table:
   - Linux/macOS: 22, 23, 25, 111, 139, 445, 3306, 5432, 5900-5909, 6379, 8000-9000, 9200, 11211, 27017.
   - Windows: 135, 139, 445, 3389, 5985, 5986, 5900-5909, database ports.
3. Resolve owning process consistently:
   - Linux: `ss -tulpn` plus PID/program extraction.
   - macOS: `lsof -iTCP -sTCP:LISTEN -n -P` already provides process and PID; include both.
   - Windows: map `OwningProcess` to `Win32_Process` and service names.
4. For active outbound connections, summarize remote ports and processes but avoid flagging by port alone. Focus on suspicious combinations: temp-path process, encoded shell, miner command line, or unsigned executable with persistent autostart.
5. Differentiate severity:
   - Info: known service on localhost.
   - Warning: admin service exposed to LAN/WAN.
   - Critical: exposed service owned by suspicious executable or known malware indicator.

**False-positive risks**

- Developer machines commonly run local web servers on 3000, 5000, 8000, 8080, 9000, and databases on localhost.
- RDP/SSH may be intentionally enabled on managed servers.
- Some endpoint protection and remote management tools listen on unusual local ports.

### 3. Linux SUID allowlist strategy is too coarse

**Current behavior**

- `lib/linux/malware.sh` defines a single string allowlist of known SUID paths.
- Any SUID path not in the list is ignored if it contains `/snap/` or `/usr/lib/`.
- Everything else is warned as `Unusual SUID binary`.

**Weaknesses**

- Blanket-excluding `/usr/lib/` can hide dangerous or malicious SUID binaries because many legitimate and attacker-placed SUID helpers live there.
- Blanket-excluding `/snap/` may miss malicious snap package contents or compromised package artifacts.
- The allowlist is Debian/Ubuntu-centric and will be noisy or incomplete on Fedora, RHEL, Arch, SUSE, NixOS, containers, and appliances.
- The check does not verify package ownership, file integrity, owner/group, permissions beyond SUID, symlink status, writable parent directory, or recent modification time.
- It does not distinguish default distro SUID files from newly added files.

**Recommended updates**

1. Replace the hardcoded path string with a structured allowlist keyed by distro/package family:
   - Debian/Ubuntu package-backed defaults.
   - RHEL/Fedora package-backed defaults.
   - Arch package-backed defaults.
   - Generic baseline for common core utilities.
2. Prefer package database validation:
   - Debian/Ubuntu: `dpkg -S "$path"` and optionally `debsums` if available.
   - RHEL/Fedora: `rpm -qf "$path"` and optionally `rpm -V`.
   - Arch: `pacman -Qo "$path"` and optionally `pacman -Qkk`.
3. Flag SUID files more strongly when:
   - Not owned by any package.
   - Located in user-writable paths (`/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/opt` with writable parent, `/usr/local` if locally modified).
   - Recently modified compared with package install time.
   - Owned by non-root or group/world-writable.
   - Interpreted scripts or files with unusual extensions.
4. Treat package-owned but uncommon SUID binaries as review items, not automatic malware.
5. Show an actionable record: path, owner, mode, package owner, mtime, parent directory writability, and reason.

**False-positive risks**

- Enterprise agents, backup tools, virtualization tools, and desktop packages may install legitimate SUID helpers.
- Snap, Flatpak, AppImage, and local software can create unusual paths that are benign.
- Minimal containers may lack package databases and should receive a lower-confidence result.

### 4. macOS LaunchAgent filtering is too shallow

**Current behavior**

- `lib/macos/malware.sh` checks `/Library/LaunchAgents`, `/Library/LaunchDaemons`, and `~/Library/LaunchAgents`.
- It lists filenames that are not `com.apple`, `com.microsoft`, or `com.google`.
- Known malware path list is small: `/Library/Application Support/macs`, `/private/var/root/.macs`, `com.pcv.hlpramc.plist`, `com.startup.plist`, and `/Users/Shared/.com.apple.autoUpdate`.

**Weaknesses**

- Filtering by filename vendor prefix is weak; malware often uses plausible `com.apple.*` or random bundle IDs, and legitimate software may not use Apple/Microsoft/Google prefixes.
- The check does not parse plist contents (`Program`, `ProgramArguments`, `RunAtLoad`, `KeepAlive`, `StartInterval`, `WatchPaths`, `StandardOutPath`, `StandardErrorPath`).
- It does not inspect the target executable path, code signature, quarantine attributes, ownership, permissions, notarization, or parent directory writability.
- It misses common user persistence locations and login items outside the three checked directories.
- It treats all third-party items as informational rather than scoring suspicious behavior.

**Recommended updates**

1. Parse each `.plist` with `plutil -p` or `/usr/libexec/PlistBuddy` and extract:
   - Label.
   - Program/ProgramArguments.
   - RunAtLoad, KeepAlive, StartInterval, StartCalendarInterval.
   - WatchPaths and QueueDirectories.
   - stdout/stderr paths.
2. Score suspicious traits:
   - Executable under `/tmp`, `/private/tmp`, `/var/tmp`, `/Users/Shared`, hidden directories, browser cache, Downloads, or writable app-support paths.
   - Shell execution (`sh`, `bash`, `zsh`, `osascript`, `python`, `perl`, `ruby`, `curl`, `wget`) with remote URL, base64, or encoded command.
   - Label mismatch with executable bundle/signing team.
   - Root LaunchDaemon writable by non-root or pointing into user home.
   - Hidden executable or hidden app bundle.
3. Expand persistence coverage:
   - `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `/System/Library/Launch*` as read-only baseline context.
   - All real users' `~/Library/LaunchAgents`, not just root's `~` under sudo.
   - Login Items / background items where available.
   - `/Library/PrivilegedHelperTools`, `/Library/StartupItems`, `/Library/Extensions`, `/Library/SystemExtensions`, `/Library/LaunchDaemons` helper links.
4. Add trust context:
   - `codesign -dv --verbose=4 <target>`.
   - `spctl --assess --type execute <target>`.
   - owner/mode checks for plist and target.
5. Expand known macOS malware/PUP/adware indicators as a maintained data file rather than embedded literals. Include families such as Shlayer, AdLoad, Pirrit, Genieo, InstallCore, Search Marquis/browser hijackers, and commodity stealers only when tied to concrete filenames/paths/labels.

**False-positive risks**

- Nearly every real Mac has third-party LaunchAgents from browsers, sync tools, VPNs, MDM, printers, cloud storage, and updaters.
- Security products often use LaunchDaemons and privileged helpers.
- Developer tooling may intentionally run scripts from user directories.

### 5. Windows PUP and miner patterns are outdated and under-contextualized

**Current behavior**

- `lib/windows/Common.ps1` defines miner names and PUP/adware strings.
- `lib/windows/Processes.ps1` checks process names against miner patterns and temp paths.
- `lib/windows/Malware.ps1` checks running processes, services, and startup commands for PUP patterns or temp paths.
- `lib/windows/ScheduledTasks.ps1` checks non-Microsoft ready tasks that run `powershell|cmd|wscript|cscript|mshta` with `http|temp|appdata\local\temp` arguments.
- `lib/windows/Defender.ps1` checks Defender status and existing threats.

**Weaknesses**

- PUP list is very small and old: `web companion`, `lavasoft`, `conduit`, `ask toolbar`, `babylon`, `delta-homes`, `sweetim`.
- Miner detection focuses on process name and misses renamed miners, command-line pool indicators, and GPU miners.
- Startup and scheduled task checks do not cover registry Run keys directly, services with executable paths, WMI persistence, PowerShell profiles, browser extensions, startup folders, or common LOLBin abuse beyond a few script hosts.
- Scheduled task filtering excludes Microsoft-authored tasks by metadata, which can be spoofed.
- `3389` is treated as suspicious in the same list as classic backdoor ports, but RDP is a configuration exposure rather than malware by itself.

**Recommended updates**

1. Expand PUP/adware indicators into a maintained data set with explicit categories:
   - Browser hijackers/toolbars/search redirectors.
   - Fake AV/optimizer/driver updater families.
   - Bundlers/installers and ad injectors.
   - Miner installers and proxy miners.
2. Add modern Windows miner indicators:
   - Names: `xmrig`, `xmrig-cuda`, `nanominer`, `nbminer`, `lolminer`, `t-rex`, `phoenixminer`, `teamredminer`, `gminer`, `cpuminer`, `minerd`, `nicehash`, `unmineable`, `ethminer`.
   - Behaviors: stratum URLs, mining pool domains, wallet-like arguments, high CPU/GPU, persistence through tasks/services/Run keys, Defender exclusions.
3. Collect process command line via `Get-CimInstance Win32_Process` and join with `Get-Process` for CPU.
4. Add persistence checks:
   - Registry Run/RunOnce keys under HKLM/HKCU and Wow6432Node.
   - Startup folders.
   - Services with suspicious binary paths.
   - WMI event consumers.
   - PowerShell profile scripts.
   - Defender exclusions (`Get-MpPreference`).
   - Scheduled task author spoofing and hidden tasks.
5. Add signer and path context:
   - Authenticode signature status.
   - Executable path under `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, public user directories, recycle bin, or hidden folders.
   - Recently created executable with autostart.
6. Distinguish PUP from malware and configuration risk in output. PUP should generally warn, while known active threats from Defender or strong miner evidence can fail.

**False-positive risks**

- Some users intentionally install remote administration tools, game launchers, mining software, overclocking tools, or bundled utilities.
- Enterprise software may create scheduled tasks, services, Defender exclusions, or unsigned internal tools.
- Localized Windows group names and enterprise-managed Defender settings can make status checks misleading.

### 6. Update checks and hardening assumptions are too platform-specific or too broad

**Current behavior**

- Linux uses `apt update -qq` and `apt list --upgradable`, and hardening uses `apt`, `ufw`, `rkhunter`, `chkrootkit`, and `unattended-upgrades` in `lib/linux/vulnerabilities.sh` and `lib/linux/hardening.sh`.
- macOS uses `softwareupdate -l`, XProtect/MRT version display, Homebrew outdated count, and optional `softwareupdate -ia` in `lib/macos/vulnerabilities.sh` and `lib/macos/hardening.sh`.
- Windows uses Microsoft Update COM APIs, UAC/RDP/SMBv1 checks, Defender scan age, and opens Windows Update UI in `lib/windows/Vulnerabilities.ps1`, `lib/windows/Defender.ps1`, and `lib/windows/Hardening.ps1`.

**Weaknesses**

- Linux README says most distros are supported, but detection and hardening are Debian/Ubuntu-specific for updates/firewall. Fedora/RHEL systems without UFW will be warned even if `firewalld` or `nftables` is active.
- `apt list --upgradable` counts all updates, not security-only updates, but user-facing text says `Pending security updates`.
- Running `apt update` during a scan changes system state and can be slow or fail on transient network issues.
- UFW inactive does not mean no firewall. Systems may use nftables, iptables, firewalld, cloud firewalls, or host-based EDR controls.
- macOS `softwareupdate -l` parsing by `recommended|restart` may miss or overcount updates depending on output format and macOS version.
- XProtect/MRT version display does not determine whether automatic security response updates are enabled or stale.
- macOS Application Firewall protects inbound app sockets but does not equal a full network firewall; stealth mode is optional and can be policy-dependent.
- Windows Update COM search may include optional updates and can fail under WSUS/Intune policy; opening Settings is not an automated patch action.
- Windows Firewall `all profiles enabled` can be too blunt; effective profile, inbound defaults, allowed rules, and third-party firewall/EDR matter.

**Recommended updates**

1. Detect Linux package/firewall ecosystem first:
   - Package managers: `apt`, `dnf`, `yum`, `zypper`, `pacman`.
   - Firewalls: `ufw`, `firewalld`, `nft`, `iptables`.
2. Separate update categories:
   - Security updates.
   - General updates.
   - Could not check.
   - Unsupported package manager.
3. Avoid mutating scan behavior unless explicitly in hardening mode. Consider using cached package metadata or clearly label when an online refresh is performed.
4. For Linux hardening, do not recommend UFW installation when another active firewall is detected without explaining the tradeoff.
5. For macOS, check:
   - `softwareupdate --list` outcome with robust parsing.
   - automatic update settings where available.
   - Rapid Security Response and XProtect update status where exposed by the OS.
6. For Windows, check:
   - Effective firewall profile and default inbound action.
   - Defender signature age and cloud-delivered protection if Defender is active.
   - Whether updates are managed by WSUS/Intune before calling inability to check a weakness.
7. Documentation updates should replace absolute claims like `security updates (always safe)` with safer wording: updates are recommended, but production systems may require maintenance windows and backups.

**False-positive risks**

- Servers may intentionally defer patches for change-control windows.
- Host firewalls may be disabled because security is enforced by a cloud security group, endpoint product, or appliance firewall.
- Corporate Macs and Windows systems may have settings controlled by MDM/GPO and should not be treated as user-remediable failures.

### 7. Severity and summary output mix security posture, suspicious behavior, and confirmed indicators

**Current behavior**

- `fail`/`Write-Fail` increments critical issues; `warn`/`Write-Warn` increments warnings.
- Summaries in `lib/linux/report.sh`, `lib/macos/report.sh`, and `lib/windows/Report.ps1` label systems as clean when there are no criticals, even if many warnings exist.
- README and CLAUDE guidance tell users most warnings are informational.

**Weaknesses**

- The same warning bucket contains benign hygiene findings, potentially serious persistence, and ambiguous detections.
- `SYSTEM APPEARS CLEAN` can be misleading because scans are best-effort and signature-light.
- Some current `fail` conditions, such as Windows suspicious ports, may be configuration risks rather than confirmed compromise.
- Some current `info` conditions, such as exposed non-SSH listeners, can be important depending on service and bind address.

**Recommended updates**

1. Introduce explicit result classes:
   - `Critical indicator`: strong compromise evidence.
   - `Suspicious`: needs review.
   - `Exposure`: network/config risk.
   - `Hygiene`: patch/firewall/encryption recommendations.
   - `Informational`: inventory only.
2. Include a confidence field or phrase in each finding: high, medium, low.
3. Change summary language from `SYSTEM APPEARS CLEAN` to `No high-confidence indicators found`.
4. Add per-finding remediation guidance and false-positive notes.
5. Keep beginner-friendly output, but log richer context for follow-up.

## Module-specific backlog

### Linux

1. `lib/linux/processes.sh` — replace grep miner check with a function that evaluates process name, command line, executable path, CPU, and miner/pool signatures.
2. `lib/linux/network.sh` — resolve listener PID/process reliably, classify exposed services by risk, and remove port-only assumptions.
3. `lib/linux/malware.sh` — replace SUID path string with package-backed validation and remove broad `/usr/lib/` and `/snap/` exclusions.
4. `lib/linux/malware.sh` — enhance cron checks for encoded commands, pastebin/raw GitHub downloads, `/dev/tcp`, base64, `nohup`, `setsid`, temp-path execution, and chained download/execute patterns.
5. `lib/linux/vulnerabilities.sh` — detect package manager/firewall ecosystem and separate security updates from general updates.
6. `lib/linux/hardening.sh` — gate UFW/apt actions on distro/firewall detection and warn about production maintenance windows.

### macOS

1. `lib/macos/processes.sh` — add command-line and pool-pattern miner matching; use context instead of process-name grep only.
2. `lib/macos/network.sh` — resolve listener PID/process and classify risk by exposure plus owning executable.
3. `lib/macos/malware.sh` — parse LaunchAgent/Daemon plists and target executables rather than filtering filenames by vendor prefix.
4. `lib/macos/malware.sh` — iterate all real user home directories instead of `~/Library/LaunchAgents` under sudo only.
5. `lib/macos/security.sh` — clarify Application Firewall and stealth mode as exposure controls, not complete firewall coverage.
6. `lib/macos/vulnerabilities.sh` — improve `softwareupdate` parsing and add checks for automatic security data updates where supported.
7. `lib/macos/hardening.sh` — treat FileVault and remote-access changes as policy-sensitive and require clear per-action confirmation.

### Windows

1. `lib/windows/Common.ps1` — move miner/PUP/suspicious-port patterns into structured signature tables with severity, category, and rationale.
2. `lib/windows/Processes.ps1` — collect `Win32_Process.CommandLine` and `ExecutablePath`; correlate with CPU from `Get-Process`.
3. `lib/windows/Network.ps1` — map listeners to process/service/signature/path and classify RDP/WinRM/SMB as exposure, not malware.
4. `lib/windows/Malware.ps1` — expand PUP and miner indicators; add signer/path context.
5. `lib/windows/ScheduledTasks.ps1` — detect suspicious task actions independent of spoofable author, and include hidden/disabled-but-triggered task review.
6. `lib/windows/Vulnerabilities.ps1` — account for WSUS/Intune-managed updates and third-party AV/firewall providers.
7. `lib/windows/Defender.ps1` — add Defender exclusions, cloud protection, tamper protection, and signature age thresholds if available.
8. `lib/windows/Hardening.ps1` — avoid implying Windows Update was applied when only Settings was opened.

## Recommended implementation order

1. **Create shared signature data and result taxonomy** for each platform without changing detections yet.
2. **Refresh process/miner detection** using command-line, path, and network context.
3. **Replace port-only network findings** with exposure/process-context findings.
4. **Rework Linux SUID validation** with package ownership and path risk scoring.
5. **Rework macOS LaunchAgent/Daemon analysis** with plist parsing and code-signature/path checks.
6. **Expand Windows PUP/miner/persistence checks** with command-line, registry, service, task, and Defender context.
7. **Update documentation and summary wording** to explain confidence, false positives, and configuration-vs-compromise distinctions.

## Acceptance criteria for the refresh

- Every finding includes: platform, module, severity class, confidence, matched evidence, and a short explanation.
- Generic strings like `miner`, `xmr`, `8080`, and third-party LaunchAgent names do not create high-severity findings by themselves.
- Linux SUID output includes package ownership or an explicit reason it could not be determined.
- macOS LaunchAgent findings include plist label, executable path, and the suspicious plist keys or path traits.
- Windows miner/PUP findings include process command line or persistence source when available.
- Update/firewall checks clearly distinguish unsupported, unmanaged, managed-by-policy, inactive, and active states.
- README/CLAUDE guidance avoids claiming that warnings are always benign or that hardening actions are always safe.
