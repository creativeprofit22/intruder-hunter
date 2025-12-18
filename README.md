# Intruder Hunter

**Cross-Platform Security Diagnostic & Hardening Tool**

Beginner-friendly scripts that scan your **Linux** and **Windows** systems for intruders, malware, and vulnerabilities - then offer to fix what they find.

```
  ___       _                  _             _   _             _
 |_ _|_ __ | |_ _ __ _   _  __| | ___ _ __  | | | |_   _ _ __ | |_ ___ _ __
  | ||  _ \| __|  __| | | |/ _` |/ _ \  __| | |_| | | | |  _ \| __/ _ \  __|
  | || | | | |_| |  | |_| | (_| |  __/ |    |  _  | |_| | | | | ||  __/ |
 |___|_| |_|\__|_|   \__,_|\__,_|\___|_|    |_| |_|\__,_|_| |_|\__\___|_|
```

## Features

- **Process Analysis** - Detects crypto miners, suspicious processes running from /tmp
- **Network Analysis** - Shows listening ports and active connections
- **User Audit** - Checks for rogue accounts, empty passwords, SSH keys, sudo access
- **Malware Detection** - Scans for rootkit indicators, suspicious cron jobs, unusual SUID binaries
- **Vulnerability Assessment** - Checks pending updates, firewall status, file permissions
- **Log Analysis** - Reviews authentication logs for brute force attempts

After scanning, it offers to automatically:
- Apply security updates
- Enable UFW firewall
- Run rootkit scanners (rkhunter + chkrootkit)
- Configure automatic updates

## Quick Start

### Linux / WSL2

**One-liner Install & Run:**

```bash
curl -fsSL https://raw.githubusercontent.com/creativeprofit22/intruder-hunter/master/intruder-hunter.sh -o intruder-hunter.sh && sudo bash intruder-hunter.sh
```

**Manual Install:**

```bash
git clone https://github.com/creativeprofit22/intruder-hunter.git
cd intruder-hunter
sudo ./intruder-hunter.sh
```

### Windows

**One-liner (Run as Administrator in PowerShell):**

```powershell
irm https://raw.githubusercontent.com/creativeprofit22/intruder-hunter/master/intruder-hunter.ps1 -OutFile intruder-hunter.ps1; .\intruder-hunter.ps1
```

**Manual Install:**

```powershell
# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/creativeprofit22/intruder-hunter/master/intruder-hunter.ps1" -OutFile "intruder-hunter.ps1"

# Run as Administrator
.\intruder-hunter.ps1
```

> **Note:** Right-click PowerShell and select "Run as Administrator" before running.

## Requirements

### Linux
- Ubuntu/Debian (or most distros)
- Root access (sudo)
- Bash 4.0+

### Windows
- Windows 10/11
- PowerShell 5.1+ (built-in)
- Administrator privileges

**Works great on:**
- Ubuntu 20.04 / 22.04 / 24.04
- Debian 10 / 11 / 12
- WSL2 (Windows Subsystem for Linux)
- Windows 10 / 11
- Windows Server 2016+

## What It Checks

### Linux

| Category | Checks Performed |
|----------|------------------|
| **Processes** | Crypto miners, processes in /tmp, high CPU usage |
| **Network** | Listening ports, exposed services, active connections |
| **Users** | UID 0 accounts, empty passwords, sudo group, NOPASSWD entries |
| **SSH** | Authorized keys, root login, password authentication |
| **Malware** | LD_PRELOAD hooks, suspicious cron jobs, unusual SUID binaries |
| **Files** | World-writable /etc files, hidden files in /tmp |
| **Updates** | Pending security patches |
| **Firewall** | UFW status |
| **Logs** | Failed login attempts, recent logins |

### Windows

| Category | Checks Performed |
|----------|------------------|
| **Processes** | Crypto miners, processes in Temp folders, high CPU usage |
| **Network** | Listening ports, backdoor port detection, active connections |
| **Users** | Hidden accounts, administrator group members, disabled accounts |
| **Defender** | AV status, real-time protection, threat detections, scan age |
| **Malware** | PUPs (adware), suspicious services, suspicious startup entries |
| **Tasks** | Scheduled tasks running scripts from unusual locations |
| **Vulnerabilities** | UAC status, Remote Desktop, SMBv1, pending updates |
| **Firewall** | Windows Firewall status (all profiles) |

## Sample Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SCAN COMPLETE - SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ╔══════════════════════════════════════════════╗
  ║          SYSTEM APPEARS CLEAN                ║
  ╚══════════════════════════════════════════════╝

  Results:
    ✗ Critical issues: 0
    ! Warnings:        3
```

## Hardening Steps

When the scan completes, you'll be asked:

```
Apply all recommended hardening steps? (y/n):
```

If you choose **yes**, the script will:

1. **Apply Updates** - `apt update && apt upgrade`
2. **Enable Firewall** - UFW with deny incoming / allow outgoing
3. **Run Rootkit Scanners** - rkhunter and chkrootkit
4. **Configure Auto-Updates** - unattended-upgrades for security patches

If you choose **no**, it shows the manual commands you can run later.

## Log File

All scan results are saved to:

```
/var/log/intruder-hunter.log
```

## FAQ

**Q: Is this safe to run on production servers?**
A: The scan itself is read-only and safe. Only apply hardening steps if you understand the changes (firewall rules may affect services).

**Q: Does it work on CentOS/RHEL/Fedora?**
A: Partially. The scan works, but hardening uses apt/ufw which are Debian-specific. PRs welcome for yum/dnf support!

**Q: Why does it need root?**
A: To read /etc/shadow, check all user crontabs, scan system directories, and apply fixes.

**Q: I got warnings but no critical issues - am I safe?**
A: Warnings are informational (e.g., "SSH allows root login" when SSH isn't even running). Review them but don't panic.

## Contributing

PRs welcome! Ideas for improvement:

- [x] Windows support (PowerShell)
- [ ] Support for RHEL/CentOS (yum/dnf, firewalld)
- [ ] macOS support
- [ ] JSON output format
- [ ] Email report option
- [ ] Scheduled scans via cron/Task Scheduler
- [ ] More rootkit/malware signatures

## Using with Claude Code (AI-Guided Mode)

Want an AI security expert to guide you through the process? Use [Claude Code](https://claude.ai/code):

### Setup

```bash
# Clone the repo
git clone https://github.com/creativeprofit22/intruder-hunter.git
cd intruder-hunter

# Open with Claude Code
claude
```

### Slash Commands

Once inside Claude Code, you can use these commands:

| Command | Description |
|---------|-------------|
| `/diagnose` | Full guided security diagnosis with explanations |
| `/harden` | Step-by-step system hardening with Claude's help |
| `/quick-scan` | Fast security check without the full script |

### Or Just Ask

You can also just ask Claude directly:

- *"Is my system compromised?"*
- *"Help me check for intruders"*
- *"What do these scan results mean?"*
- *"Should I be worried about this warning?"*

Claude has full context about this toolkit and will guide you through everything.

## License

MIT License - Use freely, no warranty.

## Credits

Built with help from [Claude Code](https://claude.ai/code) - Anthropic's AI coding assistant.

---

**Stay safe out there.**
