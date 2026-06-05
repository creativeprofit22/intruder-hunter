package linux

import (
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
