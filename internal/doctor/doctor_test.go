package doctor

import (
	"context"
	"testing"

	"github.com/creativeprofit22/intruder-hunter/internal/output"
)

type fakeProbe struct {
	platform string
	admin    AdminStatus
	goEnv    GoEnvironment
	tools    map[string]ToolStatus
	files    map[string]ToolStatus
	cmdlets  map[string]ToolStatus
}

func (p fakeProbe) Platform() string {
	return p.platform
}

func (p fakeProbe) AdminStatus(context.Context) AdminStatus {
	return p.admin
}

func (p fakeProbe) GoEnvironment() GoEnvironment {
	return p.goEnv
}

func (p fakeProbe) LookPath(name string) ToolStatus {
	if status, ok := p.tools[name]; ok {
		if status.Name == "" {
			status.Name = name
		}
		return status
	}
	return ToolStatus{Name: name, Available: false, Detail: "not found"}
}

func (p fakeProbe) FileExists(path string) ToolStatus {
	if status, ok := p.files[path]; ok {
		if status.Name == "" {
			status.Name = path
		}
		return status
	}
	return ToolStatus{Name: path, Available: false, Detail: "not found"}
}

func (p fakeProbe) PowerShellCmdlet(_ context.Context, _ string, cmdlet string) ToolStatus {
	if status, ok := p.cmdlets[cmdlet]; ok {
		if status.Name == "" {
			status.Name = cmdlet
		}
		return status
	}
	return ToolStatus{Name: cmdlet, Available: false, Detail: "not found"}
}

func TestRunWithProbeLinuxAggregatesRequiredAndOptionalTools(t *testing.T) {
	probe := fakeProbe{
		platform: "linux",
		admin:    AdminStatus{Available: false, Evidence: "euid=1000"},
		goEnv:    GoEnvironment{RuntimeVersion: "go1.26.0", GOOS: "linux", GOARCH: "amd64", Executable: "/tmp/intruder-hunter"},
		tools: map[string]ToolStatus{
			"go":      availableTool("go", "/usr/bin/go"),
			"bash":    availableTool("bash", "/usr/bin/bash"),
			"ps":      availableTool("ps", "/usr/bin/ps"),
			"awk":     availableTool("awk", "/usr/bin/awk"),
			"grep":    availableTool("grep", "/usr/bin/grep"),
			"ss":      availableTool("ss", "/usr/bin/ss"),
			"apt":     availableTool("apt", "/usr/bin/apt"),
			"nft":     availableTool("nft", "/usr/sbin/nft"),
			"netstat": missingTool("netstat"),
		},
	}

	report, err := RunWithProbe(context.Background(), probe)
	if err != nil {
		t.Fatalf("RunWithProbe returned error: %v", err)
	}

	if report.Platform != "linux" {
		t.Fatalf("platform = %q, want linux", report.Platform)
	}
	if report.Summary.WarningCount != 1 {
		t.Fatalf("warnings = %d, want 1 for missing admin/root", report.Summary.WarningCount)
	}
	if report.Summary.OKCount != 5 {
		t.Fatalf("ok count = %d, want 5", report.Summary.OKCount)
	}
	if report.Summary.InfoCount != 2 {
		t.Fatalf("info count = %d, want 2", report.Summary.InfoCount)
	}

	assertFinding(t, report, "linux.doctor.admin_capability", severityWarning, "missing")
	assertFinding(t, report, "linux.doctor.linux_network_tools", severityOK, "available")
	assertFinding(t, report, "linux.doctor.linux_package_manager", severityInfo, "available")
	assertFinding(t, report, "linux.doctor.linux_firewall_tools", severityInfo, "available")
}

func TestRunWithProbeLinuxWarnsWhenRequiredToolGroupMissing(t *testing.T) {
	probe := fakeProbe{
		platform: "linux",
		admin:    AdminStatus{Available: true, Evidence: "euid=0"},
		goEnv:    GoEnvironment{RuntimeVersion: "go1.26.0", GOOS: "linux", GOARCH: "amd64"},
		tools: map[string]ToolStatus{
			"go":   availableTool("go", "/usr/bin/go"),
			"bash": availableTool("bash", "/usr/bin/bash"),
			"ps":   availableTool("ps", "/usr/bin/ps"),
			"awk":  availableTool("awk", "/usr/bin/awk"),
			"grep": availableTool("grep", "/usr/bin/grep"),
		},
	}

	report, err := RunWithProbe(context.Background(), probe)
	if err != nil {
		t.Fatalf("RunWithProbe returned error: %v", err)
	}

	assertFinding(t, report, "linux.doctor.linux_network_tools", severityWarning, "missing")
	finding := findFinding(t, report, "linux.doctor.linux_network_tools")
	if finding.Metadata["missing"] != "netstat,ss" {
		t.Fatalf("missing metadata = %q, want netstat,ss", finding.Metadata["missing"])
	}
}

func TestRunWithProbeNormalizesMacOSPlatform(t *testing.T) {
	probe := fakeProbe{
		platform: "darwin",
		admin:    AdminStatus{Available: true, Evidence: "euid=0"},
		goEnv:    GoEnvironment{RuntimeVersion: "go1.26.0", GOOS: "darwin", GOARCH: "arm64"},
		tools: map[string]ToolStatus{
			"go":        availableTool("go", "/usr/local/go/bin/go"),
			"ps":        availableTool("ps", "/bin/ps"),
			"lsof":      availableTool("lsof", "/usr/sbin/lsof"),
			"launchctl": availableTool("launchctl", "/bin/launchctl"),
			"plutil":    availableTool("plutil", "/usr/bin/plutil"),
			"codesign":  availableTool("codesign", "/usr/bin/codesign"),
			"spctl":     availableTool("spctl", "/usr/sbin/spctl"),
			"fdesetup":  availableTool("fdesetup", "/usr/bin/fdesetup"),
		},
		files: map[string]ToolStatus{
			"/usr/libexec/ApplicationFirewall/socketfilterfw": availableTool("/usr/libexec/ApplicationFirewall/socketfilterfw", "/usr/libexec/ApplicationFirewall/socketfilterfw"),
		},
	}

	report, err := RunWithProbe(context.Background(), probe)
	if err != nil {
		t.Fatalf("RunWithProbe returned error: %v", err)
	}

	if report.Platform != "macos" {
		t.Fatalf("platform = %q, want macos", report.Platform)
	}
	if report.Summary.WarningCount != 0 {
		t.Fatalf("warnings = %d, want 0", report.Summary.WarningCount)
	}
	assertFinding(t, report, "macos.doctor.macos_trust_tools", severityOK, "available")
}

func TestRunWithProbeWindowsChecksPowerShellDefenderAndSystemTools(t *testing.T) {
	probe := fakeProbe{
		platform: "windows",
		admin:    AdminStatus{Unknown: true, Evidence: "probe unavailable"},
		goEnv:    GoEnvironment{RuntimeVersion: "go1.26.0", GOOS: "windows", GOARCH: "amd64"},
		tools: map[string]ToolStatus{
			"go":             availableTool("go", `C:\Go\bin\go.exe`),
			"powershell.exe": availableTool("powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
			"netsh":          availableTool("netsh", `C:\Windows\System32\netsh.exe`),
			"schtasks":       availableTool("schtasks", `C:\Windows\System32\schtasks.exe`),
		},
		cmdlets: map[string]ToolStatus{
			"Get-MpComputerStatus":  availableTool("Get-MpComputerStatus", ""),
			"Get-MpThreatDetection": missingTool("Get-MpThreatDetection"),
		},
	}

	report, err := RunWithProbe(context.Background(), probe)
	if err != nil {
		t.Fatalf("RunWithProbe returned error: %v", err)
	}

	assertFinding(t, report, "windows.doctor.admin_capability", severityWarning, "unknown")
	assertFinding(t, report, "windows.doctor.windows_powershell", severityOK, "available")
	assertFinding(t, report, "windows.doctor.windows_system_tools", severityOK, "available")
	assertFinding(t, report, "windows.doctor.windows_defender_cmdlets", severityWarning, "missing")
}

func TestRunWithProbeRejectsNilInputs(t *testing.T) {
	probe := fakeProbe{platform: "linux"}
	if _, err := RunWithProbe(nil, probe); err == nil {
		t.Fatal("RunWithProbe with nil context returned nil error")
	}
	if _, err := RunWithProbe(context.Background(), nil); err == nil {
		t.Fatal("RunWithProbe with nil probe returned nil error")
	}
}

func availableTool(name, path string) ToolStatus {
	return ToolStatus{Name: name, Available: true, Path: path}
}

func missingTool(name string) ToolStatus {
	return ToolStatus{Name: name, Available: false, Detail: "not found"}
}

func assertFinding(t *testing.T, report Report, id string, severity string, status string) {
	t.Helper()
	finding := findFinding(t, report, id)
	if finding.Severity != severity {
		t.Fatalf("%s severity = %q, want %q", id, finding.Severity, severity)
	}
	if finding.Metadata["status"] != status {
		t.Fatalf("%s status = %q, want %q", id, finding.Metadata["status"], status)
	}
}

func findFinding(t *testing.T, report Report, id string) output.Finding {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.ID == id {
			return finding
		}
	}
	t.Fatalf("finding %s not found in %#v", id, report.Findings)
	return output.Finding{}
}
