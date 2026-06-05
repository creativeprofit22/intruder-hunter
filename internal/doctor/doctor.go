package doctor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/output"
)

const (
	moduleName = "doctor"

	severityCritical = "critical"
	severityWarning  = "warning"
	severityOK       = "ok"
	severityInfo     = "info"
)

// AdminStatus describes whether privileged diagnostics can run in the current process.
type AdminStatus struct {
	Available bool
	Unknown   bool
	Evidence  string
	Detail    string
}

// GoEnvironment describes the Go CLI/runtime context visible to doctor.
type GoEnvironment struct {
	RuntimeVersion string
	GOOS           string
	GOARCH         string
	Executable     string
}

// ToolStatus describes a local command or file prerequisite probe.
type ToolStatus struct {
	Name      string
	Available bool
	Path      string
	Detail    string
}

// Probe supplies local, non-destructive observations to the doctor aggregator.
type Probe interface {
	Platform() string
	AdminStatus(ctx context.Context) AdminStatus
	GoEnvironment() GoEnvironment
	LookPath(name string) ToolStatus
	FileExists(path string) ToolStatus
	PowerShellCmdlet(ctx context.Context, shell string, cmdlet string) ToolStatus
}

// Report is the doctor result before it is wrapped in the shared output envelope.
type Report struct {
	Platform string
	Summary  output.Summary
	Findings []output.Finding
}

// Envelope converts the doctor report into the shared CLI output envelope.
func (r Report) Envelope(startedAt, completedAt time.Time) output.Envelope {
	return output.NewEnvelope(r.Platform, startedAt, completedAt, r.Summary, r.Findings, nil)
}

// Run probes this host with the default operating-system probe.
func Run(ctx context.Context) (Report, error) {
	return RunWithProbe(ctx, OSProbe{})
}

// RunWithProbe aggregates doctor findings from probe. It is side-effect free apart
// from the probe calls and never attempts hardening or remediation.
func RunWithProbe(ctx context.Context, probe Probe) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("doctor: nil context")
	}
	if probe == nil {
		return Report{}, errors.New("doctor: nil probe")
	}

	platform := normalizePlatform(probe.Platform())
	findings := []output.Finding{
		platformFinding(platform),
		adminFinding(platform, probe.AdminStatus(ctx)),
		goEnvironmentFinding(platform, probe.GoEnvironment(), probe.LookPath("go")),
	}

	switch platform {
	case "linux":
		findings = append(findings, linuxFindings(ctx, probe, platform)...)
	case "macos":
		findings = append(findings, macOSFindings(ctx, probe, platform)...)
	case "windows":
		findings = append(findings, windowsFindings(ctx, probe, platform)...)
	default:
		findings = append(findings, newFinding(platform, "platform_support", severityWarning,
			"Platform support is unknown",
			fmt.Sprintf("Doctor does not have a prerequisite profile for %q.", platform),
			"Use Linux, macOS, or Windows for supported Intruder Hunter diagnostics.", nil,
			map[string]string{"status": "unsupported"}))
	}

	sortFindings(findings)
	return Report{
		Platform: platform,
		Summary:  countSummary(findings),
		Findings: findings,
	}, nil
}

// OSProbe implements Probe with local operating-system observations.
type OSProbe struct{}

func (OSProbe) Platform() string {
	return runtime.GOOS
}

func (OSProbe) AdminStatus(ctx context.Context) AdminStatus {
	switch normalizePlatform(runtime.GOOS) {
	case "linux", "macos":
		if os.Geteuid() == 0 {
			return AdminStatus{Available: true, Evidence: "effective user id is 0"}
		}
		return AdminStatus{Available: false, Evidence: fmt.Sprintf("effective user id is %d", os.Geteuid())}
	case "windows":
		return windowsAdminStatus(ctx)
	default:
		return AdminStatus{Unknown: true, Evidence: "no admin probe is available for this platform"}
	}
}

func (OSProbe) GoEnvironment() GoEnvironment {
	executable, err := os.Executable()
	if err != nil {
		executable = "unknown"
	}

	return GoEnvironment{
		RuntimeVersion: runtime.Version(),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		Executable:     executable,
	}
}

func (OSProbe) LookPath(name string) ToolStatus {
	path, err := exec.LookPath(name)
	if err != nil {
		return ToolStatus{Name: name, Available: false, Detail: err.Error()}
	}
	return ToolStatus{Name: name, Available: true, Path: path}
}

func (OSProbe) FileExists(path string) ToolStatus {
	info, err := os.Stat(path)
	if err != nil {
		return ToolStatus{Name: path, Available: false, Detail: err.Error()}
	}
	if info.IsDir() {
		return ToolStatus{Name: path, Available: false, Detail: "path is a directory"}
	}
	return ToolStatus{Name: path, Available: true, Path: path}
}

func (OSProbe) PowerShellCmdlet(ctx context.Context, shell string, cmdlet string) ToolStatus {
	if strings.TrimSpace(shell) == "" || strings.TrimSpace(cmdlet) == "" {
		return ToolStatus{Name: cmdlet, Available: false, Detail: "empty shell or cmdlet"}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	command := fmt.Sprintf("if (Get-Command %s -ErrorAction SilentlyContinue) { Write-Output present; exit 0 } else { exit 1 }", shellQuotePowerShellName(cmdlet))
	result := exec.CommandContext(probeCtx, shell, "-NoProfile", "-NonInteractive", "-Command", command)
	stdout, err := result.Output()
	if err != nil {
		detail := err.Error()
		if probeCtx.Err() != nil {
			detail = probeCtx.Err().Error()
		}
		return ToolStatus{Name: cmdlet, Available: false, Detail: detail}
	}
	if strings.Contains(strings.ToLower(string(stdout)), "present") {
		return ToolStatus{Name: cmdlet, Available: true, Detail: fmt.Sprintf("available through %s", shell)}
	}
	return ToolStatus{Name: cmdlet, Available: false, Detail: fmt.Sprintf("not found through %s", shell)}
}

func windowsAdminStatus(ctx context.Context) AdminStatus {
	for _, shell := range []string{"powershell.exe", "powershell", "pwsh.exe", "pwsh"} {
		path, err := exec.LookPath(shell)
		if err != nil {
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		command := "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
		stdout, err := exec.CommandContext(probeCtx, path, "-NoProfile", "-NonInteractive", "-Command", command).Output()
		cancel()
		if err != nil {
			continue
		}

		value := strings.TrimSpace(strings.ToLower(string(stdout)))
		if value == "true" {
			return AdminStatus{Available: true, Evidence: fmt.Sprintf("%s reports Administrator role", shell)}
		}
		if value == "false" {
			return AdminStatus{Available: false, Evidence: fmt.Sprintf("%s reports non-Administrator role", shell)}
		}
	}

	return AdminStatus{Unknown: true, Evidence: "PowerShell admin role probe was unavailable"}
}

func platformFinding(platform string) output.Finding {
	return newFinding(platform, "platform", severityOK,
		"Platform detected",
		fmt.Sprintf("Doctor detected platform %q.", platform),
		"", []string{fmt.Sprintf("platform=%s", platform)},
		map[string]string{"status": "detected"})
}

func adminFinding(platform string, status AdminStatus) output.Finding {
	if status.Unknown {
		return newFinding(platform, "admin_capability", severityWarning,
			"Admin/root capability could not be confirmed",
			"Doctor could not determine whether privileged diagnostics can run.",
			"Run from an elevated shell or with sudo when performing full diagnostics.", evidenceFrom(status.Evidence, status.Detail),
			map[string]string{"status": "unknown"})
	}
	if status.Available {
		return newFinding(platform, "admin_capability", severityOK,
			"Admin/root capability is available",
			"Privileged diagnostics should be able to collect full local evidence.",
			"", evidenceFrom(status.Evidence, status.Detail),
			map[string]string{"status": "available"})
	}

	return newFinding(platform, "admin_capability", severityWarning,
		"Admin/root capability is not available",
		"Some diagnostics may be incomplete without elevated privileges.",
		"Re-run with sudo, as root, or from an Administrator PowerShell when performing full diagnostics.", evidenceFrom(status.Evidence, status.Detail),
		map[string]string{"status": "missing"})
}

func goEnvironmentFinding(platform string, env GoEnvironment, goTool ToolStatus) output.Finding {
	evidence := evidenceFrom(
		fmt.Sprintf("runtime=%s", emptyAsUnknown(env.RuntimeVersion)),
		fmt.Sprintf("goos=%s", emptyAsUnknown(env.GOOS)),
		fmt.Sprintf("goarch=%s", emptyAsUnknown(env.GOARCH)),
		fmt.Sprintf("executable=%s", emptyAsUnknown(env.Executable)),
	)
	metadata := map[string]string{
		"go_runtime": emptyAsUnknown(env.RuntimeVersion),
		"goos":       emptyAsUnknown(env.GOOS),
		"goarch":     emptyAsUnknown(env.GOARCH),
	}
	if goTool.Available {
		evidence = append(evidence, fmt.Sprintf("go=%s", goTool.Path))
		metadata["go_tool"] = "available"
		return newFinding(platform, "go_environment", severityOK,
			"Go CLI environment is available",
			"The Intruder Hunter Go command is running and the go tool is available for source builds/tests.",
			"", evidence, metadata)
	}

	metadata["go_tool"] = "missing"
	return newFinding(platform, "go_environment", severityInfo,
		"Go CLI runtime is available; go tool was not found",
		"The current Intruder Hunter binary can run, but building or testing from source needs the go tool on PATH.",
		"Install Go 1.26+ if you plan to build or test Intruder Hunter from source.", evidenceFrom(append(evidence, optionalDetail(goTool))...), metadata)
}

func linuxFindings(_ context.Context, probe Probe, platform string) []output.Finding {
	return []output.Finding{
		requireAllTools(platform, "linux_shell", "Linux shell support", []ToolStatus{probe.LookPath("bash")}, "Install bash or run the released Go binary for checks that do not require shell compatibility."),
		requireAllTools(platform, "linux_process_text_tools", "Linux process/text tools", []ToolStatus{probe.LookPath("ps"), probe.LookPath("awk"), probe.LookPath("grep")}, "Install procps and core text utilities so process diagnostics can collect evidence."),
		requireAnyTool(platform, "linux_network_tools", "Linux network socket tools", []ToolStatus{probe.LookPath("ss"), probe.LookPath("netstat")}, "Install iproute2 for ss or net-tools for netstat to enable listener and connection checks."),
		optionalAnyTool(platform, "linux_package_manager", "Linux package manager hints", []ToolStatus{probe.LookPath("apt"), probe.LookPath("dnf"), probe.LookPath("yum"), probe.LookPath("pacman")}, "Install or expose apt, dnf, yum, or pacman if you want package-specific update and ownership hints."),
		optionalAnyTool(platform, "linux_firewall_tools", "Linux firewall tool hints", []ToolStatus{probe.LookPath("ufw"), probe.LookPath("firewall-cmd"), probe.LookPath("firewalld"), probe.LookPath("nft")}, "Install or expose ufw, firewalld/firewall-cmd, or nft to enable firewall status hints."),
	}
}

func macOSFindings(_ context.Context, probe Probe, platform string) []output.Finding {
	return []output.Finding{
		requireAllTools(platform, "macos_process_tools", "macOS process and network tools", []ToolStatus{probe.LookPath("ps"), probe.LookPath("lsof")}, "Ensure standard macOS command line tools are available so process and network diagnostics can run."),
		requireAllTools(platform, "macos_persistence_tools", "macOS persistence inspection tools", []ToolStatus{probe.LookPath("launchctl"), probe.LookPath("plutil")}, "Restore launchctl and plutil availability to inspect LaunchAgents and LaunchDaemons."),
		requireAllTools(platform, "macos_trust_tools", "macOS trust and protection tools", []ToolStatus{probe.LookPath("codesign"), probe.LookPath("spctl"), probe.LookPath("fdesetup"), probe.FileExists("/usr/libexec/ApplicationFirewall/socketfilterfw")}, "Ensure codesign, spctl, fdesetup, and socketfilterfw are available for trust, Gatekeeper, FileVault, and firewall checks."),
	}
}

func windowsFindings(ctx context.Context, probe Probe, platform string) []output.Finding {
	shells := []ToolStatus{probe.LookPath("powershell.exe"), probe.LookPath("powershell"), probe.LookPath("pwsh.exe"), probe.LookPath("pwsh")}
	findings := []output.Finding{
		requireAnyTool(platform, "windows_powershell", "Windows PowerShell availability", shells, "Install or expose Windows PowerShell or PowerShell 7 so Windows diagnostics can query local security state."),
		requireAllTools(platform, "windows_system_tools", "Windows system tools", []ToolStatus{probe.LookPath("netsh"), probe.LookPath("schtasks")}, "Ensure netsh and schtasks are available for firewall and scheduled-task diagnostics."),
	}

	shell := firstAvailableTool(shells)
	if shell.Available {
		findings = append(findings, requireAllTools(platform, "windows_defender_cmdlets", "Windows Defender cmdlets", []ToolStatus{
			probe.PowerShellCmdlet(ctx, shell.Name, "Get-MpComputerStatus"),
			probe.PowerShellCmdlet(ctx, shell.Name, "Get-MpThreatDetection"),
		}, "Enable Microsoft Defender cmdlets or use an elevated PowerShell with the Defender module available."))
	} else {
		findings = append(findings, newFinding(platform, "windows_defender_cmdlets", severityWarning,
			"Windows Defender cmdlets could not be checked",
			"PowerShell was not available, so Doctor could not confirm Defender cmdlet availability.",
			"Install or expose PowerShell, then rerun doctor.", toolEvidence(shells),
			map[string]string{"status": "skipped", "reason": "powershell_missing"}))
	}

	return findings
}

func requireAllTools(platform, check, title string, tools []ToolStatus, remediation string) output.Finding {
	missing := missingTools(tools)
	if len(missing) == 0 {
		return newFinding(platform, check, severityOK, title+" are available",
			"All required local tools for this prerequisite group were found.", "", toolEvidence(tools),
			map[string]string{"status": "available", "required": "true"})
	}

	return newFinding(platform, check, severityWarning, title+" are incomplete",
		fmt.Sprintf("Missing required local tools: %s.", strings.Join(missing, ", ")), remediation, toolEvidence(tools),
		map[string]string{"status": "missing", "required": "true", "missing": strings.Join(missing, ",")})
}

func requireAnyTool(platform, check, title string, tools []ToolStatus, remediation string) output.Finding {
	available := availableTools(tools)
	if len(available) > 0 {
		return newFinding(platform, check, severityOK, title+" are available",
			fmt.Sprintf("Found at least one required tool: %s.", strings.Join(available, ", ")), "", toolEvidence(tools),
			map[string]string{"status": "available", "required": "true", "available": strings.Join(available, ",")})
	}

	return newFinding(platform, check, severityWarning, title+" are missing",
		"No acceptable tool was found for this prerequisite group.", remediation, toolEvidence(tools),
		map[string]string{"status": "missing", "required": "true", "missing": strings.Join(toolNames(tools), ",")})
}

func optionalAnyTool(platform, check, title string, tools []ToolStatus, remediation string) output.Finding {
	available := availableTools(tools)
	if len(available) > 0 {
		return newFinding(platform, check, severityInfo, title+" are available",
			fmt.Sprintf("Found optional local hints: %s.", strings.Join(available, ", ")), "", toolEvidence(tools),
			map[string]string{"status": "available", "required": "false", "available": strings.Join(available, ",")})
	}

	return newFinding(platform, check, severityInfo, title+" are missing",
		"Optional local hints were not found; diagnostics can still run but may provide less specific guidance.", remediation, toolEvidence(tools),
		map[string]string{"status": "missing", "required": "false", "missing": strings.Join(toolNames(tools), ",")})
}

func newFinding(platform, check, severity, title, finding, remediation string, evidence []string, metadata map[string]string) output.Finding {
	return output.Finding{
		ID:          fmt.Sprintf("%s.doctor.%s", platform, check),
		Platform:    platform,
		Module:      moduleName,
		Check:       check,
		Severity:    severity,
		Title:       title,
		Finding:     finding,
		Evidence:    cleanStrings(evidence),
		Remediation: remediation,
		Metadata:    cleanMetadata(metadata),
	}
}

func countSummary(findings []output.Finding) output.Summary {
	var summary output.Summary
	for _, finding := range findings {
		switch finding.Severity {
		case severityCritical:
			summary.CriticalCount++
		case severityWarning:
			summary.WarningCount++
		case severityOK:
			summary.OKCount++
		case severityInfo:
			summary.InfoCount++
		}
	}
	return summary
}

func sortFindings(findings []output.Finding) {
	slices.SortStableFunc(findings, func(left, right output.Finding) int {
		return strings.Compare(left.ID, right.ID)
	})
}

func normalizePlatform(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "darwin":
		return "macos"
	case "":
		return "unknown"
	default:
		return strings.ToLower(strings.TrimSpace(platform))
	}
}

func firstAvailableTool(tools []ToolStatus) ToolStatus {
	for _, tool := range tools {
		if tool.Available {
			return tool
		}
	}
	return ToolStatus{}
}

func availableTools(tools []ToolStatus) []string {
	var names []string
	for _, tool := range tools {
		if tool.Available {
			names = append(names, tool.Name)
		}
	}
	slices.Sort(names)
	return names
}

func missingTools(tools []ToolStatus) []string {
	var names []string
	for _, tool := range tools {
		if !tool.Available {
			names = append(names, tool.Name)
		}
	}
	slices.Sort(names)
	return names
}

func toolNames(tools []ToolStatus) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func toolEvidence(tools []ToolStatus) []string {
	evidence := make([]string, 0, len(tools))
	for _, tool := range tools {
		if tool.Available {
			value := tool.Name
			if tool.Path != "" {
				value = fmt.Sprintf("%s=%s", tool.Name, tool.Path)
			}
			if tool.Detail != "" {
				value = fmt.Sprintf("%s (%s)", value, tool.Detail)
			}
			evidence = append(evidence, value)
			continue
		}

		value := fmt.Sprintf("%s=missing", tool.Name)
		if tool.Detail != "" {
			value = fmt.Sprintf("%s (%s)", value, tool.Detail)
		}
		evidence = append(evidence, value)
	}
	return cleanStrings(evidence)
}

func optionalDetail(tool ToolStatus) string {
	if tool.Detail == "" {
		return fmt.Sprintf("%s=missing", tool.Name)
	}
	return fmt.Sprintf("%s=missing (%s)", tool.Name, tool.Detail)
}

func evidenceFrom(values ...string) []string {
	return cleanStrings(values)
}

func cleanStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	slices.Sort(cleaned)
	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

func cleanMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}

	cleaned := make(map[string]string, len(metadata))
	for key, value := range metadata {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		cleaned[trimmedKey] = strings.TrimSpace(value)
	}
	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

func emptyAsUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return strings.TrimSpace(value)
}

func shellQuotePowerShellName(name string) string {
	return "'" + strings.ReplaceAll(name, "'", "''") + "'"
}
