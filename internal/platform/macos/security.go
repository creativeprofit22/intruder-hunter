package macos

import (
	"context"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type securityCheck struct{ macOSCheck }

type namedStatus struct{ Enabled, Known bool }

func (c securityCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	findings := make([]report.Finding, 0, 7)
	findings = append(findings, statusFinding(ctx, checkCtx, c.macOSCheck, "sip", "csrutil", []string{"status"}, parseEnabledDisabled, report.SeverityCritical, "System Integrity Protection (SIP)", "SIP protects system locations and runtime controls; disabling it can be legitimate for testing but materially weakens platform protections."))
	findings = append(findings, statusFinding(ctx, checkCtx, c.macOSCheck, "gatekeeper", "spctl", []string{"--status"}, parseEnabledDisabled, report.SeverityWarning, "Gatekeeper", "Gatekeeper helps block untrusted downloaded apps; managed Macs may enforce this through policy."))
	findings = append(findings, statusFinding(ctx, checkCtx, c.macOSCheck, "filevault", "fdesetup", []string{"status"}, parseOnOff, report.SeverityWarning, "FileVault disk encryption", "FileVault protects data at rest. Enabling it requires recovery-key handling and may be policy-managed."))
	findings = append(findings, statusFinding(ctx, checkCtx, c.macOSCheck, "application_firewall", "/usr/libexec/ApplicationFirewall/socketfilterfw", []string{"--getglobalstate"}, parseEnabledDisabled, report.SeverityWarning, "macOS Application Firewall", "The Application Firewall controls inbound app sockets but is not a complete substitute for network segmentation."))
	findings = append(findings, statusFinding(ctx, checkCtx, c.macOSCheck, "stealth_mode", "/usr/libexec/ApplicationFirewall/socketfilterfw", []string{"--getstealthmode"}, parseEnabledDisabled, report.SeverityInfo, "Firewall stealth mode", "Stealth mode is optional and can be policy-dependent."))
	findings = append(findings, remoteLoginFinding(ctx, checkCtx, c.macOSCheck))
	findings = append(findings, launchctlServiceFinding(ctx, checkCtx, c.macOSCheck, "remote_desktop", "com.apple.RemoteDesktop", "Apple Remote Desktop"))
	findings = append(findings, launchctlServiceFinding(ctx, checkCtx, c.macOSCheck, "screen_sharing", "com.apple.screensharing", "Screen Sharing"))
	return findings, nil
}

func statusFinding(ctx context.Context, checkCtx check.Context, base macOSCheck, name, command string, args []string, parser func(string) namedStatus, disabledSeverity report.Severity, title, explanation string) report.Finding {
	out, err := commandOutput(ctx, checkCtx, command, args...)
	if err != nil {
		return commandInfoFinding(base.findingID(name+"_unavailable"), base.moduleName(), name, command, err)
	}
	status := parser(out)
	if !status.Known {
		return infoFinding(base.findingID(name+"_unknown"), base.moduleName(), name, title+" status could not be parsed", explanation, []string{out})
	}
	if status.Enabled {
		return okFinding(base.findingID(name+"_enabled"), base.moduleName(), name, title+" is enabled", explanation, []string{firstLine(out)})
	}
	return finding(base.findingID(name+"_disabled"), base.moduleName(), name, disabledSeverity, title+" is disabled or enabled unexpectedly", explanation, []string{firstLine(out)}, "Review whether this is intentional for this Mac or enforced by MDM policy before changing it.", map[string]string{"confidence": "medium"})
}

func parseEnabledDisabled(output string) namedStatus {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "enabled") {
		return namedStatus{Enabled: true, Known: true}
	}
	if strings.Contains(lower, "disabled") {
		return namedStatus{Enabled: false, Known: true}
	}
	return namedStatus{}
}

func parseOnOff(output string) namedStatus {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "on") || strings.Contains(lower, "enabled") {
		return namedStatus{Enabled: true, Known: true}
	}
	if strings.Contains(lower, "off") || strings.Contains(lower, "disabled") {
		return namedStatus{Enabled: false, Known: true}
	}
	return namedStatus{}
}

func remoteLoginFinding(ctx context.Context, checkCtx check.Context, base macOSCheck) report.Finding {
	out, err := commandOutput(ctx, checkCtx, "systemsetup", "-getremotelogin")
	if err != nil {
		return commandInfoFinding(base.findingID("remote_login_unavailable"), base.moduleName(), "remote_login", "systemsetup", err)
	}
	status := parseOnOff(out)
	if !status.Known {
		return infoFinding(base.findingID("remote_login_unknown"), base.moduleName(), "remote_login", "Remote Login (SSH) status could not be parsed", "SSH access should be enabled only when needed and constrained by accounts, keys, and firewall policy.", []string{out})
	}
	if !status.Enabled {
		return okFinding(base.findingID("remote_login_disabled"), base.moduleName(), "remote_login", "Remote Login (SSH) is disabled", "SSH remote access was reported off by systemsetup.", []string{firstLine(out)})
	}
	return finding(base.findingID("remote_login_enabled"), base.moduleName(), "remote_login", report.SeverityWarning, "Remote Login (SSH) is enabled", "SSH remote access is enabled and should be intentional, key/account constrained, and aligned with firewall policy.", []string{firstLine(out)}, "Disable SSH if it is not needed, after confirming remote-management and MDM requirements.", map[string]string{"confidence": "medium"})
}

func launchctlServiceFinding(ctx context.Context, checkCtx check.Context, base macOSCheck, name, label, title string) report.Finding {
	out, err := commandOutput(ctx, checkCtx, "launchctl", "list")
	if err != nil {
		return commandInfoFinding(base.findingID(name+"_unavailable"), base.moduleName(), name, "launchctl", err)
	}
	if strings.Contains(out, label) {
		return finding(base.findingID(name+"_running"), base.moduleName(), name, report.SeverityWarning, title+" is running", title+" allows remote access and should be expected, constrained, and monitored.", []string{label}, "Disable remote access features that are not required, after confirming remote-management and MDM requirements.", map[string]string{"confidence": "medium"})
	}
	return okFinding(base.findingID(name+"_not_running"), base.moduleName(), name, title+" is not running", title+" was not present in launchctl list output.", nil)
}
