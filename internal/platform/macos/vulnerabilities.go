package macos

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type vulnerabilitiesCheck struct{ macOSCheck }

func (c vulnerabilitiesCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	findings := make([]report.Finding, 0, 5)
	findings = append(findings, softwareUpdateFinding(ctx, checkCtx, c.macOSCheck))
	findings = append(findings, xprotectFinding(ctx, checkCtx, c.macOSCheck))
	findings = append(findings, pathSecurityFinding(c.macOSCheck))
	findings = append(findings, homebrewFinding(ctx, checkCtx, c.macOSCheck))
	return findings, nil
}

func softwareUpdateFinding(ctx context.Context, checkCtx check.Context, base macOSCheck) report.Finding {
	out, err := commandOutput(ctx, checkCtx, "softwareupdate", "--list")
	if err != nil {
		return commandInfoFinding(base.findingID("softwareupdate_unavailable"), base.moduleName(), "software_updates", "softwareupdate", err)
	}
	updates := parseSoftwareUpdateList(out)
	if len(updates) == 0 {
		return okFinding(base.findingID("software_updates_ok"), base.moduleName(), "software_updates", "No software updates reported", "softwareupdate did not report available updates using cached Apple update metadata.", []string{firstLine(out)})
	}
	return finding(base.findingID("software_updates_pending"), base.moduleName(), "software_updates", report.SeverityWarning, "Pending software updates available", "Apple software updates are available. This is a hygiene finding, not evidence of compromise.", limitLines(updates, 20), "Plan updates with backups and a maintenance window if this Mac is production or managed by policy.", map[string]string{"confidence": "medium", "count": fmt.Sprint(len(updates))})
}

func parseSoftwareUpdateList(output string) []string {
	var updates []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(trimmed, "*") || strings.Contains(lower, "recommended") || strings.Contains(lower, "restart") || strings.Contains(lower, "label:") {
			updates = append(updates, trimmed)
		}
	}
	return updates
}

func xprotectFinding(ctx context.Context, checkCtx check.Context, base macOSCheck) report.Finding {
	var evidence []string
	if out, err := commandOutput(ctx, checkCtx, "defaults", "read", "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist", "Version"); err == nil {
		evidence = append(evidence, "XProtect version: "+strings.TrimSpace(out))
	}
	if out, err := commandOutput(ctx, checkCtx, "defaults", "read", "/System/Library/CoreServices/MRT.app/Contents/version.plist", "CFBundleShortVersionString"); err == nil {
		evidence = append(evidence, "MRT version: "+strings.TrimSpace(out))
	}
	if out, err := commandOutput(ctx, checkCtx, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"); err == nil {
		evidence = append(evidence, "ConfigDataInstall: "+strings.TrimSpace(out))
	}
	if len(evidence) == 0 {
		return infoFinding(base.findingID("xprotect_unknown"), base.moduleName(), "xprotect", "XProtect status unavailable", "Could not read XProtect/MRT version or automatic security data update settings.", nil)
	}
	return infoFinding(base.findingID("xprotect"), base.moduleName(), "xprotect", "XProtect and security data update context", "Version and automatic security data update context was collected where available; version alone does not prove protection is current.", evidence)
}

func pathSecurityFinding(base macOSCheck) report.Finding {
	var risky []string
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if info.Mode().Perm()&0o002 != 0 {
			risky = append(risky, dir)
		}
	}
	if len(risky) == 0 {
		return okFinding(base.findingID("path_ok"), base.moduleName(), "path_security", "No world-writable PATH directories", "No PATH directories visible to the scanner were world-writable.", nil)
	}
	return finding(base.findingID("path_world_writable"), base.moduleName(), "path_security", report.SeverityWarning, "World-writable directory in PATH", "A world-writable PATH directory can allow command hijacking depending on ordering and user context.", risky, "Remove world-writable directories from PATH or tighten permissions after confirming app compatibility.", map[string]string{"confidence": "medium"})
}

func homebrewFinding(ctx context.Context, checkCtx check.Context, base macOSCheck) report.Finding {
	out, err := commandOutput(ctx, checkCtx, "brew", "outdated")
	if err != nil {
		return infoFinding(base.findingID("brew_unavailable"), base.moduleName(), "homebrew", "Homebrew unavailable or no outdated output", "brew outdated could not be collected; this is normal if Homebrew is not installed.", []string{err.Error()})
	}
	outdated := compactEvidence(strings.Split(out, "\n"))
	if len(outdated) == 0 {
		return okFinding(base.findingID("brew_ok"), base.moduleName(), "homebrew", "Homebrew packages appear up to date", "brew outdated did not report packages.", nil)
	}
	severity := report.SeverityInfo
	if len(outdated) > 10 {
		severity = report.SeverityWarning
	}
	return finding(base.findingID("brew_outdated"), base.moduleName(), "homebrew", severity, "Outdated Homebrew packages", "Outdated third-party packages can carry vulnerabilities but may be intentionally pinned.", limitLines(outdated, 20), "Review and update packages with awareness of development and production compatibility.", map[string]string{"count": fmt.Sprint(len(outdated)), "confidence": "low"})
}
