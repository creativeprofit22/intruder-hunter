package macos

import (
	"context"
	"fmt"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type logsCheck struct{ macOSCheck }

func (c logsCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	findings := make([]report.Finding, 0, 4)
	findings = append(findings, authFailuresFinding(ctx, checkCtx, c.macOSCheck))
	findings = append(findings, recentSudoFinding(ctx, checkCtx, c.macOSCheck))
	findings = append(findings, kernelPanicFinding(ctx, checkCtx, c.macOSCheck))
	findings = append(findings, recentLoginsFinding(ctx, checkCtx, c.macOSCheck))
	return findings, nil
}

func authFailuresFinding(ctx context.Context, checkCtx check.Context, base macOSCheck) report.Finding {
	out, err := commandOutput(ctx, checkCtx, "log", "show", "--predicate", `eventMessage contains "Failed password" OR eventMessage contains "authentication failure"`, "--last", "24h")
	if err != nil {
		return commandInfoFinding(base.findingID("auth_failures_unavailable"), base.moduleName(), "auth_failures", "log", err)
	}
	count := len(compactEvidence(strings.Split(out, "\n")))
	if count > 100 {
		return finding(base.findingID("auth_failures_high"), base.moduleName(), "auth_failures", report.SeverityWarning, "High authentication failure volume", fmt.Sprintf("%d authentication failure log lines were seen in the last 24h.", count), limitLines(strings.Split(out, "\n"), 10), "Review source context and remote access exposure; high failure volume may indicate brute-force attempts or noisy services.", map[string]string{"count": fmt.Sprint(count), "confidence": "medium"})
	}
	if count > 0 {
		return infoFinding(base.findingID("auth_failures"), base.moduleName(), "auth_failures", "Authentication failures found", fmt.Sprintf("%d authentication failure log lines were seen in the last 24h.", count), limitLines(strings.Split(out, "\n"), 10))
	}
	return okFinding(base.findingID("auth_failures_ok"), base.moduleName(), "auth_failures", "No authentication failures in last 24h", "No matching failed password or authentication failure messages were returned by log show.", nil)
}

func recentSudoFinding(ctx context.Context, checkCtx check.Context, base macOSCheck) report.Finding {
	out, err := commandOutput(ctx, checkCtx, "log", "show", "--predicate", `eventMessage contains "sudo"`, "--last", "1h")
	if err != nil {
		return commandInfoFinding(base.findingID("sudo_unavailable"), base.moduleName(), "sudo_usage", "log", err)
	}
	lines := limitLines(strings.Split(out, "\n"), 5)
	if len(lines) == 0 {
		return okFinding(base.findingID("sudo_none"), base.moduleName(), "sudo_usage", "No recent sudo usage", "No sudo log messages were returned for the last hour.", nil)
	}
	return infoFinding(base.findingID("sudo_recent"), base.moduleName(), "sudo_usage", "Recent sudo usage", "Recent sudo log context was collected for review.", lines)
}

func kernelPanicFinding(ctx context.Context, checkCtx check.Context, base macOSCheck) report.Finding {
	out, err := commandOutput(ctx, checkCtx, "find", "/Library/Logs/DiagnosticReports", "-name", "*.panic", "-mtime", "-7", "-print")
	if err != nil {
		return commandInfoFinding(base.findingID("kernel_panics_unavailable"), base.moduleName(), "kernel_panics", "find", err)
	}
	panics := limitLines(strings.Split(out, "\n"), 20)
	if len(panics) == 0 {
		return okFinding(base.findingID("kernel_panics_ok"), base.moduleName(), "kernel_panics", "No kernel panics in last 7 days", "No recent .panic reports were found under /Library/Logs/DiagnosticReports.", nil)
	}
	return finding(base.findingID("kernel_panics"), base.moduleName(), "kernel_panics", report.SeverityWarning, "Kernel panics in last 7 days", "Recent panics are stability signals and can also affect forensic reliability, but are not compromise evidence by themselves.", panics, "Review panic reports and hardware/software changes; escalate if panics align with suspicious activity.", map[string]string{"count": fmt.Sprint(len(panics)), "confidence": "low"})
}

func recentLoginsFinding(ctx context.Context, checkCtx check.Context, base macOSCheck) report.Finding {
	out, err := commandOutput(ctx, checkCtx, "last", "-5")
	if err != nil {
		return commandInfoFinding(base.findingID("recent_logins_unavailable"), base.moduleName(), "recent_logins", "last", err)
	}
	lines := limitLines(strings.Split(out, "\n"), 5)
	if len(lines) == 0 {
		return infoFinding(base.findingID("recent_logins_empty"), base.moduleName(), "recent_logins", "No recent login rows parsed", "last returned no parseable rows.", nil)
	}
	return infoFinding(base.findingID("recent_logins"), base.moduleName(), "recent_logins", "Recent login summary", "Recent login rows were collected for review.", lines)
}
