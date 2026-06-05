package linux

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type logsCheck struct{ linuxCheck }

func (logsCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	base := linuxCheck{id: "linux.logs.auth", title: "Linux authentication logs", category: check.CategoryLogs}
	findings := []report.Finding{authLogFinding(base)}
	if out, err := commandOutput(ctx, checkCtx, "last", "-n", "5"); err == nil {
		findings = append(findings, infoFinding(base.findingID("recent_logins"), base.moduleName(), "recent_logins", "Recent login summary", "Recent login records were collected from last.", limitLines(compactEvidence(strings.Split(out, "\n")), 5)))
	}
	return findings, nil
}

func authLogFinding(base linuxCheck) report.Finding {
	path := firstExistingFile("/var/log/auth.log", "/var/log/secure")
	if path == "" {
		return infoFinding(base.findingID("auth_log_unavailable"), base.moduleName(), "failed_logins", "Auth log not available", "No /var/log/auth.log or /var/log/secure file was readable. This is normal for some systems, containers, or journald-only hosts.", nil)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return infoFinding(base.findingID("auth_log_unreadable"), base.moduleName(), "failed_logins", "Auth log not readable", "An auth log path exists but could not be read with current permissions.", []string{path + ": " + err.Error()})
	}
	count, recent := summarizeFailedLogins(string(data))
	if count > 100 {
		return finding(base.findingID("failed_logins_high"), base.moduleName(), "failed_logins", report.SeverityWarning, "High failed-login volume", fmt.Sprintf("Found %d failed password attempt(s) in %s.", count, path), recent, "Review source addresses and account names. If exposed SSH is unnecessary, restrict network access or disable password authentication after confirming access needs.", map[string]string{"count": fmt.Sprint(count), "confidence": "medium"})
	}
	if count > 0 {
		return infoFinding(base.findingID("failed_logins_some"), base.moduleName(), "failed_logins", "Failed-login attempts present", fmt.Sprintf("Found %d failed password attempt(s) in %s.", count, path), recent)
	}
	return okFinding(base.findingID("failed_logins_none"), base.moduleName(), "failed_logins", "No failed password attempts found", "No failed password log entries were found in the readable auth log.", nil)
}

func summarizeFailedLogins(data string) (int, []string) {
	var recent []string
	count := 0
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, "Failed password") || strings.Contains(line, "authentication failure") {
			count++
			recent = append(recent, strings.TrimSpace(line))
		}
	}
	if len(recent) > 5 {
		recent = recent[len(recent)-5:]
	}
	return count, recent
}

func firstExistingFile(paths ...string) string {
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}
