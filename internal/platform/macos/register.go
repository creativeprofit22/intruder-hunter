package macos

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
	"github.com/creativeprofit22/intruder-hunter/internal/runner"
)

const (
	platformName   = "macos"
	defaultTimeout = 5 * time.Second
)

// Checks returns the initial Go-native macOS diagnostic checks.
func Checks() []check.Check {
	return []check.Check{
		systemCheck{macOSCheck: macOSCheck{id: "macos.system.info", title: "macOS system information", category: check.CategorySystem}},
		processesCheck{macOSCheck: macOSCheck{id: "macos.processes.context", title: "macOS process context", category: check.CategoryProcesses}},
		networkCheck{macOSCheck: macOSCheck{id: "macos.network.listeners", title: "macOS network listeners", category: check.CategoryNetwork}},
		usersCheck{macOSCheck: macOSCheck{id: "macos.users.accounts", title: "macOS users and authentication", category: check.CategoryUsers}},
		malwareCheck{macOSCheck: macOSCheck{id: "macos.malware.indicators", title: "macOS malware and persistence indicators", category: check.CategoryMalware}},
		securityCheck{macOSCheck: macOSCheck{id: "macos.security.settings", title: "macOS security settings", category: check.CategorySecurity}},
		vulnerabilitiesCheck{macOSCheck: macOSCheck{id: "macos.vulnerabilities.posture", title: "macOS vulnerability posture", category: check.CategoryVulnerabilities}},
		logsCheck{macOSCheck: macOSCheck{id: "macos.logs.auth", title: "macOS authentication logs", category: check.CategoryLogs}},
	}
}

// Registry returns a deterministic registry containing all macOS checks.
func Registry() *check.Registry { return check.MustRegistry(Checks()...) }

type macOSCheck struct {
	id            string
	title         string
	category      check.Category
	requiresAdmin bool
}

func (c macOSCheck) ID() string                  { return c.id }
func (c macOSCheck) Title() string               { return c.title }
func (c macOSCheck) Category() check.Category    { return c.category }
func (c macOSCheck) Platforms() []check.Platform { return []check.Platform{check.PlatformMacOS} }
func (c macOSCheck) RequiresAdmin() bool         { return c.requiresAdmin }
func (c macOSCheck) findingID(name string) string {
	return fmt.Sprintf("macos.%s.%s", c.category, name)
}
func (c macOSCheck) moduleName() string { return string(c.category) }

func finding(id, module, checkName string, severity report.Severity, title, text string, evidence []string, remediation string, metadata map[string]string) report.Finding {
	return report.Finding{ID: id, Platform: platformName, Module: module, Check: checkName, Severity: severity, Title: title, Finding: text, Evidence: compactEvidence(evidence), Remediation: remediation, Metadata: metadata}
}

func okFinding(id, module, checkName, title, text string, evidence []string) report.Finding {
	return finding(id, module, checkName, report.SeverityOK, title, text, evidence, "No action required.", nil)
}

func infoFinding(id, module, checkName, title, text string, evidence []string) report.Finding {
	return finding(id, module, checkName, report.SeverityInfo, title, text, evidence, "Review this context if it is unexpected for this Mac.", nil)
}

func commandInfoFinding(id, module, checkName, command string, err error) report.Finding {
	return finding(id, module, checkName, report.SeverityInfo, command+" unavailable", "The check could not collect this source, so results may be incomplete.", []string{err.Error()}, "Install or permit the tool if you need this signal.", map[string]string{"command": command, "status": "unavailable"})
}

func runCommand(ctx context.Context, checkCtx check.Context, name string, args ...string) (*runner.Result, error) {
	return checkCtx.Runner.Run(ctx, name, args, runner.Options{Timeout: defaultTimeout})
}

func commandOutput(ctx context.Context, checkCtx check.Context, name string, args ...string) (string, error) {
	result, err := runCommand(ctx, checkCtx, name, args...)
	if err != nil {
		if errors.Is(err, runner.ErrCommandNotFound) {
			return "", err
		}
		if result != nil && len(result.Stdout) > 0 {
			return string(result.Stdout), nil
		}
		return "", err
	}
	return string(result.Stdout), nil
}

func compactEvidence(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func parseInt(value string) int { parsed, _ := strconv.Atoi(strings.TrimSpace(value)); return parsed }

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "unknown"
}

func limitLines(lines []string, limit int) []string {
	lines = compactEvidence(lines)
	if len(lines) > limit {
		return lines[:limit]
	}
	return lines
}
