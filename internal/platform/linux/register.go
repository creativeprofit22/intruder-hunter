package linux

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
	platformName   = "linux"
	defaultTimeout = 5 * time.Second
)

// Checks returns the initial Go-native Linux diagnostic checks.
func Checks() []check.Check {
	return []check.Check{
		systemCheck{linuxCheck: linuxCheck{id: "linux.system.info", title: "Linux system information", category: check.CategorySystem}},
		processesCheck{linuxCheck: linuxCheck{id: "linux.processes.context", title: "Linux process context", category: check.CategoryProcesses}},
		networkCheck{linuxCheck: linuxCheck{id: "linux.network.listeners", title: "Linux network listeners", category: check.CategoryNetwork}},
		usersCheck{linuxCheck: linuxCheck{id: "linux.users.accounts", title: "Linux users and authentication", category: check.CategoryUsers}},
		malwareCheck{linuxCheck: linuxCheck{id: "linux.malware.indicators", title: "Linux malware and persistence indicators", category: check.CategoryMalware}},
		vulnerabilitiesCheck{linuxCheck: linuxCheck{id: "linux.vulnerabilities.posture", title: "Linux vulnerability posture", category: check.CategoryVulnerabilities}},
		logsCheck{linuxCheck: linuxCheck{id: "linux.logs.auth", title: "Linux authentication logs", category: check.CategoryLogs}},
	}
}

// Registry returns a deterministic registry containing all Linux checks.
func Registry() *check.Registry {
	return check.MustRegistry(Checks()...)
}

type linuxCheck struct {
	id            string
	title         string
	category      check.Category
	requiresAdmin bool
}

func (c linuxCheck) ID() string                  { return c.id }
func (c linuxCheck) Title() string               { return c.title }
func (c linuxCheck) Category() check.Category    { return c.category }
func (c linuxCheck) Platforms() []check.Platform { return []check.Platform{check.PlatformLinux} }
func (c linuxCheck) RequiresAdmin() bool         { return c.requiresAdmin }
func (c linuxCheck) findingID(name string) string {
	return fmt.Sprintf("linux.%s.%s", c.category, name)
}
func (c linuxCheck) checkName(name string) string  { return name }
func (c linuxCheck) moduleName() string            { return string(c.category) }
func (c linuxCheck) commandTimeout() time.Duration { return defaultTimeout }

func finding(id, module, checkName string, severity report.Severity, title, text string, evidence []string, remediation string, metadata map[string]string) report.Finding {
	return report.Finding{
		ID:          id,
		Platform:    platformName,
		Module:      module,
		Check:       checkName,
		Severity:    severity,
		Title:       title,
		Finding:     text,
		Evidence:    compactEvidence(evidence),
		Remediation: remediation,
		Metadata:    metadata,
	}
}

func okFinding(id, module, checkName, title, text string, evidence []string) report.Finding {
	return finding(id, module, checkName, report.SeverityOK, title, text, evidence, "No action required.", nil)
}

func infoFinding(id, module, checkName, title, text string, evidence []string) report.Finding {
	return finding(id, module, checkName, report.SeverityInfo, title, text, evidence, "Review this context if it is unexpected for this host.", nil)
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

func parseInt(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "unknown"
}
