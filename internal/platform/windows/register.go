package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
	"github.com/creativeprofit22/intruder-hunter/internal/runner"
)

const (
	platformName   = "windows"
	defaultTimeout = 10 * time.Second
)

// Checks returns the initial Go-native Windows diagnostic checks.
func Checks() []check.Check {
	return []check.Check{
		systemCheck{windowsCheck: windowsCheck{id: "windows.system.info", title: "Windows system information", category: check.CategorySystem}},
		processesCheck{windowsCheck: windowsCheck{id: "windows.processes.context", title: "Windows process context", category: check.CategoryProcesses}},
		networkCheck{windowsCheck: windowsCheck{id: "windows.network.listeners", title: "Windows network listeners", category: check.CategoryNetwork}},
		usersCheck{windowsCheck: windowsCheck{id: "windows.users.accounts", title: "Windows local users and administrators", category: check.CategoryUsers}},
		malwareCheck{windowsCheck: windowsCheck{id: "windows.malware.persistence", title: "Windows malware and persistence indicators", category: check.CategoryMalware}},
		defenderCheck{windowsCheck: windowsCheck{id: "windows.defender.status", title: "Windows Defender status", category: check.CategoryDefender}},
		tasksCheck{windowsCheck: windowsCheck{id: "windows.scheduled_tasks.persistence", title: "Windows scheduled task persistence", category: check.CategoryScheduledTasks}},
		vulnerabilitiesCheck{windowsCheck: windowsCheck{id: "windows.vulnerabilities.posture", title: "Windows vulnerability posture", category: check.CategoryVulnerabilities}},
	}
}

// Registry returns a deterministic registry containing all Windows checks.
func Registry() *check.Registry { return check.MustRegistry(Checks()...) }

type windowsCheck struct {
	id            string
	title         string
	category      check.Category
	requiresAdmin bool
}

func (c windowsCheck) ID() string                  { return c.id }
func (c windowsCheck) Title() string               { return c.title }
func (c windowsCheck) Category() check.Category    { return c.category }
func (c windowsCheck) Platforms() []check.Platform { return []check.Platform{check.PlatformWindows} }
func (c windowsCheck) RequiresAdmin() bool         { return c.requiresAdmin }
func (c windowsCheck) findingID(name string) string {
	return fmt.Sprintf("windows.%s.%s", c.category, name)
}
func (c windowsCheck) moduleName() string { return string(c.category) }

func finding(id, module, checkName string, severity report.Severity, title, text string, evidence []string, remediation string, metadata map[string]string) report.Finding {
	return report.Finding{ID: id, Platform: platformName, Module: module, Check: checkName, Severity: severity, Title: title, Finding: text, Evidence: compactEvidence(evidence), Remediation: remediation, Metadata: metadata}
}

func okFinding(id, module, checkName, title, text string, evidence []string) report.Finding {
	return finding(id, module, checkName, report.SeverityOK, title, text, evidence, "No action required.", nil)
}

func infoFinding(id, module, checkName, title, text string, evidence []string) report.Finding {
	return finding(id, module, checkName, report.SeverityInfo, title, text, evidence, "Review this context if it is unexpected for this Windows host.", nil)
}

func commandInfoFinding(id, module, checkName, command string, err error) report.Finding {
	return finding(id, module, checkName, report.SeverityInfo, command+" unavailable", "The check could not collect this source, so results may be incomplete.", []string{err.Error()}, "Run from Windows PowerShell with sufficient local permissions if you need this signal.", map[string]string{"command": command, "status": "unavailable"})
}

func powerShellOutput(ctx context.Context, checkCtx check.Context, script string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("Windows PowerShell checks are skipped on non-Windows runtime")
	}
	result, err := checkCtx.Runner.Run(ctx, "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script}, runner.Options{Timeout: defaultTimeout})
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

func parseJSONList[T any](input string) ([]T, error) {
	input = strings.TrimSpace(input)
	if input == "" || input == "null" {
		return nil, nil
	}
	var rows []T
	if err := json.Unmarshal([]byte(input), &rows); err == nil {
		return rows, nil
	}
	var row T
	if err := json.Unmarshal([]byte(input), &row); err != nil {
		return nil, fmt.Errorf("parse PowerShell JSON: %w", err)
	}
	return []T{row}, nil
}

func parseJSONValue[T any](input string) (T, error) {
	var value T
	if err := json.Unmarshal([]byte(strings.TrimSpace(input)), &value); err != nil {
		return value, fmt.Errorf("parse PowerShell JSON: %w", err)
	}
	return value, nil
}

func containsAnyFold(text string, tokens []string) (string, bool) {
	lower := strings.ToLower(text)
	for _, token := range tokens {
		if strings.Contains(lower, strings.ToLower(token)) {
			return token, true
		}
	}
	return "", false
}

func windowsUserWritablePath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	return strings.Contains(lower, `\appdata\local\temp\`) || strings.Contains(lower, `\windows\temp\`) || strings.HasPrefix(lower, `c:\users\`) || strings.Contains(lower, `\downloads\`)
}

func boolWord(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func atoi(value string) int { parsed, _ := strconv.Atoi(strings.TrimSpace(value)); return parsed }

func limitEvidence(lines []string, limit int) []string {
	lines = compactEvidence(lines)
	if len(lines) > limit {
		return lines[:limit]
	}
	return lines
}
