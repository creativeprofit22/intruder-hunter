package windows

import (
	"context"
	"fmt"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type tasksCheck struct{ windowsCheck }

type windowsScheduledTask struct {
	TaskName  string `json:"TaskName"`
	TaskPath  string `json:"TaskPath"`
	State     string `json:"State"`
	Author    string `json:"Author"`
	Actions   string `json:"Actions"`
	Principal string `json:"Principal"`
}

const scheduledTasksScript = `Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath; State=[string]$_.State; Author=$_.Author; Actions=(($_.Actions | ForEach-Object { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() }) -join ' | '); Principal=$_.Principal.UserId } } | ConvertTo-Json -Compress -Depth 4`

func (c tasksCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	out, err := powerShellOutput(ctx, checkCtx, scheduledTasksScript)
	if err != nil {
		return []report.Finding{commandInfoFinding(c.findingID("powershell_unavailable"), c.moduleName(), "scheduled_tasks", "powershell.exe", err)}, nil
	}
	tasks, err := parseWindowsScheduledTasks(out)
	if err != nil {
		return nil, err
	}
	findings := make([]report.Finding, 0, 4)
	flagged := 0
	for index, task := range tasks {
		severity, reasons := assessWindowsScheduledTask(task)
		if severity == "" {
			continue
		}
		flagged++
		findings = append(findings, finding(c.findingID(fmt.Sprintf("task_%d", index+1)), c.moduleName(), "scheduled_tasks", severity, "Scheduled task needs review", "A scheduled task action matched suspicious path, encoded shell, or miner context.", []string{formatWindowsScheduledTask(task), strings.Join(reasons, "; ")}, "Confirm the task owner and action. Disable only after validating that it is not required by Windows, management software, or business apps.", map[string]string{"task": task.TaskPath + task.TaskName}))
	}
	if flagged == 0 {
		findings = append(findings, okFinding(c.findingID("scheduled_tasks_ok"), c.moduleName(), "scheduled_tasks", "No suspicious scheduled task actions found", "No scheduled task action matched user-writable path, encoded shell, or miner command context.", nil))
	}
	findings = append(findings, infoFinding(c.findingID("scheduled_tasks_summary"), c.moduleName(), "scheduled_tasks", "Scheduled task inventory collected", fmt.Sprintf("Collected %d scheduled tasks.", len(tasks)), summarizeWindowsScheduledTasks(tasks, 10)))
	return findings, nil
}

func parseWindowsScheduledTasks(output string) ([]windowsScheduledTask, error) {
	return parseJSONList[windowsScheduledTask](output)
}

func assessWindowsScheduledTask(task windowsScheduledTask) (report.Severity, []string) {
	text := task.Actions
	reasons := make([]string, 0, 3)
	score := 0
	if windowsUserWritablePath(text) {
		score += 2
		reasons = append(reasons, "task action references user-writable path")
	}
	if token, ok := containsAnyFold(text, []string{"-enc", "-encodedcommand", "frombase64string", "downloadstring", "invoke-webrequest", "iex "}); ok {
		score += 2
		reasons = append(reasons, "suspicious shell/download indicator: "+token)
	}
	if token, ok := containsAnyFold(text, windowsMinerCLI); ok {
		score += 3
		reasons = append(reasons, "miner command-line indicator: "+token)
	}
	if token, ok := containsAnyFold(text, knownWindowsMinerNames); ok {
		score += 3
		reasons = append(reasons, "known miner/tool name: "+token)
	}
	switch {
	case score >= 5:
		return report.SeverityCritical, reasons
	case score >= 2:
		return report.SeverityWarning, reasons
	default:
		return "", nil
	}
}

func formatWindowsScheduledTask(task windowsScheduledTask) string {
	return fmt.Sprintf("task=%s%s state=%s author=%s principal=%s actions=%s", task.TaskPath, task.TaskName, task.State, task.Author, task.Principal, task.Actions)
}

func summarizeWindowsScheduledTasks(tasks []windowsScheduledTask, limit int) []string {
	out := make([]string, 0, len(tasks))
	for _, task := range tasks {
		out = append(out, formatWindowsScheduledTask(task))
	}
	return limitEvidence(out, limit)
}
