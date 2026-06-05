package windows

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type processesCheck struct{ windowsCheck }

type windowsProcess struct {
	Name            string  `json:"Name"`
	ProcessID       int     `json:"ProcessId"`
	ParentProcessID int     `json:"ParentProcessId"`
	ExecutablePath  string  `json:"ExecutablePath"`
	CommandLine     string  `json:"CommandLine"`
	CreationDate    string  `json:"CreationDate"`
	CPU             float64 `json:"CPU"`
}

type windowsProcessAssessment struct {
	Severity report.Severity
	Score    int
	Reasons  []string
}

var (
	knownWindowsMinerNames = []string{"xmrig", "xmrig-proxy", "kdevtmpfsi", "kinsing", "teamtnt", "hildegard", "lemonduck", "nicehash", "nanominer", "cpuminer", "ethminer", "nbminer", "lolminer", "t-rex", "phoenixminer", "bfgminer", "cgminer", "minerd"}
	windowsMinerCLI        = []string{"stratum+tcp", "stratum+ssl", "pool.minexmr", "supportxmr", "nanopool", "nicehash", "moneroocean", "2miners", "f2pool", "miningpoolhub", "--donate-level", "--coin", "--algo", "randomx", "rx/0", "--cpu-priority", "--opencl", "--cuda", "--url"}
	genericWindowsMiner    = regexp.MustCompile(`(?i)(^|[^a-z0-9])(miner|xmr|monero|coinminer)([^a-z0-9]|$)`)
)

const processesScript = `$cpu = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $cpu[[int]$_.Id] = [double]($_.CPU) }; Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate,@{Name='CPU';Expression={ if ($cpu.ContainsKey([int]$_.ProcessId)) { $cpu[[int]$_.ProcessId] } else { 0 } }} | ConvertTo-Json -Compress -Depth 3`

func (c processesCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	out, err := powerShellOutput(ctx, checkCtx, processesScript)
	if err != nil {
		return []report.Finding{commandInfoFinding(c.findingID("powershell_unavailable"), c.moduleName(), "process_context", "powershell.exe", err)}, nil
	}
	processes, err := parseWindowsProcesses(out)
	if err != nil {
		return nil, err
	}
	findings := make([]report.Finding, 0, 4)
	suspicious := 0
	for _, proc := range processes {
		assessment := assessWindowsProcess(proc)
		if assessment.Severity == "" {
			continue
		}
		suspicious++
		findings = append(findings, finding(c.findingID(fmt.Sprintf("pid_%d", proc.ProcessID)), c.moduleName(), "miner_indicators", assessment.Severity, "Process has miner or suspicious execution indicators", "Process context matched miner names, pool flags, user-writable paths, or high CPU strongly enough to flag.", []string{formatWindowsProcess(proc), strings.Join(assessment.Reasons, "; ")}, "Confirm whether the process is expected. If unknown, preserve evidence, inspect the executable path and parent process, then isolate or stop only after understanding impact.", map[string]string{"pid": strconv.Itoa(proc.ProcessID), "score": strconv.Itoa(assessment.Score)}))
	}
	if suspicious == 0 {
		findings = append(findings, okFinding(c.findingID("miner_indicators_ok"), c.moduleName(), "miner_indicators", "No process miner indicators found", "No process combined miner name, pool flag, temp-path, or high-CPU indicators strongly enough to flag.", nil))
	}
	findings = append(findings, infoFinding(c.findingID("top_cpu"), c.moduleName(), "top_cpu", "Top CPU process context collected", fmt.Sprintf("Reviewed %d process rows using Get-CimInstance Win32_Process plus Get-Process CPU context.", len(processes)), topWindowsCPU(processes, 5)))
	return findings, nil
}

func parseWindowsProcesses(output string) ([]windowsProcess, error) {
	return parseJSONList[windowsProcess](output)
}

func assessWindowsProcess(proc windowsProcess) windowsProcessAssessment {
	text := strings.ToLower(proc.Name + " " + proc.ExecutablePath + " " + proc.CommandLine)
	reasons := make([]string, 0, 4)
	score := 0
	if token, ok := containsAnyFold(proc.Name+" "+proc.ExecutablePath, knownWindowsMinerNames); ok {
		score += 3
		reasons = append(reasons, "known miner/tool name: "+token)
	}
	if token, ok := containsAnyFold(proc.CommandLine, windowsMinerCLI); ok {
		score += 3
		reasons = append(reasons, "mining pool or miner command-line indicator: "+token)
	}
	if genericWindowsMiner.MatchString(text) {
		score++
		reasons = append(reasons, "generic miner token requires context")
	}
	if windowsUserWritablePath(proc.ExecutablePath) {
		score += 2
		reasons = append(reasons, "executable path in user-writable location: "+proc.ExecutablePath)
	}
	if proc.CPU >= 80 {
		score += 2
		reasons = append(reasons, fmt.Sprintf("high CPU %.1f", proc.CPU))
	} else if proc.CPU >= 50 {
		score++
		reasons = append(reasons, fmt.Sprintf("elevated CPU %.1f", proc.CPU))
	}
	switch {
	case score >= 6:
		return windowsProcessAssessment{Severity: report.SeverityCritical, Score: score, Reasons: reasons}
	case score >= 3:
		return windowsProcessAssessment{Severity: report.SeverityWarning, Score: score, Reasons: reasons}
	default:
		return windowsProcessAssessment{}
	}
}

func formatWindowsProcess(proc windowsProcess) string {
	return fmt.Sprintf("pid=%d ppid=%d name=%s path=%s command=%s", proc.ProcessID, proc.ParentProcessID, proc.Name, proc.ExecutablePath, proc.CommandLine)
}

func topWindowsCPU(processes []windowsProcess, limit int) []string {
	selected := append([]windowsProcess(nil), processes...)
	sort.SliceStable(selected, func(i, j int) bool { return selected[j].CPU < selected[i].CPU })
	if len(selected) > limit {
		selected = selected[:limit]
	}
	evidence := make([]string, 0, len(selected))
	for _, proc := range selected {
		evidence = append(evidence, fmt.Sprintf("pid=%d name=%s cpu=%.1f path=%s", proc.ProcessID, proc.Name, proc.CPU, proc.ExecutablePath))
	}
	return evidence
}
