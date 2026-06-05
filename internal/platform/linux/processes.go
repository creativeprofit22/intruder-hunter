package linux

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type processesCheck struct{ linuxCheck }

type processRecord struct {
	PID     string
	PPID    string
	User    string
	CPU     float64
	Elapsed string
	Comm    string
	Args    string
}

type processAssessment struct {
	Severity report.Severity
	Score    int
	Reasons  []string
}

var (
	knownMinerNames = []string{"xmrig", "xmrig-proxy", "kdevtmpfsi", "kinsing", "watchdog", "sysrv", "teamtnt", "hildegard", "lemonduck", "nicehash", "nanominer", "cpuminer", "ethminer", "nbminer", "lolminer", "t-rex", "phoenixminer", "bfgminer", "cgminer", "minerd"}
	minerCLI        = []string{"stratum+tcp", "stratum+ssl", "pool.minexmr", "supportxmr", "nanopool", "nicehash", "moneroocean", "2miners", "f2pool", "miningpoolhub", "--donate-level", "--coin", "--algo", "randomx", "rx/0", "--cpu-priority", "--opencl"}
	genericMiner    = regexp.MustCompile(`(?i)(^|[^a-z0-9])(miner|xmr|monero|coinminer)([^a-z0-9]|$)`)
)

func (processesCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	base := linuxCheck{id: "linux.processes.context", title: "Linux process context", category: check.CategoryProcesses}
	out, err := commandOutput(ctx, checkCtx, "ps", "-axo", "pid=,ppid=,user=,%cpu=,etime=,comm=,args=")
	if err != nil {
		return []report.Finding{commandInfoFinding(base.findingID("ps_unavailable"), base.moduleName(), "process_context", "ps", err)}, nil
	}

	processes := parseProcessTable(out)
	if len(processes) == 0 {
		return []report.Finding{infoFinding(base.findingID("empty"), base.moduleName(), "process_context", "No process rows parsed", "The ps command returned no parseable process rows.", nil)}, nil
	}

	findings := make([]report.Finding, 0, 4)
	suspicious := 0
	for _, proc := range processes {
		assessment := assessProcess(proc)
		if assessment.Severity != "" {
			suspicious++
			id := base.findingID(fmt.Sprintf("pid_%s", proc.PID))
			findings = append(findings, finding(id, base.moduleName(), "miner_indicators", assessment.Severity, "Process has miner or suspicious execution indicators", "Process context matched one or more miner, temp-path, or high-CPU signals.", []string{formatProcess(proc), strings.Join(assessment.Reasons, "; ")}, "Confirm whether the process is expected. If unknown, preserve evidence, inspect the executable path and parent process, then stop or isolate only after understanding impact.", map[string]string{"pid": proc.PID, "score": strconv.Itoa(assessment.Score)}))
		}
	}
	if suspicious == 0 {
		findings = append(findings, okFinding(base.findingID("miner_indicators_ok"), base.moduleName(), "miner_indicators", "No process miner indicators found", "No process combined miner name, command-line pool, temp-path, or high-CPU indicators strongly enough to flag.", nil))
	}
	findings = append(findings, infoFinding(base.findingID("top_cpu"), base.moduleName(), "top_cpu", "Top CPU process context collected", fmt.Sprintf("Reviewed %d process rows using ps -axo context.", len(processes)), topCPU(processes, 5)))
	return findings, nil
}

func parseProcessTable(output string) []processRecord {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	records := make([]processRecord, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		cpu, _ := strconv.ParseFloat(fields[3], 64)
		records = append(records, processRecord{PID: fields[0], PPID: fields[1], User: fields[2], CPU: cpu, Elapsed: fields[4], Comm: fields[5], Args: strings.Join(fields[6:], " ")})
	}
	return records
}

func assessProcess(proc processRecord) processAssessment {
	text := strings.ToLower(proc.Comm + " " + proc.Args)
	path := executableCandidate(proc)
	reasons := make([]string, 0, 4)
	score := 0
	for _, token := range knownMinerNames {
		if strings.Contains(text, token) {
			score += 3
			reasons = append(reasons, "known miner/tool name: "+token)
			break
		}
	}
	for _, token := range minerCLI {
		if strings.Contains(text, token) {
			score += 3
			reasons = append(reasons, "mining pool or miner command-line indicator: "+token)
			break
		}
	}
	if genericMiner.MatchString(text) {
		score++
		reasons = append(reasons, "generic miner token requires context")
	}
	if isUserWritablePath(path) {
		score += 2
		reasons = append(reasons, "executable or command path in user-writable location: "+path)
	}
	if proc.CPU >= 80 {
		score += 2
		reasons = append(reasons, fmt.Sprintf("high CPU %.1f%%", proc.CPU))
	} else if proc.CPU >= 50 {
		score++
		reasons = append(reasons, fmt.Sprintf("elevated CPU %.1f%%", proc.CPU))
	}

	switch {
	case score >= 6:
		return processAssessment{Severity: report.SeverityCritical, Score: score, Reasons: reasons}
	case score >= 3:
		return processAssessment{Severity: report.SeverityWarning, Score: score, Reasons: reasons}
	default:
		return processAssessment{}
	}
}

func executableCandidate(proc processRecord) string {
	fields := strings.Fields(proc.Args)
	if len(fields) > 0 {
		return fields[0]
	}
	return proc.Comm
}

func isUserWritablePath(path string) bool {
	path = strings.ToLower(path)
	return strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/var/tmp/") || strings.HasPrefix(path, "/dev/shm/") || strings.HasPrefix(path, "/home/") || strings.HasPrefix(path, "./")
}

func formatProcess(proc processRecord) string {
	return fmt.Sprintf("pid=%s ppid=%s user=%s cpu=%.1f etime=%s comm=%s args=%s", proc.PID, proc.PPID, proc.User, proc.CPU, proc.Elapsed, proc.Comm, proc.Args)
}

func topCPU(processes []processRecord, limit int) []string {
	selected := append([]processRecord(nil), processes...)
	for i := 0; i < len(selected); i++ {
		for j := i + 1; j < len(selected); j++ {
			if selected[j].CPU > selected[i].CPU {
				selected[i], selected[j] = selected[j], selected[i]
			}
		}
	}
	if len(selected) > limit {
		selected = selected[:limit]
	}
	evidence := make([]string, 0, len(selected))
	for _, proc := range selected {
		evidence = append(evidence, formatProcess(proc))
	}
	return evidence
}
