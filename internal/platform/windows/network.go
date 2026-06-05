package windows

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type networkCheck struct{ windowsCheck }

type windowsListener struct {
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	OwningProcess int    `json:"OwningProcess"`
	ProcessName   string `json:"ProcessName"`
	Path          string `json:"Path"`
	ServiceNames  string `json:"ServiceNames"`
}

var highRiskWindowsPorts = map[int]string{135: "RPC endpoint mapper", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5901: "VNC", 5902: "VNC", 5903: "VNC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}

const listenersScript = `$procs = @{}; Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }; $svc = @{}; Get-CimInstance Win32_Service | Where-Object ProcessId -gt 0 | ForEach-Object { $pid = [int]$_.ProcessId; if (-not $svc.ContainsKey($pid)) { $svc[$pid] = @() }; $svc[$pid] += $_.Name }; Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $pid = [int]$_.OwningProcess; [pscustomobject]@{ LocalAddress=$_.LocalAddress; LocalPort=[int]$_.LocalPort; OwningProcess=$pid; ProcessName=if($procs.ContainsKey($pid)){$procs[$pid].Name}else{''}; Path=if($procs.ContainsKey($pid)){$procs[$pid].ExecutablePath}else{''}; ServiceNames=if($svc.ContainsKey($pid)){($svc[$pid] -join ',')}else{''} } } | ConvertTo-Json -Compress -Depth 3`

func (c networkCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	out, err := powerShellOutput(ctx, checkCtx, listenersScript)
	if err != nil {
		return []report.Finding{commandInfoFinding(c.findingID("powershell_unavailable"), c.moduleName(), "listeners", "powershell.exe", err)}, nil
	}
	listeners, err := parseWindowsListeners(out)
	if err != nil {
		return nil, err
	}
	findings := make([]report.Finding, 0, 4)
	flagged := 0
	for _, listener := range listeners {
		severity, reason := assessWindowsListener(listener)
		if severity == "" {
			continue
		}
		flagged++
		findings = append(findings, finding(c.findingID(fmt.Sprintf("listener_%d_%d", listener.OwningProcess, listener.LocalPort)), c.moduleName(), "listener_risk", severity, "Listening service needs review", "A TCP listener matched exposed administrative service or suspicious owner context.", []string{formatWindowsListener(listener), reason}, "Confirm the service is expected, restrict exposure with firewall rules, and inspect the owning process if unknown.", map[string]string{"pid": strconv.Itoa(listener.OwningProcess), "port": strconv.Itoa(listener.LocalPort)}))
	}
	if flagged == 0 {
		findings = append(findings, okFinding(c.findingID("listeners_ok"), c.moduleName(), "listener_risk", "No high-risk exposed listeners found", "No listener combined high-risk ports with public binding or suspicious executable context.", nil))
	}
	findings = append(findings, infoFinding(c.findingID("listeners_summary"), c.moduleName(), "listeners", "Listening TCP services collected", fmt.Sprintf("Collected %d listening TCP sockets with owning process and service context.", len(listeners)), summarizeWindowsListeners(listeners, 10)))
	return findings, nil
}

func parseWindowsListeners(output string) ([]windowsListener, error) {
	return parseJSONList[windowsListener](output)
}

func assessWindowsListener(listener windowsListener) (report.Severity, string) {
	public := isPublicWindowsBind(listener.LocalAddress)
	service, highRisk := highRiskWindowsPorts[listener.LocalPort]
	suspiciousPath := windowsUserWritablePath(listener.Path)
	switch {
	case public && highRisk && suspiciousPath:
		return report.SeverityCritical, fmt.Sprintf("%s exposed on %s with user-writable executable path %s", service, listener.LocalAddress, listener.Path)
	case public && highRisk:
		return report.SeverityWarning, fmt.Sprintf("%s exposed on %s", service, listener.LocalAddress)
	case public && suspiciousPath:
		return report.SeverityWarning, "public listener owned by process from user-writable path: " + listener.Path
	default:
		return "", ""
	}
}

func isPublicWindowsBind(address string) bool {
	address = strings.TrimSpace(strings.ToLower(address))
	return address == "0.0.0.0" || address == "::" || address == "[::]" || (!strings.HasPrefix(address, "127.") && address != "localhost" && address != "::1" && address != "")
}

func formatWindowsListener(listener windowsListener) string {
	return fmt.Sprintf("local=%s:%d pid=%d process=%s services=%s path=%s", listener.LocalAddress, listener.LocalPort, listener.OwningProcess, listener.ProcessName, listener.ServiceNames, listener.Path)
}

func summarizeWindowsListeners(listeners []windowsListener, limit int) []string {
	selected := append([]windowsListener(nil), listeners...)
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].LocalPort == selected[j].LocalPort {
			return selected[i].OwningProcess < selected[j].OwningProcess
		}
		return selected[i].LocalPort < selected[j].LocalPort
	})
	if len(selected) > limit {
		selected = selected[:limit]
	}
	out := make([]string, 0, len(selected))
	for _, listener := range selected {
		out = append(out, formatWindowsListener(listener))
	}
	return out
}
