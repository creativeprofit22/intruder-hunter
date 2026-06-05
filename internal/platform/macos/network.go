package macos

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type networkCheck struct{ macOSCheck }

type listenerRecord struct {
	Command, PID, User, Protocol, Address, Raw string
	Port                                       int
}

type listenerAssessment struct {
	Severity report.Severity
	Title    string
	Reason   string
}

func (c networkCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	out, err := commandOutput(ctx, checkCtx, "lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
	if err != nil {
		return []report.Finding{commandInfoFinding(c.findingID("lsof_unavailable"), c.moduleName(), "listeners", "lsof", err)}, nil
	}
	listeners := parseLsofListeners(out)
	if len(listeners) == 0 {
		return []report.Finding{okFinding(c.findingID("none"), c.moduleName(), "listeners", "No listening services found", "No TCP listening sockets were reported by lsof.", nil)}, nil
	}
	findings := make([]report.Finding, 0, len(listeners)+1)
	for i, listener := range listeners {
		assessment := assessListener(listener)
		findings = append(findings, finding(c.findingID(fmt.Sprintf("listener_%d_%d", listener.Port, i)), c.moduleName(), "listener_risk", assessment.Severity, assessment.Title, assessment.Reason, []string{listener.Raw}, listenerRemediation(listener), map[string]string{"bind": listener.Address, "port": strconv.Itoa(listener.Port), "process": listener.Command, "pid": listener.PID}))
	}
	if established, err := commandOutput(ctx, checkCtx, "netstat", "-an"); err == nil {
		findings = append(findings, infoFinding(c.findingID("active_connections"), c.moduleName(), "active_connections", "Active connection summary", fmt.Sprintf("Established TCP connections: %d", strings.Count(established, "ESTABLISHED")), nil))
	}
	return findings, nil
}

func parseLsofListeners(output string) []listenerRecord {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	listeners := make([]listenerRecord, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 9 || strings.EqualFold(fields[0], "COMMAND") {
			continue
		}
		name := fields[8]
		addr, port := splitLsofName(name)
		listeners = append(listeners, listenerRecord{Command: fields[0], PID: fields[1], User: fields[2], Protocol: fields[7], Address: addr, Port: port, Raw: line})
	}
	return listeners
}

func splitLsofName(value string) (string, int) {
	value = strings.TrimSuffix(value, "(LISTEN)")
	value = strings.TrimSpace(value)
	lastColon := strings.LastIndex(value, ":")
	if lastColon == -1 {
		return value, 0
	}
	addr := strings.Trim(value[:lastColon], "[]")
	if addr == "" || addr == "*" {
		addr = "0.0.0.0"
	}
	return addr, parseInt(value[lastColon+1:])
}

func assessListener(listener listenerRecord) listenerAssessment {
	exposed := isExposedBind(listener.Address)
	service := highRiskService(listener.Port)
	procLower := strings.ToLower(listener.Command)
	if exposed && service != "" {
		return listenerAssessment{Severity: report.SeverityWarning, Title: "High-risk service exposed to network", Reason: fmt.Sprintf("%s on port %d is bound to %s by process %s pid=%s rather than loopback.", service, listener.Port, listener.Address, listener.Command, listener.PID)}
	}
	if exposed && (strings.Contains(procLower, "python") || strings.Contains(procLower, "ruby") || strings.Contains(procLower, "node")) && listener.Port >= 8000 && listener.Port <= 9000 {
		return listenerAssessment{Severity: report.SeverityInfo, Title: "Developer-range service exposed", Reason: fmt.Sprintf("Port %d is exposed by %s; this is common for development services but should be intentional.", listener.Port, listener.Command)}
	}
	if exposed {
		return listenerAssessment{Severity: report.SeverityInfo, Title: "Network listener exposed", Reason: fmt.Sprintf("Port %d is bound to %s by %s pid=%s and may be reachable beyond localhost.", listener.Port, listener.Address, listener.Command, listener.PID)}
	}
	return listenerAssessment{Severity: report.SeverityOK, Title: "Listener limited to local interface", Reason: fmt.Sprintf("Port %d appears bound to loopback or a local-only address by %s pid=%s.", listener.Port, listener.Command, listener.PID)}
}

func isExposedBind(address string) bool {
	address = strings.Trim(address, "[]")
	if address == "" || address == "*" || address == "0.0.0.0" || address == "::" {
		return true
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

func highRiskService(port int) string {
	single := map[int]string{22: "SSH", 23: "Telnet", 25: "SMTP", 111: "rpcbind", 139: "NetBIOS", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
	if name, ok := single[port]; ok {
		return name
	}
	if port >= 5900 && port <= 5909 {
		return "VNC"
	}
	if port >= 8000 && port <= 9000 {
		return "web/developer service"
	}
	return ""
}

func listenerRemediation(listener listenerRecord) string {
	if isExposedBind(listener.Address) {
		return "Confirm the service is expected and firewall exposure is intentional; bind to loopback or restrict network access if not needed."
	}
	return "No action required if this localhost-only service is expected."
}
