package linux

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type networkCheck struct{ linuxCheck }

type listenerRecord struct {
	Protocol string
	Address  string
	Port     int
	Process  string
	PID      string
	Raw      string
}

type listenerAssessment struct {
	Severity report.Severity
	Title    string
	Reason   string
}

var procRE = regexp.MustCompile(`users:\(\("([^"]+)",pid=([0-9]+)`) // ss -tulpn process field.

func (networkCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	base := linuxCheck{id: "linux.network.listeners", title: "Linux network listeners", category: check.CategoryNetwork}
	out, err := commandOutput(ctx, checkCtx, "ss", "-tulpn")
	if err != nil {
		return []report.Finding{commandInfoFinding(base.findingID("ss_unavailable"), base.moduleName(), "listeners", "ss", err)}, nil
	}
	listeners := parseSSListeners(out)
	findings := make([]report.Finding, 0, len(listeners)+1)
	if len(listeners) == 0 {
		return []report.Finding{okFinding(base.findingID("none"), base.moduleName(), "listeners", "No listening services found", "No TCP or UDP listening sockets were reported by ss.", nil)}, nil
	}
	for i, listener := range listeners {
		assessment := assessListener(listener)
		id := base.findingID(fmt.Sprintf("listener_%d_%d", listener.Port, i))
		findings = append(findings, finding(id, base.moduleName(), "listener_risk", assessment.Severity, assessment.Title, assessment.Reason, []string{listener.Raw}, listenerRemediation(listener), map[string]string{"bind": listener.Address, "port": strconv.Itoa(listener.Port), "process": listener.Process, "pid": listener.PID}))
	}

	established, err := commandOutput(ctx, checkCtx, "ss", "-antp")
	if err == nil {
		findings = append(findings, infoFinding(base.findingID("active_connections"), base.moduleName(), "active_connections", "Active connection summary", fmt.Sprintf("Established TCP connections: %d", strings.Count(established, "ESTAB")), nil))
	}
	return findings, nil
}

func parseSSListeners(output string) []listenerRecord {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	listeners := make([]listenerRecord, 0, len(lines))
	for _, line := range lines {
		if !strings.Contains(line, "LISTEN") && !strings.Contains(line, "UNCONN") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || strings.EqualFold(fields[0], "Netid") {
			continue
		}
		local := fields[4]
		if len(fields) > 5 && strings.Contains(fields[5], ":") && !strings.Contains(fields[4], ":") {
			local = fields[5]
		}
		addr, port := splitAddressPort(local)
		proc, pid := parseSSProcess(line)
		listeners = append(listeners, listenerRecord{Protocol: fields[0], Address: addr, Port: port, Process: proc, PID: pid, Raw: line})
	}
	return listeners
}

func splitAddressPort(value string) (string, int) {
	value = strings.Trim(value, "[]")
	lastColon := strings.LastIndex(value, ":")
	if lastColon == -1 {
		return value, 0
	}
	port := parseInt(value[lastColon+1:])
	addr := strings.Trim(value[:lastColon], "[]")
	if addr == "" || addr == "*" {
		addr = "0.0.0.0"
	}
	return addr, port
}

func parseSSProcess(line string) (string, string) {
	match := procRE.FindStringSubmatch(line)
	if len(match) == 3 {
		return match[1], match[2]
	}
	return "unknown", ""
}

func assessListener(listener listenerRecord) listenerAssessment {
	exposed := isExposedBind(listener.Address)
	service := highRiskService(listener.Port)
	if exposed && service != "" {
		return listenerAssessment{Severity: report.SeverityWarning, Title: "High-risk service exposed to network", Reason: fmt.Sprintf("%s on port %d is bound to %s rather than loopback.", service, listener.Port, listener.Address)}
	}
	if exposed && listener.Port >= 8000 && listener.Port <= 9000 {
		return listenerAssessment{Severity: report.SeverityInfo, Title: "Developer-range service exposed", Reason: fmt.Sprintf("Port %d is exposed; this is common for development services but should be intentional.", listener.Port)}
	}
	if exposed {
		return listenerAssessment{Severity: report.SeverityInfo, Title: "Network listener exposed", Reason: fmt.Sprintf("Port %d is bound to %s and may be reachable beyond localhost.", listener.Port, listener.Address)}
	}
	return listenerAssessment{Severity: report.SeverityOK, Title: "Listener limited to local interface", Reason: fmt.Sprintf("Port %d appears bound to loopback or a local-only address.", listener.Port)}
}

func isExposedBind(address string) bool {
	address = strings.Trim(address, "[]")
	if address == "" || address == "*" || address == "0.0.0.0" || address == "::" || address == "[::]" {
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
