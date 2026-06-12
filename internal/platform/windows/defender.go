package windows

import (
	"context"
	"fmt"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type defenderCheck struct{ windowsCheck }

type windowsDefenderStatus struct {
	AntivirusEnabled              bool                    `json:"AntivirusEnabled"`
	RealTimeProtectionEnabled     bool                    `json:"RealTimeProtectionEnabled"`
	AntispywareEnabled            bool                    `json:"AntispywareEnabled"`
	BehaviorMonitorEnabled        bool                    `json:"BehaviorMonitorEnabled"`
	IoavProtectionEnabled         bool                    `json:"IoavProtectionEnabled"`
	NISEnabled                    bool                    `json:"NISEnabled"`
	AntivirusSignatureLastUpdated string                  `json:"AntivirusSignatureLastUpdated"`
	QuickScanAge                  int                     `json:"QuickScanAge"`
	FullScanAge                   int                     `json:"FullScanAge"`
	Threats                       []windowsDefenderThreat `json:"Threats"`
}

type windowsDefenderThreat struct {
	ThreatName string `json:"ThreatName"`
	IsActive   bool   `json:"IsActive"`
}

const defenderScript = `$status = Get-MpComputerStatus -ErrorAction Stop; $threats = @(Get-MpThreat -ErrorAction SilentlyContinue | Select-Object ThreatName,IsActive); [pscustomobject]@{ AntivirusEnabled=$status.AntivirusEnabled; RealTimeProtectionEnabled=$status.RealTimeProtectionEnabled; AntispywareEnabled=$status.AntispywareEnabled; BehaviorMonitorEnabled=$status.BehaviorMonitorEnabled; IoavProtectionEnabled=$status.IoavProtectionEnabled; NISEnabled=$status.NISEnabled; AntivirusSignatureLastUpdated=$status.AntivirusSignatureLastUpdated; QuickScanAge=[int]$status.QuickScanAge; FullScanAge=[int]$status.FullScanAge; Threats=$threats } | ConvertTo-Json -Compress -Depth 4`

func (c defenderCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	out, err := powerShellOutput(ctx, checkCtx, defenderScript)
	if err != nil {
		return []report.Finding{commandInfoFinding(c.findingID("defender_unavailable"), c.moduleName(), "defender_status", "Get-MpComputerStatus", err)}, nil
	}
	status, err := parseWindowsDefenderStatus(out)
	if err != nil {
		return nil, err
	}
	findings := make([]report.Finding, 0, 3)
	if !status.AntivirusEnabled || !status.RealTimeProtectionEnabled {
		findings = append(findings, finding(c.findingID("protection_disabled"), c.moduleName(), "defender_status", report.SeverityCritical, "Microsoft Defender protection is disabled", "Defender antivirus or real-time protection is disabled. This may be intentional on managed hosts with another AV, but it reduces native protection.", defenderEvidence(status), "Confirm whether another managed security product is active. Re-enable Defender only if it will not conflict with enterprise policy or another AV.", nil))
	} else if !status.BehaviorMonitorEnabled || !status.IoavProtectionEnabled || !status.NISEnabled {
		findings = append(findings, finding(c.findingID("components_disabled"), c.moduleName(), "defender_status", report.SeverityWarning, "Some Defender protection components are disabled", "Core antivirus is enabled, but one or more protection components are disabled.", defenderEvidence(status), "Review security policy, management tooling, and Defender settings before changing component state.", nil))
	} else {
		findings = append(findings, okFinding(c.findingID("enabled"), c.moduleName(), "defender_status", "Microsoft Defender protections are enabled", "Defender antivirus, real-time protection, behavior monitoring, IOAV, and network inspection report enabled.", defenderEvidence(status)))
	}
	if threats := activeDefenderThreats(status.Threats); len(threats) > 0 {
		findings = append(findings, finding(c.findingID("active_threats"), c.moduleName(), "defender_threats", report.SeverityCritical, "Microsoft Defender reports active threats", fmt.Sprintf("Defender returned %d active threat record(s).", len(threats)), threats, "Preserve evidence and follow incident response procedures; do not simply clear detections without understanding persistence and scope.", map[string]string{"confidence": "high"}))
	} else {
		findings = append(findings, okFinding(c.findingID("active_threats_ok"), c.moduleName(), "defender_threats", "No active Defender threats reported", "Get-MpThreat returned no active threat records.", nil))
	}
	if status.QuickScanAge > 7 {
		findings = append(findings, finding(c.findingID("quick_scan_stale"), c.moduleName(), "scan_age", report.SeverityWarning, "Defender quick scan is stale", fmt.Sprintf("Defender reports quick scan age of %d days.", status.QuickScanAge), []string{fmt.Sprintf("quick_scan_age_days=%d", status.QuickScanAge)}, "Run a quick or full scan when operationally safe, unless scan scheduling is managed centrally.", nil))
	}
	return findings, nil
}

func parseWindowsDefenderStatus(output string) (windowsDefenderStatus, error) {
	return parseJSONValue[windowsDefenderStatus](output)
}

func defenderEvidence(status windowsDefenderStatus) []string {
	return []string{
		fmt.Sprintf("antivirus_enabled=%s realtime_enabled=%s antispyware_enabled=%s", boolWord(status.AntivirusEnabled), boolWord(status.RealTimeProtectionEnabled), boolWord(status.AntispywareEnabled)),
		fmt.Sprintf("behavior_monitor=%s ioav=%s nis=%s signature_updated=%s", boolWord(status.BehaviorMonitorEnabled), boolWord(status.IoavProtectionEnabled), boolWord(status.NISEnabled), status.AntivirusSignatureLastUpdated),
		fmt.Sprintf("quick_scan_age_days=%d full_scan_age_days=%d", status.QuickScanAge, status.FullScanAge),
	}
}

func activeDefenderThreats(threats []windowsDefenderThreat) []string {
	out := make([]string, 0, len(threats))
	for _, threat := range threats {
		if threat.IsActive {
			out = append(out, fmt.Sprintf("threat=%s active=true", threat.ThreatName))
		}
	}
	return limitEvidence(out, 20)
}
