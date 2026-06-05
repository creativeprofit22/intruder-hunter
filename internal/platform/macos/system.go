package macos

import (
	"context"
	"fmt"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type systemCheck struct{ macOSCheck }

func (c systemCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	var evidence []string
	if out, err := commandOutput(ctx, checkCtx, "sw_vers"); err == nil {
		evidence = append(evidence, compactEvidence(strings.Split(out, "\n"))...)
	}
	if out, err := commandOutput(ctx, checkCtx, "hostname"); err == nil {
		evidence = append(evidence, "hostname="+strings.TrimSpace(out))
	}
	if out, err := commandOutput(ctx, checkCtx, "sysctl", "-n", "machdep.cpu.brand_string"); err == nil {
		evidence = append(evidence, "chip="+strings.TrimSpace(out))
	}
	if out, err := commandOutput(ctx, checkCtx, "uptime"); err == nil {
		evidence = append(evidence, "uptime="+strings.TrimSpace(out))
	}
	if len(evidence) == 0 {
		return []report.Finding{commandInfoFinding(c.findingID("system_unavailable"), c.moduleName(), "system_info", "sw_vers", fmt.Errorf("no macOS system information commands returned output"))}, nil
	}
	return []report.Finding{infoFinding(c.findingID("info"), c.moduleName(), "system_info", "macOS system information collected", "Basic host, OS, chip, uptime, and scan timestamp context was collected.", append(evidence, "scan_started_at="+checkCtx.StartedAt.Format("2006-01-02T15:04:05Z07:00")))}, nil
}
