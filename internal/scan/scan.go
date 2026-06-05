package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/output"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
	"github.com/creativeprofit22/intruder-hunter/internal/state"
)

const defaultSnapshotBaseDir = "."

// Options configures a Go-native scan run.
type Options struct {
	Registry        *check.Registry
	Platform        check.Platform
	Clock           check.Clock
	StartedAt       time.Time
	OutputFormat    string
	ReportJSONPath  string
	NoSnapshot      bool
	SnapshotBaseDir string
	Timeout         time.Duration
}

// Result describes the completed scan and any persisted snapshot.
type Result struct {
	Report           report.Report
	Snapshot         *state.Snapshot
	SnapshotDisabled bool
}

// Run selects platform checks from the registry, runs them sequentially, and
// aggregates their findings into a normalized report. Individual check failures
// are represented as warning findings so one broken check does not hide other
// results. Context cancellation and scan timeouts stop orchestration promptly.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if ctx == nil {
		return nil, errors.New("scan: nil context")
	}

	clock := opts.Clock
	if clock == nil {
		clock = check.ClockFunc(time.Now)
	}

	startedAt := opts.StartedAt
	if startedAt.IsZero() {
		startedAt = clock.Now()
	}
	startedAt = startedAt.UTC()

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	platform := opts.Platform
	checks := opts.Registry.ForPlatform(platform)
	findings := make([]report.Finding, 0, len(checks))
	checkCtx := check.NewContext(check.ContextOptions{
		Clock:     clock,
		StartedAt: startedAt,
		Output: check.OutputOptions{
			Format:     defaultString(opts.OutputFormat, output.FormatText),
			ReportPath: opts.ReportJSONPath,
		},
		Report: check.ReportOptions{
			SchemaVersion: report.SchemaVersion,
			Tool:          report.ToolName,
			Platform:      platform,
		},
	})

	for _, platformCheck := range checks {
		if err := runCtx.Err(); err != nil {
			findings = append(findings, cancellationFinding(platform, err))
			completedAt := clock.Now().UTC()
			scanReport := report.New(string(platform), startedAt, completedAt, findings)
			return &Result{Report: scanReport}, fmt.Errorf("scan canceled: %w", err)
		}

		checkFindings, err := platformCheck.Run(runCtx, checkCtx)
		findings = append(findings, checkFindings...)
		if err != nil {
			findings = append(findings, failureFinding(platform, platformCheck, err))
		}
	}

	if err := runCtx.Err(); err != nil {
		completedAt := clock.Now().UTC()
		scanReport := report.New(string(platform), startedAt, completedAt, findings)
		return &Result{Report: scanReport}, fmt.Errorf("scan canceled: %w", err)
	}

	completedAt := clock.Now().UTC()
	scanReport := report.New(string(platform), startedAt, completedAt, findings)

	if opts.ReportJSONPath != "" {
		if err := writeReportJSON(opts.ReportJSONPath, scanReport); err != nil {
			return &Result{Report: scanReport}, err
		}
	}

	result := &Result{Report: scanReport, SnapshotDisabled: opts.NoSnapshot}
	if !opts.NoSnapshot {
		baseDir := opts.SnapshotBaseDir
		if baseDir == "" {
			baseDir = defaultSnapshotBaseDir
		}
		snapshot, err := state.StoreSnapshot(baseDir, scanReport, state.SnapshotOptions{
			StartedAt:   startedAt,
			CompletedAt: completedAt,
		})
		if err != nil {
			return result, fmt.Errorf("store scan snapshot: %w", err)
		}
		result.Snapshot = snapshot
	}

	return result, nil
}

func cancellationFinding(platform check.Platform, err error) report.Finding {
	return report.Finding{
		ID:          fmt.Sprintf("%s.scan.canceled", platform),
		Platform:    string(platform),
		Module:      "scan",
		Check:       "orchestration",
		Severity:    report.SeverityWarning,
		Title:       "Scan stopped before all checks completed",
		Finding:     "The scan context was canceled before remaining checks could run.",
		Evidence:    []string{err.Error()},
		Remediation: "Re-run with a longer --timeout or investigate why the command was canceled.",
		Metadata: map[string]string{
			"status": "canceled",
		},
	}
}

func failureFinding(platform check.Platform, platformCheck check.Check, err error) report.Finding {
	module := string(platformCheck.Category())
	checkName := stableCheckName(platformCheck.ID())
	return report.Finding{
		ID:          fmt.Sprintf("%s.%s.%s.failed", platform, module, checkName),
		Platform:    string(platform),
		Module:      module,
		Check:       checkName,
		Severity:    report.SeverityWarning,
		Title:       fmt.Sprintf("%s could not complete", platformCheck.Title()),
		Finding:     "This check returned an error, so its results may be incomplete.",
		Evidence:    []string{err.Error()},
		Remediation: "Review the error and re-run the scan after fixing missing permissions, tools, or platform prerequisites.",
		Metadata: map[string]string{
			"check_id": platformCheck.ID(),
			"status":   "failed",
		},
	}
}

func stableCheckName(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "unknown"
	}
	parts := strings.Split(id, ".")
	for index := len(parts) - 1; index >= 0; index-- {
		part := strings.TrimSpace(parts[index])
		if part != "" {
			return part
		}
	}
	return "unknown"
}

func writeReportJSON(path string, scanReport report.Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open report json: %w", err)
	}
	defer func() { _ = file.Close() }()

	if err := report.WriteJSON(file, scanReport); err != nil {
		return fmt.Errorf("write report json: %w", err)
	}
	return nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
