package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

func TestRunAggregatesSuccessfulFindings(t *testing.T) {
	registry := check.MustRegistry(fakeCheck{
		id:       "linux.system.os",
		title:    "Operating system",
		category: check.CategorySystem,
		findings: []report.Finding{{
			ID:          "linux.system.os",
			Platform:    "linux",
			Module:      "system",
			Check:       "os",
			Severity:    report.SeverityOK,
			Title:       "Operating system detected",
			Finding:     "The scan is running on Linux.",
			Remediation: "",
		}},
	})

	baseDir := t.TempDir()
	result, err := Run(context.Background(), Options{
		Registry:        registry,
		Platform:        check.PlatformLinux,
		Clock:           fixedClock(),
		SnapshotBaseDir: baseDir,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if got := result.Report.Summary.OKCount; got != 1 {
		t.Fatalf("OKCount = %d, want 1", got)
	}
	if len(result.Report.Findings) != 1 {
		t.Fatalf("findings length = %d, want 1", len(result.Report.Findings))
	}
	if result.Snapshot == nil {
		t.Fatal("snapshot was nil")
	}
	if _, err := os.Stat(filepath.Join(baseDir, ".intruder-hunter", "latest", "report.json")); err != nil {
		t.Fatalf("latest report was not written: %v", err)
	}
}

func TestRunAggregatesCheckFailureAsFinding(t *testing.T) {
	registry := check.MustRegistry(fakeCheck{
		id:       "linux.network.listeners",
		title:    "Listening ports",
		category: check.CategoryNetwork,
		findings: []report.Finding{{
			ID:          "linux.network.partial",
			Platform:    "linux",
			Module:      "network",
			Check:       "listeners",
			Severity:    report.SeverityInfo,
			Title:       "Partial network output",
			Finding:     "Some network output was collected before the check failed.",
			Remediation: "",
		}},
		err: errors.New("ss command failed"),
	})

	result, err := Run(context.Background(), Options{
		Registry:   registry,
		Platform:   check.PlatformLinux,
		Clock:      fixedClock(),
		NoSnapshot: true,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(result.Report.Findings) != 2 {
		t.Fatalf("findings length = %d, want 2", len(result.Report.Findings))
	}
	if got := result.Report.Summary.WarningCount; got != 1 {
		t.Fatalf("WarningCount = %d, want 1", got)
	}
	failure := findReportFinding(result.Report.Findings, "linux.network.listeners.failed")
	if failure == nil {
		t.Fatalf("failure finding was not present: %#v", result.Report.Findings)
	}
	if failure.Evidence[0] != "ss command failed" {
		t.Fatalf("failure evidence = %q, want command error", failure.Evidence[0])
	}
}

func TestRunTimeoutStopsScan(t *testing.T) {
	registry := check.MustRegistry(fakeCheck{
		id:       "linux.system.slow",
		title:    "Slow check",
		category: check.CategorySystem,
		run: func(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})

	result, err := Run(context.Background(), Options{
		Registry:   registry,
		Platform:   check.PlatformLinux,
		Clock:      fixedClock(),
		NoSnapshot: true,
		Timeout:    time.Nanosecond,
	})
	if err == nil {
		t.Fatal("Run returned nil error, want timeout error")
	}
	if result == nil {
		t.Fatal("result was nil")
	}
	if got := result.Report.Summary.WarningCount; got != 1 {
		t.Fatalf("WarningCount = %d, want 1", got)
	}
	if result.Snapshot != nil {
		t.Fatal("snapshot should not be written after timeout")
	}
}

func TestRunNoSnapshot(t *testing.T) {
	baseDir := t.TempDir()
	result, err := Run(context.Background(), Options{
		Registry:        check.MustRegistry(),
		Platform:        check.PlatformLinux,
		Clock:           fixedClock(),
		NoSnapshot:      true,
		SnapshotBaseDir: baseDir,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Snapshot != nil {
		t.Fatal("snapshot was written despite NoSnapshot")
	}
	if _, err := os.Stat(filepath.Join(baseDir, ".intruder-hunter")); !os.IsNotExist(err) {
		t.Fatalf("state dir exists or stat failed unexpectedly: %v", err)
	}
}

func fixedClock() check.Clock {
	instant := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	return check.ClockFunc(func() time.Time { return instant })
}

func findReportFinding(findings []report.Finding, id string) *report.Finding {
	for index := range findings {
		if findings[index].ID == id {
			return &findings[index]
		}
	}
	return nil
}

type fakeCheck struct {
	id        string
	title     string
	category  check.Category
	platforms []check.Platform
	findings  []report.Finding
	err       error
	run       func(context.Context, check.Context) ([]report.Finding, error)
}

func (f fakeCheck) ID() string               { return f.id }
func (f fakeCheck) Title() string            { return f.title }
func (f fakeCheck) Category() check.Category { return f.category }
func (f fakeCheck) Platforms() []check.Platform {
	if len(f.platforms) == 0 {
		return []check.Platform{check.PlatformLinux}
	}
	return append([]check.Platform(nil), f.platforms...)
}
func (f fakeCheck) RequiresAdmin() bool { return false }
func (f fakeCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	if f.run != nil {
		return f.run(ctx, checkCtx)
	}
	return append([]report.Finding(nil), f.findings...), f.err
}
