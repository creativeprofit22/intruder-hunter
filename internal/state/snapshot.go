package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

const snapshotTimestampFormat = "2006-01-02T15-04-05Z"

// RawArtifact is an optional raw file to persist under a run's raw/ directory.
// Path must be relative and may not contain . or .. path segments.
type RawArtifact struct {
	Path    string
	Content []byte
}

// RunMetadata describes a stored Intruder Hunter run. Fields are ordered to
// keep metadata.json deterministic and easy to diff.
type RunMetadata struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	Platform      string    `json:"platform"`
	RunID         string    `json:"run_id"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	ReportPath    string    `json:"report_path"`
	RawPath       string    `json:"raw_path,omitempty"`
}

// Snapshot is the on-disk location and deterministic metadata for a stored run.
type Snapshot struct {
	Dir      string      `json:"dir"`
	Metadata RunMetadata `json:"metadata"`
}

// SnapshotOptions controls StoreSnapshot behavior.
type SnapshotOptions struct {
	Now          time.Time
	StartedAt    time.Time
	CompletedAt  time.Time
	RawArtifacts []RawArtifact
}

// FormatSnapshotTimestamp formats t as a filesystem-safe UTC timestamp.
func FormatSnapshotTimestamp(t time.Time) string {
	return utcTimestamp(t).Format(snapshotTimestampFormat)
}

// StoreSnapshot writes a run snapshot using this layout:
//
//	.intruder-hunter/runs/<utc-ts>/metadata.json
//	.intruder-hunter/runs/<utc-ts>/report.json
//	.intruder-hunter/runs/<utc-ts>/raw/...
//	.intruder-hunter/latest/report.json
//
// Snapshot files are written with write-temp-then-rename, directories are 0700,
// and files are 0600. Same-second run IDs receive a deterministic numeric
// suffix such as 2026-05-27T12-00-00Z-1.
func StoreSnapshot(baseDir string, scanReport report.Report, options SnapshotOptions) (*Snapshot, error) {
	completedAt := utcTimestamp(firstNonZeroTime(options.CompletedAt, options.Now, scanReport.CompletedAt))
	startedAt := utcTimestamp(firstNonZeroTime(options.StartedAt, scanReport.StartedAt, completedAt))

	preparedReport := report.New(scanReport.Platform, startedAt, completedAt, scanReport.Findings)
	if scanReport.SchemaVersion != "" {
		preparedReport.SchemaVersion = scanReport.SchemaVersion
	}
	if scanReport.Tool != "" {
		preparedReport.Tool = scanReport.Tool
	}

	reportBody, err := report.MarshalJSON(preparedReport)
	if err != nil {
		return nil, fmt.Errorf("snapshot: marshal report: %w", err)
	}

	runID, runDir, err := reserveRunDir(baseDir, completedAt)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(runDir)
		}
	}()

	metadata := RunMetadata{
		SchemaVersion: preparedReport.SchemaVersion,
		Tool:          preparedReport.Tool,
		Platform:      preparedReport.Platform,
		RunID:         runID,
		StartedAt:     startedAt,
		CompletedAt:   completedAt,
		ReportPath:    reportFileName,
	}

	if len(options.RawArtifacts) > 0 {
		metadata.RawPath = RawDirName
		if err := writeRawArtifacts(filepath.Join(runDir, RawDirName), options.RawArtifacts); err != nil {
			return nil, fmt.Errorf("snapshot: write raw artifacts: %w", err)
		}
	}

	if err := writeFileAtomic(filepath.Join(runDir, reportFileName), reportBody); err != nil {
		return nil, fmt.Errorf("snapshot: write report: %w", err)
	}
	if err := writeJSONAtomic(filepath.Join(runDir, metadataFileName), metadata); err != nil {
		return nil, fmt.Errorf("snapshot: write metadata: %w", err)
	}
	if err := copyFileAtomic(filepath.Join(runDir, reportFileName), filepath.Join(LatestPath(baseDir), reportFileName)); err != nil {
		return nil, fmt.Errorf("snapshot: update latest report: %w", err)
	}

	cleanup = false
	return &Snapshot{Dir: runDir, Metadata: metadata}, nil
}

// LatestReportPath returns .intruder-hunter/latest/report.json for baseDir.
func LatestReportPath(baseDir string) string {
	return filepath.Join(LatestPath(baseDir), reportFileName)
}

// ReadMetadata reads metadata.json from a stored run directory.
func ReadMetadata(runDir string) (RunMetadata, error) {
	var metadata RunMetadata
	body, err := os.ReadFile(filepath.Join(runDir, metadataFileName))
	if err != nil {
		return metadata, fmt.Errorf("read metadata: %w", err)
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return metadata, fmt.Errorf("parse metadata: %w", err)
	}

	return metadata, nil
}

func reserveRunDir(baseDir string, completedAt time.Time) (string, string, error) {
	runsDir := RunsPath(baseDir)
	if err := ensureDir(runsDir); err != nil {
		return "", "", fmt.Errorf("snapshot: create runs dir: %w", err)
	}

	baseName := FormatSnapshotTimestamp(completedAt)
	for suffix := 0; suffix < 1000; suffix++ {
		name := baseName
		if suffix > 0 {
			name = fmt.Sprintf("%s-%d", baseName, suffix)
		}

		runDir := filepath.Join(runsDir, name)
		if err := os.Mkdir(runDir, stateDirMode); err == nil {
			if err := os.Chmod(runDir, stateDirMode); err != nil {
				return "", "", fmt.Errorf("snapshot: chmod run dir: %w", err)
			}
			return name, runDir, nil
		} else if !os.IsExist(err) {
			return "", "", fmt.Errorf("snapshot: create run dir: %w", err)
		}
	}

	return "", "", fmt.Errorf("snapshot: exhausted timestamp collisions for %s", baseName)
}

func writeRawArtifacts(rawDir string, artifacts []RawArtifact) error {
	if err := ensureDir(rawDir); err != nil {
		return err
	}

	artifacts = append([]RawArtifact(nil), artifacts...)
	sort.SliceStable(artifacts, func(left, right int) bool {
		return strings.Compare(artifacts[left].Path, artifacts[right].Path) < 0
	})

	for _, artifact := range artifacts {
		relativePath, err := safeRelativePath(artifact.Path)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(rawDir, relativePath), artifact.Content); err != nil {
			return err
		}
	}

	return nil
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}

	return time.Time{}
}
