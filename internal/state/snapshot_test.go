package state

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

var fileModeAssertionsEnabled = supportsFileModeAssertions()

func TestStoreSnapshotCreatesRunFiles(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	startedAt := time.Date(2026, 5, 27, 12, 0, 1, 987654321, time.FixedZone("local", -7*60*60))
	completedAt := time.Date(2026, 5, 27, 12, 0, 3, 123456789, time.FixedZone("local", -7*60*60))
	scanReport := report.Report{
		Platform:    "linux",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Findings: []report.Finding{
			{
				ID:          "linux.users.uid0-extra-root-account",
				Platform:    "linux",
				Module:      "users",
				Check:       "check_users",
				Severity:    report.SeverityCritical,
				Title:       "Unexpected UID 0 account found",
				Finding:     "Account backuproot has UID 0 privileges.",
				Remediation: "Review the account and disable it if unauthorized.",
			},
		},
	}

	snapshot, err := StoreSnapshot(baseDir, scanReport, SnapshotOptions{
		RawArtifacts: []RawArtifact{{Path: "network/listeners.txt", Content: []byte("tcp 0.0.0.0:22\n")}},
	})
	if err != nil {
		t.Fatalf("StoreSnapshot() error = %v", err)
	}

	wantRunID := "2026-05-27T19-00-03Z"
	if snapshot.Metadata.RunID != wantRunID {
		t.Fatalf("RunID = %q, want %q", snapshot.Metadata.RunID, wantRunID)
	}
	if snapshot.Dir != filepath.Join(baseDir, DirName, RunsDirName, wantRunID) {
		t.Fatalf("Dir = %q", snapshot.Dir)
	}

	metadata := readMetadataForTest(t, snapshot.Dir)
	if metadata != snapshot.Metadata {
		t.Fatalf("metadata = %+v, want %+v", metadata, snapshot.Metadata)
	}
	if metadata.SchemaVersion != report.SchemaVersion || metadata.Tool != report.ToolName || metadata.Platform != "linux" {
		t.Fatalf("metadata defaults = %+v", metadata)
	}
	if metadata.ReportPath != reportFileName || metadata.RawPath != RawDirName {
		t.Fatalf("metadata paths = %+v", metadata)
	}
	if metadata.StartedAt != time.Date(2026, 5, 27, 19, 0, 1, 0, time.UTC) {
		t.Fatalf("StartedAt = %s", metadata.StartedAt)
	}
	if metadata.CompletedAt != time.Date(2026, 5, 27, 19, 0, 3, 0, time.UTC) {
		t.Fatalf("CompletedAt = %s", metadata.CompletedAt)
	}

	assertFileMode(t, snapshot.Dir, stateDirMode)
	assertFileMode(t, filepath.Join(snapshot.Dir, metadataFileName), stateFileMode)
	assertFileMode(t, filepath.Join(snapshot.Dir, reportFileName), stateFileMode)
	assertFileMode(t, filepath.Join(snapshot.Dir, RawDirName), stateDirMode)
	assertFileMode(t, filepath.Join(snapshot.Dir, RawDirName, "network"), stateDirMode)
	assertFileMode(t, filepath.Join(snapshot.Dir, RawDirName, "network", "listeners.txt"), stateFileMode)

	reportBody := readFileForTest(t, filepath.Join(snapshot.Dir, reportFileName))
	var decoded report.Report
	if err := json.Unmarshal(reportBody, &decoded); err != nil {
		t.Fatalf("decode report.json: %v", err)
	}
	if decoded.SchemaVersion != report.SchemaVersion || decoded.Tool != report.ToolName || decoded.Platform != "linux" {
		t.Fatalf("decoded report defaults = %+v", decoded)
	}
	if decoded.Summary != (report.Summary{CriticalCount: 1}) {
		t.Fatalf("decoded summary = %+v", decoded.Summary)
	}

	rawBody := readFileForTest(t, filepath.Join(snapshot.Dir, RawDirName, "network", "listeners.txt"))
	if string(rawBody) != "tcp 0.0.0.0:22\n" {
		t.Fatalf("raw artifact = %q", rawBody)
	}
}

func TestStoreSnapshotUpdatesLatestReport(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	firstReport := report.New("linux", time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC), time.Date(2026, 5, 27, 12, 0, 1, 0, time.UTC), []report.Finding{
		{ID: "linux.users.first", Platform: "linux", Module: "users", Check: "check_users", Severity: report.SeverityInfo, Title: "First"},
	})
	secondReport := report.New("linux", time.Date(2026, 5, 27, 12, 1, 0, 0, time.UTC), time.Date(2026, 5, 27, 12, 1, 1, 0, time.UTC), []report.Finding{
		{ID: "linux.network.second", Platform: "linux", Module: "network", Check: "check_network", Severity: report.SeverityWarning, Title: "Second"},
	})

	firstSnapshot, err := StoreSnapshot(baseDir, firstReport, SnapshotOptions{})
	if err != nil {
		t.Fatalf("StoreSnapshot(first) error = %v", err)
	}
	firstLatest := append([]byte(nil), readFileForTest(t, LatestReportPath(baseDir))...)

	secondSnapshot, err := StoreSnapshot(baseDir, secondReport, SnapshotOptions{})
	if err != nil {
		t.Fatalf("StoreSnapshot(second) error = %v", err)
	}
	secondLatest := readFileForTest(t, LatestReportPath(baseDir))
	secondRunReport := readFileForTest(t, filepath.Join(secondSnapshot.Dir, reportFileName))

	if bytes.Equal(firstLatest, secondLatest) {
		t.Fatal("latest report was not updated")
	}
	if !bytes.Equal(secondLatest, secondRunReport) {
		t.Fatalf("latest report does not match second run report")
	}
	if !bytes.Equal(firstLatest, readFileForTest(t, filepath.Join(firstSnapshot.Dir, reportFileName))) {
		t.Fatalf("first run report changed after latest update")
	}
	assertFileMode(t, filepath.Join(baseDir, DirName, LatestDirName), stateDirMode)
	assertFileMode(t, LatestReportPath(baseDir), stateFileMode)
}

func TestStoreSnapshotHandlesSameSecondCollisions(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	when := time.Date(2026, 5, 27, 12, 0, 0, 900, time.UTC)
	scanReport := report.New("linux", when, when, nil)

	firstSnapshot, err := StoreSnapshot(baseDir, scanReport, SnapshotOptions{})
	if err != nil {
		t.Fatalf("StoreSnapshot(first) error = %v", err)
	}
	secondSnapshot, err := StoreSnapshot(baseDir, scanReport, SnapshotOptions{})
	if err != nil {
		t.Fatalf("StoreSnapshot(second) error = %v", err)
	}
	thirdSnapshot, err := StoreSnapshot(baseDir, scanReport, SnapshotOptions{})
	if err != nil {
		t.Fatalf("StoreSnapshot(third) error = %v", err)
	}

	wantIDs := []string{
		"2026-05-27T12-00-00Z",
		"2026-05-27T12-00-00Z-1",
		"2026-05-27T12-00-00Z-2",
	}
	gotIDs := []string{firstSnapshot.Metadata.RunID, secondSnapshot.Metadata.RunID, thirdSnapshot.Metadata.RunID}
	for index := range wantIDs {
		if gotIDs[index] != wantIDs[index] {
			t.Fatalf("run IDs = %#v, want %#v", gotIDs, wantIDs)
		}
		if _, err := os.Stat(filepath.Join(baseDir, DirName, RunsDirName, wantIDs[index], reportFileName)); err != nil {
			t.Fatalf("stat run %q report: %v", wantIDs[index], err)
		}
	}
}

func readMetadataForTest(t *testing.T, runDir string) RunMetadata {
	t.Helper()

	metadata, err := ReadMetadata(runDir)
	if err != nil {
		t.Fatalf("ReadMetadata() error = %v", err)
	}

	return metadata
}

func readFileForTest(t *testing.T, path string) []byte {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}

	return body
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	if !fileModeAssertionsEnabled {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%q) = %v, want %v", path, got, want)
	}
}

func supportsFileModeAssertions() bool {
	if runtime.GOOS == "windows" {
		return false
	}

	probeDir, err := os.MkdirTemp("", "intruder-hunter-mode-probe-*")
	if err != nil {
		return false
	}
	defer func() { _ = os.RemoveAll(probeDir) }()

	if err := os.Chmod(probeDir, stateDirMode); err != nil {
		return false
	}
	info, err := os.Stat(probeDir)
	if err != nil {
		return false
	}

	return info.Mode().Perm() == stateDirMode
}
