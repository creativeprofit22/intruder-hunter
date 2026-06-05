package cli

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/output"
	"github.com/creativeprofit22/intruder-hunter/internal/version"
)

func TestVersionCommandTextOutput(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := NewRootCommand(Options{Out: &stdout, Err: &stderr})
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	got := stdout.String()
	for _, want := range []string{
		version.Name,
		version.Version,
		version.Commit,
		runtime.GOOS + "/" + runtime.GOARCH,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("version output %q does not contain %q", got, want)
		}
	}
}

func TestVersionCommandJSONEnvelope(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fixedTime := time.Date(2026, 5, 27, 12, 0, 0, 0, time.FixedZone("local", -7*60*60))

	cmd := NewRootCommand(Options{
		Out: &stdout,
		Err: &stderr,
		Now: func() time.Time {
			return fixedTime
		},
	})
	cmd.SetArgs([]string{"version", "--output", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; output = %s", err, stdout.String())
	}

	if envelope.SchemaVersion != output.SchemaVersion || envelope.Tool != output.ToolName {
		t.Fatalf("envelope identity = schema %q tool %q", envelope.SchemaVersion, envelope.Tool)
	}
	if envelope.Platform != currentPlatform() {
		t.Fatalf("platform = %q, want %q", envelope.Platform, currentPlatform())
	}
	wantTime := fixedTime.UTC()
	if !envelope.StartedAt.Equal(wantTime) || !envelope.CompletedAt.Equal(wantTime) {
		t.Fatalf("times = %s/%s, want %s", envelope.StartedAt, envelope.CompletedAt, wantTime)
	}
	if envelope.Summary != (output.Summary{InfoCount: 1}) {
		t.Fatalf("summary = %+v, want one info finding", envelope.Summary)
	}
	if envelope.Error != nil {
		t.Fatalf("error = %+v, want nil", envelope.Error)
	}
	if len(envelope.Findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(envelope.Findings))
	}

	finding := envelope.Findings[0]
	if finding.ID != currentPlatform()+".version.current" || finding.Module != "version" || finding.Check != "version" || finding.Severity != "info" {
		t.Fatalf("version finding identity = %+v", finding)
	}
	if finding.Metadata["commit"] != version.Commit || finding.Metadata["goos"] != runtime.GOOS || finding.Metadata["goarch"] != runtime.GOARCH {
		t.Fatalf("version metadata = %+v", finding.Metadata)
	}
}

func TestExecuteUnsupportedOutputFormatReturnsStableError(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute(&stdout, &stderr, []string{"version", "--output", "yaml"})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	got := stderr.String()
	if !strings.Contains(got, "ERROR ["+output.CodeUnsupportedFormat+"]: unsupported output format") {
		t.Fatalf("stderr = %q, want stable unsupported output error", got)
	}
}
