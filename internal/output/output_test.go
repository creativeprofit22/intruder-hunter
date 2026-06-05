package output

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRenderEnvelopeTextIncludesFindingDetails(t *testing.T) {
	var buffer bytes.Buffer
	renderer, err := NewRenderer(FormatText, &buffer)
	if err != nil {
		t.Fatalf("NewRenderer() error = %v", err)
	}

	envelope := NewEnvelope("linux", time.Unix(0, 0), time.Unix(1, 0), Summary{WarningCount: 1}, []Finding{
		{
			ID:          "linux.doctor.admin_capability",
			Platform:    "linux",
			Module:      "doctor",
			Check:       "admin_capability",
			Severity:    "warning",
			Title:       "Admin/root capability is not available",
			Finding:     "Some diagnostics may be incomplete without elevated privileges.",
			Evidence:    []string{"effective user id is 1000"},
			Remediation: "Re-run with sudo when performing full diagnostics.",
		},
	}, nil)

	if err := renderer.RenderEnvelope(envelope); err != nil {
		t.Fatalf("RenderEnvelope() error = %v", err)
	}

	output := buffer.String()
	assertContains(t, output, "intruder-hunter report (linux)")
	assertContains(t, output, "WARNING: Admin/root capability is not available")
	assertContains(t, output, "Some diagnostics may be incomplete without elevated privileges.")
	assertContains(t, output, "Evidence: effective user id is 1000")
	assertContains(t, output, "Remediation: Re-run with sudo when performing full diagnostics.")
}

func TestRenderEnvelopeTextErrorUsesStableErrorFormat(t *testing.T) {
	var buffer bytes.Buffer
	renderer, err := NewRenderer(FormatText, &buffer)
	if err != nil {
		t.Fatalf("NewRenderer() error = %v", err)
	}

	envelope := NewEnvelope("linux", time.Unix(0, 0), time.Unix(1, 0), Summary{}, nil, NewError(CodeUnsupportedFormat, "unsupported output format", "use text or json"))

	if err := renderer.RenderEnvelope(envelope); err != nil {
		t.Fatalf("RenderEnvelope() error = %v", err)
	}

	got := buffer.String()
	want := "ERROR [IH_UNSUPPORTED_OUTPUT_FORMAT]: unsupported output format\n"
	if got != want {
		t.Fatalf("RenderEnvelope() output = %q, want %q", got, want)
	}
}

func assertContains(t *testing.T, haystack string, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("output does not contain %q:\n%s", needle, haystack)
	}
}
