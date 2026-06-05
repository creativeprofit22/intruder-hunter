package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestRenderEnvelopeJSONUsesDocumentedShape(t *testing.T) {
	var buffer bytes.Buffer
	renderer, err := NewRenderer(FormatJSON, &buffer)
	if err != nil {
		t.Fatalf("NewRenderer() error = %v", err)
	}

	startedAt := time.Date(2026, 5, 27, 12, 0, 0, 0, time.FixedZone("local", -7*60*60))
	completedAt := startedAt.Add(time.Minute)
	envelope := NewEnvelope("linux", startedAt, completedAt, Summary{OKCount: 1}, []Finding{
		{
			ID:          "linux.doctor.platform",
			Platform:    "linux",
			Module:      "doctor",
			Check:       "platform",
			Severity:    "ok",
			Title:       "Platform detected",
			Finding:     "Doctor detected platform \"linux\".",
			Remediation: "",
			Metadata:    map[string]string{"status": "detected"},
		},
	}, nil)

	if err := renderer.RenderEnvelope(envelope); err != nil {
		t.Fatalf("RenderEnvelope() error = %v", err)
	}

	var decoded Envelope
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; output = %s", err, buffer.String())
	}
	if decoded.SchemaVersion != SchemaVersion || decoded.Tool != ToolName || decoded.Platform != "linux" {
		t.Fatalf("decoded top-level fields = %+v", decoded)
	}
	if decoded.StartedAt.Format(time.RFC3339) != "2026-05-27T19:00:00Z" || decoded.CompletedAt.Format(time.RFC3339) != "2026-05-27T19:01:00Z" {
		t.Fatalf("decoded times = %s/%s", decoded.StartedAt, decoded.CompletedAt)
	}
	if decoded.Summary != (Summary{OKCount: 1}) {
		t.Fatalf("decoded summary = %+v", decoded.Summary)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].ID != "linux.doctor.platform" {
		t.Fatalf("decoded findings = %+v", decoded.Findings)
	}
	if decoded.Error != nil {
		t.Fatalf("decoded error = %+v, want nil", decoded.Error)
	}
}

func TestNewEnvelopeNormalizesNilFindingsAndUTCTimes(t *testing.T) {
	startedAt := time.Date(2026, 5, 27, 12, 0, 0, 0, time.FixedZone("local", -7*60*60))
	completedAt := startedAt.Add(time.Second)

	envelope := NewEnvelope("linux", startedAt, completedAt, Summary{}, nil, nil)

	if envelope.Findings == nil {
		t.Fatal("Findings is nil, want empty slice for stable JSON shape")
	}
	if !envelope.StartedAt.Equal(startedAt.UTC()) || !envelope.CompletedAt.Equal(completedAt.UTC()) {
		t.Fatalf("times = %s/%s, want UTC-normalized", envelope.StartedAt, envelope.CompletedAt)
	}
}
