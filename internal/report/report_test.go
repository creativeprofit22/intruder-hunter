package report

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCountSummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		findings []Finding
		want     Summary
	}{
		{
			name:     "empty findings",
			findings: nil,
			want:     Summary{},
		},
		{
			name: "counts supported severities",
			findings: []Finding{
				{Severity: SeverityCritical},
				{Severity: SeverityWarning},
				{Severity: SeverityWarning},
				{Severity: SeverityOK},
				{Severity: SeverityInfo},
			},
			want: Summary{CriticalCount: 1, WarningCount: 2, OKCount: 1, InfoCount: 1},
		},
		{
			name: "ignores unknown severity",
			findings: []Finding{
				{Severity: Severity("unknown")},
				{Severity: SeverityInfo},
			},
			want: Summary{InfoCount: 1},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := CountSummary(test.findings)
			if got != test.want {
				t.Fatalf("CountSummary() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestMarshalJSONShape(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 5, 27, 12, 0, 0, 0, time.FixedZone("local", -7*60*60))
	completedAt := time.Date(2026, 5, 27, 12, 1, 30, 0, time.FixedZone("local", -7*60*60))
	scanReport := New("linux", startedAt, completedAt, []Finding{
		{
			ID:          "linux.users.uid0-extra-root-account",
			Platform:    "linux",
			Module:      "users",
			Check:       "check_users",
			Severity:    SeverityCritical,
			Title:       "Unexpected UID 0 account found",
			Finding:     "Account backuproot has UID 0 privileges.",
			Evidence:    []string{"backuproot:x:0:0:..."},
			Remediation: "Review the account, disable it if unauthorized, and rotate affected credentials.",
			References:  []string{"https://example.test/users"},
			Metadata: map[string]string{
				"source_file": "lib/linux/users.sh",
			},
		},
	})

	encoded, err := MarshalJSON(scanReport)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}

	want := "{\n" +
		"  \"schema_version\": \"1.0\",\n" +
		"  \"tool\": \"intruder-hunter\",\n" +
		"  \"platform\": \"linux\",\n" +
		"  \"started_at\": \"2026-05-27T19:00:00Z\",\n" +
		"  \"completed_at\": \"2026-05-27T19:01:30Z\",\n" +
		"  \"summary\": {\n" +
		"    \"critical_count\": 1,\n" +
		"    \"warning_count\": 0,\n" +
		"    \"ok_count\": 0,\n" +
		"    \"info_count\": 0\n" +
		"  },\n" +
		"  \"findings\": [\n" +
		"    {\n" +
		"      \"id\": \"linux.users.uid0-extra-root-account\",\n" +
		"      \"platform\": \"linux\",\n" +
		"      \"module\": \"users\",\n" +
		"      \"check\": \"check_users\",\n" +
		"      \"severity\": \"critical\",\n" +
		"      \"title\": \"Unexpected UID 0 account found\",\n" +
		"      \"finding\": \"Account backuproot has UID 0 privileges.\",\n" +
		"      \"evidence\": [\n" +
		"        \"backuproot:x:0:0:...\"\n" +
		"      ],\n" +
		"      \"remediation\": \"Review the account, disable it if unauthorized, and rotate affected credentials.\",\n" +
		"      \"references\": [\n" +
		"        \"https://example.test/users\"\n" +
		"      ],\n" +
		"      \"metadata\": {\n" +
		"        \"source_file\": \"lib/linux/users.sh\"\n" +
		"      }\n" +
		"    }\n" +
		"  ]\n" +
		"}\n"

	if string(encoded) != want {
		t.Fatalf("MarshalJSON() =\n%s\nwant\n%s", encoded, want)
	}

	var decoded struct {
		SchemaVersion string  `json:"schema_version"`
		Tool          string  `json:"tool"`
		Platform      string  `json:"platform"`
		Summary       Summary `json:"summary"`
		Findings      []struct {
			ID          string            `json:"id"`
			Platform    string            `json:"platform"`
			Module      string            `json:"module"`
			Check       string            `json:"check"`
			Severity    Severity          `json:"severity"`
			Title       string            `json:"title"`
			Finding     string            `json:"finding"`
			Evidence    []string          `json:"evidence"`
			Remediation string            `json:"remediation"`
			References  []string          `json:"references"`
			Metadata    map[string]string `json:"metadata"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.SchemaVersion != SchemaVersion || decoded.Tool != ToolName || decoded.Platform != "linux" {
		t.Fatalf("decoded top-level fields = %+v", decoded)
	}
	if decoded.Summary != (Summary{CriticalCount: 1}) {
		t.Fatalf("decoded summary = %+v", decoded.Summary)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].Severity != SeverityCritical {
		t.Fatalf("decoded findings = %+v", decoded.Findings)
	}
}

func TestMarshalJSONSortsFindingsAndNestedSlices(t *testing.T) {
	t.Parallel()

	scanReport := Report{
		Platform: "linux",
		Findings: []Finding{
			{
				ID:         "linux.users.b",
				Platform:   "linux",
				Module:     "users",
				Check:      "check_users",
				Severity:   SeverityInfo,
				Title:      "B",
				Evidence:   []string{"z", "a"},
				References: []string{"z", "a"},
			},
			{
				ID:       "linux.network.a",
				Platform: "linux",
				Module:   "network",
				Check:    "check_network",
				Severity: SeverityWarning,
				Title:    "A",
			},
		},
	}

	encoded, err := MarshalJSON(scanReport)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.SchemaVersion != SchemaVersion || decoded.Tool != ToolName {
		t.Fatalf("decoded defaults = schema %q tool %q", decoded.SchemaVersion, decoded.Tool)
	}
	if len(decoded.Findings) != 2 {
		t.Fatalf("len(decoded.Findings) = %d, want 2", len(decoded.Findings))
	}
	if decoded.Findings[0].ID != "linux.network.a" || decoded.Findings[1].ID != "linux.users.b" {
		t.Fatalf("finding order = %q, %q", decoded.Findings[0].ID, decoded.Findings[1].ID)
	}
	if got := decoded.Findings[1].Evidence; len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("evidence order = %#v", got)
	}
	if got := decoded.Findings[1].References; len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("references order = %#v", got)
	}
}
