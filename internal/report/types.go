package report

import "time"

const (
	SchemaVersion = "1.0"
	ToolName      = "intruder-hunter"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityOK       Severity = "ok"
	SeverityInfo     Severity = "info"
)

type Summary struct {
	CriticalCount int `json:"critical_count"`
	WarningCount  int `json:"warning_count"`
	OKCount       int `json:"ok_count"`
	InfoCount     int `json:"info_count"`
}

type Finding struct {
	ID          string            `json:"id"`
	Platform    string            `json:"platform"`
	Module      string            `json:"module"`
	Check       string            `json:"check"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Finding     string            `json:"finding"`
	Evidence    []string          `json:"evidence,omitempty"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	Platform      string    `json:"platform"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}
