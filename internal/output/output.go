package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	FormatText = "text"
	FormatJSON = "json"

	SchemaVersion = "1.0"
	ToolName      = "intruder-hunter"
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
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Finding     string            `json:"finding"`
	Evidence    []string          `json:"evidence,omitempty"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type Envelope struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	Platform      string    `json:"platform"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
	Error         *Error    `json:"error,omitempty"`
}

type Renderer struct {
	format string
	out    io.Writer
}

func NewRenderer(format string, out io.Writer) (*Renderer, error) {
	switch format {
	case "", FormatText:
		return &Renderer{format: FormatText, out: out}, nil
	case FormatJSON:
		return &Renderer{format: FormatJSON, out: out}, nil
	default:
		return nil, NewError(CodeUnsupportedFormat, "unsupported output format", fmt.Sprintf("use %q or %q", FormatText, FormatJSON))
	}
}

func (r *Renderer) Format() string {
	return r.format
}

func (r *Renderer) RenderEnvelope(envelope Envelope) error {
	if r.format == FormatJSON {
		encoder := json.NewEncoder(r.out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(envelope)
	}

	if envelope.Error != nil {
		_, err := fmt.Fprintf(r.out, "ERROR [%s]: %s\n", envelope.Error.Code, envelope.Error.Message)
		return err
	}

	if _, err := fmt.Fprintf(r.out, "%s report (%s)\nCritical: %d  Warnings: %d  OK: %d  Info: %d\n",
		envelope.Tool,
		envelope.Platform,
		envelope.Summary.CriticalCount,
		envelope.Summary.WarningCount,
		envelope.Summary.OKCount,
		envelope.Summary.InfoCount,
	); err != nil {
		return err
	}

	for _, finding := range envelope.Findings {
		if err := r.renderFinding(finding); err != nil {
			return err
		}
	}

	return nil
}

func (r *Renderer) renderFinding(finding Finding) error {
	line := fmt.Sprintf("- %s: %s — %s", strings.ToUpper(finding.Severity), finding.Title, finding.Finding)
	if _, err := fmt.Fprintln(r.out, line); err != nil {
		return err
	}

	if len(finding.Evidence) > 0 {
		if _, err := fmt.Fprintf(r.out, "  Evidence: %s\n", strings.Join(finding.Evidence, "; ")); err != nil {
			return err
		}
	}
	if strings.TrimSpace(finding.Remediation) != "" {
		if _, err := fmt.Fprintf(r.out, "  Remediation: %s\n", finding.Remediation); err != nil {
			return err
		}
	}

	return nil
}

func (r *Renderer) RenderMessage(message string) error {
	_, err := fmt.Fprintln(r.out, message)
	return err
}

func NewEnvelope(platform string, startedAt, completedAt time.Time, summary Summary, findings []Finding, outputErr *Error) Envelope {
	if findings == nil {
		findings = []Finding{}
	}

	return Envelope{
		SchemaVersion: SchemaVersion,
		Tool:          ToolName,
		Platform:      platform,
		StartedAt:     startedAt.UTC(),
		CompletedAt:   completedAt.UTC(),
		Summary:       summary,
		Findings:      findings,
		Error:         outputErr,
	}
}
