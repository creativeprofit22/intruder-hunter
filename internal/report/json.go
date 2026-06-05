package report

import (
	"bytes"
	"encoding/json"
	"io"
)

func WriteJSON(writer io.Writer, scanReport Report) error {
	encoded, err := MarshalJSON(scanReport)
	if err != nil {
		return err
	}

	_, err = writer.Write(encoded)
	return err
}

func MarshalJSON(scanReport Report) ([]byte, error) {
	preparedReport := scanReport
	preparedReport.SchemaVersion = defaultString(preparedReport.SchemaVersion, SchemaVersion)
	preparedReport.Tool = defaultString(preparedReport.Tool, ToolName)
	preparedReport.StartedAt = preparedReport.StartedAt.UTC()
	preparedReport.CompletedAt = preparedReport.CompletedAt.UTC()
	preparedReport.Findings = NormalizeFindings(preparedReport.Findings)
	preparedReport.Summary = CountSummary(preparedReport.Findings)

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(preparedReport); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}
