package report

import (
	"slices"
	"strings"
	"time"
)

func New(platform string, startedAt, completedAt time.Time, findings []Finding) Report {
	preparedFindings := NormalizeFindings(findings)

	return Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolName,
		Platform:      platform,
		StartedAt:     startedAt.UTC(),
		CompletedAt:   completedAt.UTC(),
		Summary:       CountSummary(preparedFindings),
		Findings:      preparedFindings,
	}
}

func CountSummary(findings []Finding) Summary {
	var summary Summary

	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.CriticalCount++
		case SeverityWarning:
			summary.WarningCount++
		case SeverityOK:
			summary.OKCount++
		case SeverityInfo:
			summary.InfoCount++
		}
	}

	return summary
}

func NormalizeFindings(findings []Finding) []Finding {
	if findings == nil {
		return []Finding{}
	}

	normalized := make([]Finding, len(findings))
	for index, finding := range findings {
		finding.ID = strings.TrimSpace(finding.ID)
		finding.Platform = strings.TrimSpace(finding.Platform)
		finding.Module = strings.TrimSpace(finding.Module)
		finding.Check = strings.TrimSpace(finding.Check)
		finding.Title = strings.TrimSpace(finding.Title)
		finding.Finding = strings.TrimSpace(finding.Finding)
		finding.Remediation = strings.TrimSpace(finding.Remediation)
		finding.Evidence = copyStrings(finding.Evidence)
		finding.References = copyStrings(finding.References)
		finding.Metadata = copyMetadata(finding.Metadata)
		normalized[index] = finding
	}

	SortFindings(normalized)

	return normalized
}

func SortFindings(findings []Finding) {
	slices.SortStableFunc(findings, func(left, right Finding) int {
		for _, compare := range []int{
			strings.Compare(left.Platform, right.Platform),
			strings.Compare(left.Module, right.Module),
			strings.Compare(left.Check, right.Check),
			strings.Compare(left.ID, right.ID),
			strings.Compare(string(left.Severity), string(right.Severity)),
			strings.Compare(left.Title, right.Title),
		} {
			if compare != 0 {
				return compare
			}
		}

		return 0
	})
}

func copyStrings(values []string) []string {
	if values == nil {
		return nil
	}

	copied := append([]string(nil), values...)
	slices.Sort(copied)

	return copied
}

func copyMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	copied := make(map[string]string, len(metadata))
	for key, value := range metadata {
		copied[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	return copied
}
