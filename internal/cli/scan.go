package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/output"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
	"github.com/creativeprofit22/intruder-hunter/internal/scan"
	"github.com/spf13/cobra"
)

func newScanCommand(opts *Options) *cobra.Command {
	var reportJSONPath string
	var noSnapshot bool
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run Go-native security checks for this platform",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			renderer, err := output.NewRenderer(opts.OutputFormat, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			registry := opts.ScanRegistry
			if registry == nil {
				registry = check.MustRegistry()
			}

			result, err := scan.Run(cmd.Context(), scan.Options{
				Registry:        registry,
				Platform:        check.Platform(currentPlatform()),
				Clock:           check.ClockFunc(opts.Now),
				OutputFormat:    renderer.Format(),
				ReportJSONPath:  reportJSONPath,
				NoSnapshot:      noSnapshot,
				SnapshotBaseDir: opts.SnapshotBaseDir,
				Timeout:         timeout,
			})
			if result == nil {
				return err
			}

			if renderer.Format() == output.FormatJSON {
				if renderErr := renderer.RenderEnvelope(envelopeFromReport(result.Report)); renderErr != nil {
					return renderErr
				}
				return err
			}

			if renderErr := renderScanText(cmd.OutOrStdout(), result); renderErr != nil {
				return renderErr
			}
			return err
		},
	}

	cmd.Flags().StringVar(&reportJSONPath, "report-json", "", "write the normalized scan report JSON to PATH")
	cmd.Flags().BoolVar(&noSnapshot, "no-snapshot", false, "do not write .intruder-hunter snapshot files")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "cancel the scan after this duration, for example 30s or 5m")

	return cmd
}

func renderScanText(writer io.Writer, result *scan.Result) error {
	scanReport := result.Report
	if _, err := fmt.Fprintf(writer, "Intruder Hunter scan report (%s)\n", scanReport.Platform); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "Summary:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  Critical issues: %d\n", scanReport.Summary.CriticalCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  Warnings:        %d\n", scanReport.Summary.WarningCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  OK checks:       %d\n", scanReport.Summary.OKCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  Info notes:      %d\n", scanReport.Summary.InfoCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, ""); err != nil {
		return err
	}

	if len(scanReport.Findings) == 0 {
		if _, err := fmt.Fprintln(writer, "No Go-native findings were produced for this platform yet."); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, "For a fuller diagnostic today, use the retained platform script or the legacy bridge."); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(writer, "Findings:"); err != nil {
			return err
		}
		for _, finding := range scanReport.Findings {
			if _, err := fmt.Fprintf(writer, "  [%s] %s — %s\n", finding.Severity, finding.Title, finding.Finding); err != nil {
				return err
			}
			if finding.Remediation != "" {
				if _, err := fmt.Fprintf(writer, "      Next step: %s\n", finding.Remediation); err != nil {
					return err
				}
			}
		}
	}

	if result.Snapshot != nil {
		if _, err := fmt.Fprintf(writer, "\nSnapshot saved to: %s\n", result.Snapshot.Dir); err != nil {
			return err
		}
	} else if result.SnapshotDisabled {
		if _, err := fmt.Fprintln(writer, "\nSnapshot writing was disabled for this run."); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(writer, "\nSnapshot was not written for this run."); err != nil {
			return err
		}
	}

	return nil
}

func envelopeFromReport(scanReport report.Report) output.Envelope {
	findings := make([]output.Finding, 0, len(scanReport.Findings))
	for _, finding := range scanReport.Findings {
		findings = append(findings, output.Finding{
			ID:          finding.ID,
			Platform:    finding.Platform,
			Module:      finding.Module,
			Check:       finding.Check,
			Severity:    string(finding.Severity),
			Title:       finding.Title,
			Finding:     finding.Finding,
			Evidence:    append([]string(nil), finding.Evidence...),
			Remediation: finding.Remediation,
			References:  append([]string(nil), finding.References...),
			Metadata:    copyMetadata(finding.Metadata),
		})
	}

	return output.NewEnvelope(scanReport.Platform, scanReport.StartedAt, scanReport.CompletedAt, output.Summary{
		CriticalCount: scanReport.Summary.CriticalCount,
		WarningCount:  scanReport.Summary.WarningCount,
		OKCount:       scanReport.Summary.OKCount,
		InfoCount:     scanReport.Summary.InfoCount,
	}, findings, nil)
}

func copyMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}
	copied := make(map[string]string, len(metadata))
	for key, value := range metadata {
		copied[key] = value
	}
	return copied
}
