package report

import (
	"fmt"
	"io"
)

func WriteText(writer io.Writer, scanReport Report) error {
	_, err := fmt.Fprintf(writer, "%s scan report (%s)\nCritical: %d  Warnings: %d  OK: %d  Info: %d\n",
		defaultString(scanReport.Tool, ToolName),
		scanReport.Platform,
		scanReport.Summary.CriticalCount,
		scanReport.Summary.WarningCount,
		scanReport.Summary.OKCount,
		scanReport.Summary.InfoCount,
	)
	return err
}
