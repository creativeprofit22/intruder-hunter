package cli

import (
	"github.com/creativeprofit22/intruder-hunter/internal/doctor"
	"github.com/creativeprofit22/intruder-hunter/internal/output"
	"github.com/spf13/cobra"
)

func newDoctorCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check local prerequisites for Go-native diagnostics",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			renderer, err := output.NewRenderer(opts.OutputFormat, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			startedAt := opts.Now()
			report, err := doctor.Run(cmd.Context())
			completedAt := opts.Now()
			if err != nil {
				return err
			}

			return renderer.RenderEnvelope(report.Envelope(startedAt, completedAt))
		},
	}
}
