package cli

import (
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/output"
	"github.com/creativeprofit22/intruder-hunter/internal/version"
	"github.com/spf13/cobra"
)

type Options struct {
	OutputFormat    string
	Out             io.Writer
	Err             io.Writer
	Now             func() time.Time
	ScanRegistry    *check.Registry
	SnapshotBaseDir string
}

func NewRootCommand(opts Options) *cobra.Command {
	config := &opts
	if config.Out == nil {
		config.Out = io.Discard
	}
	if config.Err == nil {
		config.Err = io.Discard
	}
	if config.Now == nil {
		config.Now = time.Now
	}

	cmd := &cobra.Command{
		Use:           version.Name,
		Short:         "Cross-platform security diagnostics for Linux, macOS, and Windows",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.SetOut(config.Out)
	cmd.SetErr(config.Err)
	cmd.PersistentFlags().StringVarP(&config.OutputFormat, "output", "o", output.FormatText, "output format: text or json")

	cmd.AddCommand(newVersionCommand(config))
	cmd.AddCommand(newDoctorCommand(config))
	cmd.AddCommand(newScanCommand(config))
	cmd.AddCommand(newLegacyCommand())

	return cmd
}

func newVersionCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			renderer, err := output.NewRenderer(opts.OutputFormat, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			if renderer.Format() == output.FormatJSON {
				now := opts.Now()
				platform := currentPlatform()
				envelope := output.NewEnvelope(platform, now, now, output.Summary{InfoCount: 1}, []output.Finding{
					{
						ID:          fmt.Sprintf("%s.version.current", platform),
						Platform:    platform,
						Module:      "version",
						Check:       "version",
						Severity:    "info",
						Title:       "Intruder Hunter version",
						Finding:     fmt.Sprintf("%s %s", version.Name, version.Version),
						Remediation: "",
						Metadata: map[string]string{
							"commit": version.Commit,
							"goos":   runtime.GOOS,
							"goarch": runtime.GOARCH,
						},
					},
				}, nil)
				return renderer.RenderEnvelope(envelope)
			}

			return renderer.RenderMessage(fmt.Sprintf("%s %s (%s) %s/%s", version.Name, version.Version, version.Commit, runtime.GOOS, runtime.GOARCH))
		},
	}
}

func Execute(out, errOut io.Writer, args []string) int {
	cmd := NewRootCommand(Options{Out: out, Err: errOut})
	cmd.SetArgs(args)

	if err := cmd.Execute(); err != nil {
		outputErr := output.NormalizeError(err)
		if outputErr.Rendered {
			return 1
		}

		renderer, rendererErr := output.NewRenderer(output.FormatText, errOut)
		if rendererErr != nil {
			_, _ = fmt.Fprintf(errOut, "ERROR [%s]: %s\n", outputErr.Code, outputErr.Message)
			return 1
		}
		_ = renderer.RenderEnvelope(output.NewEnvelope(currentPlatform(), time.Now(), time.Now(), output.Summary{}, nil, outputErr))
		return 1
	}

	return 0
}

func currentPlatform() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}

	return runtime.GOOS
}
