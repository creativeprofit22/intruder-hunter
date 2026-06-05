package cli

import (
	"fmt"
	"os"

	"github.com/creativeprofit22/intruder-hunter/internal/legacy"
	"github.com/spf13/cobra"
)

func newLegacyCommand() *cobra.Command {
	var repoRoot string

	cmd := &cobra.Command{
		Use:   "legacy",
		Short: "Run retained platform scripts during Go CLI migration",
		Long:  "Run retained platform scripts during Go CLI migration. Legacy scripts are interactive and may offer optional hardening; the Go CLI does not auto-accept those prompts.",
	}
	cmd.PersistentFlags().StringVar(&repoRoot, "repo-root", "", "repository root containing the legacy scripts")

	cmd.AddCommand(newLegacyScriptCommand(&repoRoot, legacy.LinuxScript, "Run the retained Linux Bash script"))
	cmd.AddCommand(newLegacyScriptCommand(&repoRoot, legacy.MacOSScript, "Run the retained macOS Bash script"))
	cmd.AddCommand(newLegacyScriptCommand(&repoRoot, legacy.WindowsScript, "Run the retained Windows PowerShell script"))

	return cmd
}

func newLegacyScriptCommand(repoRoot *string, script legacy.Script, short string) *cobra.Command {
	return &cobra.Command{
		Use:   string(script),
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.ErrOrStderr(), "Running legacy %s. Do not approve hardening prompts unless you understand the changes.\n", script)
			if err != nil {
				return err
			}

			_, err = legacy.RunScript(cmd.Context(), script, legacy.Config{
				RepoRoot: *repoRoot,
				Stdin:    os.Stdin,
				Stdout:   cmd.OutOrStdout(),
				Stderr:   cmd.ErrOrStderr(),
			})
			return err
		},
	}
}
