package check

import (
	"context"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/output"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
	"github.com/creativeprofit22/intruder-hunter/internal/runner"
)

// CommandRunner executes external commands for checks without relying on package globals.
type CommandRunner interface {
	Run(ctx context.Context, name string, args []string, opts runner.Options) (*runner.Result, error)
}

// CommandRunnerFunc adapts a function to CommandRunner.
type CommandRunnerFunc func(ctx context.Context, name string, args []string, opts runner.Options) (*runner.Result, error)

func (f CommandRunnerFunc) Run(ctx context.Context, name string, args []string, opts runner.Options) (*runner.Result, error) {
	return f(ctx, name, args, opts)
}

// Clock supplies timestamps for deterministic tests and reports.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time {
	return f()
}

// OutputOptions captures output choices needed by checks and report assembly.
type OutputOptions struct {
	Format     string
	ReportPath string
}

// ReportOptions captures report metadata shared by checks.
type ReportOptions struct {
	SchemaVersion string
	Tool          string
	Platform      Platform
}

// Context carries check dependencies and run metadata explicitly.
type Context struct {
	Runner    CommandRunner
	Clock     Clock
	StartedAt time.Time
	Output    OutputOptions
	Report    ReportOptions
}

// ContextOptions configures a check Context.
type ContextOptions struct {
	Runner    CommandRunner
	Clock     Clock
	StartedAt time.Time
	Output    OutputOptions
	Report    ReportOptions
}

// NewContext builds a check context with explicit, overridable dependencies.
func NewContext(opts ContextOptions) Context {
	clock := opts.Clock
	if clock == nil {
		clock = ClockFunc(time.Now)
	}

	run := opts.Runner
	if run == nil {
		run = CommandRunnerFunc(runner.Run)
	}

	startedAt := opts.StartedAt
	if startedAt.IsZero() {
		startedAt = clock.Now()
	}

	reportOpts := opts.Report
	if reportOpts.SchemaVersion == "" {
		reportOpts.SchemaVersion = report.SchemaVersion
	}
	if reportOpts.Tool == "" {
		reportOpts.Tool = report.ToolName
	}

	outputOpts := opts.Output
	if outputOpts.Format == "" {
		outputOpts.Format = output.FormatText
	}

	return Context{
		Runner:    run,
		Clock:     clock,
		StartedAt: startedAt.UTC(),
		Output:    outputOpts,
		Report:    reportOpts,
	}
}
