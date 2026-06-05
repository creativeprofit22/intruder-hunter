package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// ErrCommandNotFound is returned when a command cannot be resolved on PATH.
var ErrCommandNotFound = errors.New("command not found")

// Options controls command execution.
type Options struct {
	// Stdin is connected to the child process when non-nil.
	Stdin io.Reader

	// Stdout and Stderr receive live copies of the child streams when non-nil.
	// Output is always captured in Result.Stdout and Result.Stderr.
	Stdout io.Writer
	Stderr io.Writer

	// Timeout bounds command execution when greater than zero.
	Timeout time.Duration

	// Env replaces the inherited process environment when non-nil.
	Env []string

	// Dir sets the child process working directory when non-empty.
	Dir string
}

// Result describes a completed command attempt.
type Result struct {
	Command  string
	Args     []string
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
	TimedOut bool
}

// Run executes name directly with args. It resolves the binary with exec.LookPath
// and never invokes a shell, so callers must pass arguments exactly as intended.
func Run(ctx context.Context, name string, args []string, opts Options) (*Result, error) {
	if ctx == nil {
		return nil, errors.New("runner.Run: nil context")
	}
	if name == "" {
		return nil, errors.New("runner.Run: empty command name")
	}

	resolved, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCommandNotFound, name)
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	cmdArgs := append([]string(nil), args...)
	cmd := exec.CommandContext(runCtx, resolved, cmdArgs...)
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}
	if opts.Env != nil {
		cmd.Env = append([]string(nil), opts.Env...)
	}
	if opts.Dir != "" {
		cmd.Dir = opts.Dir
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}

	var stdoutBuf bytes.Buffer
	stdoutSink := io.Writer(&stdoutBuf)
	if opts.Stdout != nil {
		stdoutSink = io.MultiWriter(&stdoutBuf, opts.Stdout)
	}

	var stderrBuf bytes.Buffer
	stderrSink := io.Writer(&stderrBuf)
	if opts.Stderr != nil {
		stderrSink = io.MultiWriter(&stderrBuf, opts.Stderr)
	}

	startedAt := time.Now()
	if err := cmd.Start(); err != nil {
		return &Result{
			Command:  resolved,
			Args:     cmdArgs,
			ExitCode: -1,
			Duration: time.Since(startedAt),
		}, fmt.Errorf("start %s: %w", resolved, err)
	}

	var drains sync.WaitGroup
	drains.Add(2)
	go func() {
		defer drains.Done()
		_, _ = io.Copy(stdoutSink, stdoutPipe)
	}()
	go func() {
		defer drains.Done()
		_, _ = io.Copy(stderrSink, stderrPipe)
	}()

	waitErr := cmd.Wait()
	drains.Wait()

	result := &Result{
		Command:  resolved,
		Args:     cmdArgs,
		Stdout:   stdoutBuf.Bytes(),
		Stderr:   stderrBuf.Bytes(),
		ExitCode: 0,
		Duration: time.Since(startedAt),
		TimedOut: errors.Is(runCtx.Err(), context.DeadlineExceeded),
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	if waitErr != nil {
		if result.TimedOut {
			return result, fmt.Errorf("command %s timed out after %s", name, opts.Timeout)
		}
		return result, fmt.Errorf("command %s failed: %w", name, waitErr)
	}

	return result, nil
}
