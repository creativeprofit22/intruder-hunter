package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunSuccessCapturesStdoutAndOptions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stdout := &bytes.Buffer{}
	result, err := Run(context.Background(), os.Args[0], []string{"-test.run=TestHelperProcess", "--", "success"}, Options{
		Env:    helperEnv("success"),
		Dir:    dir,
		Stdin:  strings.NewReader("input-value"),
		Stdout: stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	want := "stdout:helper-value:" + dir + ":input-value\n"
	if string(result.Stdout) != want {
		t.Fatalf("Result.Stdout = %q, want %q", result.Stdout, want)
	}
	if stdout.String() != want {
		t.Fatalf("live stdout = %q, want %q", stdout.String(), want)
	}
	if len(result.Stderr) != 0 {
		t.Fatalf("Result.Stderr = %q, want empty", result.Stderr)
	}
	if result.ExitCode != 0 {
		t.Fatalf("Result.ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Duration <= 0 {
		t.Fatalf("Result.Duration = %s, want positive", result.Duration)
	}
	if result.TimedOut {
		t.Fatal("Result.TimedOut = true, want false")
	}
	if filepath.Base(result.Command) != filepath.Base(os.Args[0]) {
		t.Fatalf("Result.Command = %q, want test binary path", result.Command)
	}
	if got, want := result.Args, []string{"-test.run=TestHelperProcess", "--", "success"}; !equalStrings(got, want) {
		t.Fatalf("Result.Args = %#v, want %#v", got, want)
	}
}

func TestRunCapturesStderr(t *testing.T) {
	t.Parallel()

	stderr := &bytes.Buffer{}
	result, err := Run(context.Background(), os.Args[0], []string{"-test.run=TestHelperProcess", "--", "stderr"}, Options{
		Env:    helperEnv("stderr"),
		Stderr: stderr,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if string(result.Stderr) != "stderr:diagnostic\n" {
		t.Fatalf("Result.Stderr = %q, want diagnostic", result.Stderr)
	}
	if stderr.String() != "stderr:diagnostic\n" {
		t.Fatalf("live stderr = %q, want diagnostic", stderr.String())
	}
	if result.ExitCode != 0 {
		t.Fatalf("Result.ExitCode = %d, want 0", result.ExitCode)
	}
}

func TestRunCommandNotFound(t *testing.T) {
	t.Parallel()

	result, err := Run(context.Background(), "intruder-hunter-command-that-does-not-exist", nil, Options{})
	if err == nil {
		t.Fatal("Run() error = nil, want command-not-found error")
	}
	if !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("Run() error = %v, want ErrCommandNotFound", err)
	}
	if result != nil {
		t.Fatalf("Run() result = %#v, want nil", result)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	t.Parallel()

	result, err := Run(context.Background(), os.Args[0], []string{"-test.run=TestHelperProcess", "--", "exit", "17"}, Options{
		Env: helperEnv("exit"),
	})
	if err == nil {
		t.Fatal("Run() error = nil, want non-zero exit error")
	}
	if result == nil {
		t.Fatal("Run() result = nil, want populated result")
	}
	if result.ExitCode != 17 {
		t.Fatalf("Result.ExitCode = %d, want 17", result.ExitCode)
	}
	if result.TimedOut {
		t.Fatal("Result.TimedOut = true, want false")
	}
}

func TestRunTimeout(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("helper-process timeout behavior is timing-sensitive on Windows")
	}

	result, err := Run(context.Background(), os.Args[0], []string{"-test.run=TestHelperProcess", "--", "sleep", "5s"}, Options{
		Env:     helperEnv("sleep"),
		Timeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Run() error = nil, want timeout error")
	}
	if result == nil {
		t.Fatal("Run() result = nil, want populated result")
	}
	if !result.TimedOut {
		t.Fatal("Result.TimedOut = false, want true")
	}
	if result.ExitCode == 0 {
		t.Fatalf("Result.ExitCode = %d, want non-zero", result.ExitCode)
	}
	if result.Duration <= 0 {
		t.Fatalf("Result.Duration = %s, want positive", result.Duration)
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	args := os.Args
	separator := -1
	for index, arg := range args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator == -1 || separator+1 >= len(args) {
		os.Exit(2)
	}

	switch args[separator+1] {
	case "success":
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			_, _ = os.Stderr.WriteString(err.Error())
			os.Exit(2)
		}
		_, _ = os.Stdout.WriteString("stdout:" + os.Getenv("HELPER_VALUE") + ":" + mustGetwd() + ":" + string(stdin) + "\n")
	case "stderr":
		_, _ = os.Stderr.WriteString("stderr:diagnostic\n")
	case "exit":
		code, err := strconv.Atoi(args[separator+2])
		if err != nil {
			os.Exit(2)
		}
		os.Exit(code)
	case "sleep":
		duration, err := time.ParseDuration(args[separator+2])
		if err != nil {
			os.Exit(2)
		}
		time.Sleep(duration)
	default:
		os.Exit(2)
	}

	os.Exit(0)
}

func helperEnv(mode string) []string {
	return append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"HELPER_MODE="+mode,
		"HELPER_VALUE=helper-value",
	)
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error())
		os.Exit(2)
	}
	return wd
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
