package legacy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/creativeprofit22/intruder-hunter/internal/runner"
)

func TestRunScriptExecutesMatchingPlatformWithAdmin(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	writeLegacyScript(t, repoRoot, "intruder-hunter.sh")

	var gotName string
	var gotArgs []string
	var gotOptions runner.Options
	result, err := RunScript(context.Background(), LinuxScript, Config{
		Platform: "linux",
		RepoRoot: repoRoot,
		Stdin:    strings.NewReader("n\n"),
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		AdminChecker: func(ctx context.Context, platform string) (AdminStatus, error) {
			if platform != "linux" {
				t.Fatalf("admin platform = %q, want linux", platform)
			}
			return AdminStatus{Available: true, Evidence: "test admin"}, nil
		},
		Runner: func(ctx context.Context, name string, args []string, opts runner.Options) (*runner.Result, error) {
			gotName = name
			gotArgs = append([]string(nil), args...)
			gotOptions = opts
			return &runner.Result{Command: name, Args: args, ExitCode: 0}, nil
		},
	})
	if err != nil {
		t.Fatalf("RunScript() error = %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("RunScript() exit = %d, want 0", result.ExitCode)
	}
	if gotName != "bash" {
		t.Fatalf("command = %q, want bash", gotName)
	}
	wantScriptPath := filepath.Join(repoRoot, "intruder-hunter.sh")
	if len(gotArgs) != 1 || gotArgs[0] != wantScriptPath {
		t.Fatalf("args = %#v, want [%q]", gotArgs, wantScriptPath)
	}
	if gotOptions.Dir != repoRoot {
		t.Fatalf("Dir = %q, want %q", gotOptions.Dir, repoRoot)
	}
	if gotOptions.Stdin == nil || gotOptions.Stdout == nil || gotOptions.Stderr == nil {
		t.Fatalf("runner options did not preserve stdio: %#v", gotOptions)
	}
}

func TestRunScriptRejectsPlatformMismatch(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	writeLegacyScript(t, repoRoot, "intruder-hunter-macos.sh")

	_, err := RunScript(context.Background(), MacOSScript, Config{
		Platform: "linux",
		RepoRoot: repoRoot,
		AdminChecker: func(ctx context.Context, platform string) (AdminStatus, error) {
			return AdminStatus{Available: true}, nil
		},
		Runner: func(ctx context.Context, name string, args []string, opts runner.Options) (*runner.Result, error) {
			t.Fatal("runner should not be called for platform mismatch")
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("RunScript() error = nil, want platform mismatch")
	}
	if !strings.Contains(err.Error(), "requires macos") {
		t.Fatalf("RunScript() error = %q, want macos requirement", err)
	}
}

func TestRunScriptRequiresAdmin(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	writeLegacyScript(t, repoRoot, "intruder-hunter.sh")

	_, err := RunScript(context.Background(), LinuxScript, Config{
		Platform: "linux",
		RepoRoot: repoRoot,
		AdminChecker: func(ctx context.Context, platform string) (AdminStatus, error) {
			return AdminStatus{Available: false, Evidence: "effective user id is 1000"}, nil
		},
		Runner: func(ctx context.Context, name string, args []string, opts runner.Options) (*runner.Result, error) {
			t.Fatal("runner should not be called without admin")
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("RunScript() error = nil, want admin requirement")
	}
	if !strings.Contains(err.Error(), "requires administrator/root privileges") {
		t.Fatalf("RunScript() error = %q, want admin requirement", err)
	}
}

func TestRunScriptPropagatesAdminCheckError(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	writeLegacyScript(t, repoRoot, "intruder-hunter.sh")
	wantErr := errors.New("probe failed")

	_, err := RunScript(context.Background(), LinuxScript, Config{
		Platform: "linux",
		RepoRoot: repoRoot,
		AdminChecker: func(ctx context.Context, platform string) (AdminStatus, error) {
			return AdminStatus{}, wantErr
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("RunScript() error = %v, want wrapped %v", err, wantErr)
	}
}

func TestRunScriptRequiresExistingScript(t *testing.T) {
	t.Parallel()

	_, err := RunScript(context.Background(), LinuxScript, Config{
		Platform: "linux",
		RepoRoot: t.TempDir(),
		AdminChecker: func(ctx context.Context, platform string) (AdminStatus, error) {
			return AdminStatus{Available: true}, nil
		},
	})
	if err == nil {
		t.Fatal("RunScript() error = nil, want missing script")
	}
	if !strings.Contains(err.Error(), "script not found") {
		t.Fatalf("RunScript() error = %q, want missing script", err)
	}
}

func TestWindowsAdminStatusFallsBackToPwsh(t *testing.T) {
	binDir := t.TempDir()
	writeFakeCommand(t, binDir, "pwsh", "#!/bin/sh\nprintf 'true\\n'\n")
	t.Setenv("PATH", binDir)

	status, err := windowsAdminStatus(context.Background())
	if err != nil {
		t.Fatalf("windowsAdminStatus() error = %v", err)
	}
	if !status.Available {
		t.Fatalf("windowsAdminStatus() available = false, want true; evidence=%q", status.Evidence)
	}
	if status.Shell != "pwsh" {
		t.Fatalf("windowsAdminStatus() shell = %q, want pwsh", status.Shell)
	}
}

func TestRunScriptSelectsWindowsPowerShellCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		adminShell string
		wantName   string
	}{
		{name: "default", wantName: "powershell.exe"},
		{name: "admin probe shell", adminShell: "pwsh", wantName: "pwsh"},
		{name: "trimmed admin probe shell", adminShell: " powershell ", wantName: "powershell"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repoRoot := t.TempDir()
			writeLegacyScript(t, repoRoot, "intruder-hunter.ps1")

			var gotName string
			var gotArgs []string
			_, err := RunScript(context.Background(), WindowsScript, Config{
				Platform: "windows",
				RepoRoot: repoRoot,
				AdminChecker: func(ctx context.Context, platform string) (AdminStatus, error) {
					return AdminStatus{Available: true, Shell: test.adminShell}, nil
				},
				PowerShellResolver: func(ctx context.Context) (string, error) {
					return "powershell.exe", nil
				},
				Runner: func(ctx context.Context, name string, args []string, opts runner.Options) (*runner.Result, error) {
					gotName = name
					gotArgs = append([]string(nil), args...)
					return &runner.Result{Command: name, Args: args, ExitCode: 0}, nil
				},
			})
			if err != nil {
				t.Fatalf("RunScript() error = %v", err)
			}
			if gotName != test.wantName {
				t.Fatalf("command = %q, want %s", gotName, test.wantName)
			}
			wantScriptPath := filepath.Join(repoRoot, "intruder-hunter.ps1")
			if len(gotArgs) != 5 || gotArgs[0] != "-NoProfile" || gotArgs[3] != "-File" || gotArgs[4] != wantScriptPath {
				t.Fatalf("args = %#v, want PowerShell invocation ending with %q", gotArgs, wantScriptPath)
			}
		})
	}
}

func writeLegacyScript(t *testing.T, repoRoot string, relativePath string) {
	t.Helper()
	path := filepath.Join(repoRoot, relativePath)
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\necho legacy\n"), 0o755); err != nil {
		t.Fatalf("write script fixture: %v", err)
	}
}

func writeFakeCommand(t *testing.T, dir string, name string, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
}
