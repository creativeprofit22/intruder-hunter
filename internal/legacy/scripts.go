package legacy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/creativeprofit22/intruder-hunter/internal/runner"
)

const (
	LinuxScript   Script = "linux-script"
	MacOSScript   Script = "macos-script"
	WindowsScript Script = "windows-script"
)

// Script identifies one of the legacy platform scripts retained during the Go CLI migration.
type Script string

// AdminStatus describes whether the current process has the privilege needed by a legacy script.
type AdminStatus struct {
	Available bool
	Evidence  string
	Shell     string
}

// AdminChecker supplies privilege checks for the target platform.
type AdminChecker func(ctx context.Context, platform string) (AdminStatus, error)

// Runner executes the selected legacy script through the shared command runner.
type Runner func(ctx context.Context, name string, args []string, opts runner.Options) (*runner.Result, error)

// PowerShellResolver selects the PowerShell executable used for Windows legacy scripts.
type PowerShellResolver func(ctx context.Context) (string, error)

// Config controls legacy script execution. Empty fields use safe OS defaults.
type Config struct {
	Platform           string
	RepoRoot           string
	Stdin              io.Reader
	Stdout             io.Writer
	Stderr             io.Writer
	AdminChecker       AdminChecker
	Runner             Runner
	PowerShellResolver PowerShellResolver
}

type scriptSpec struct {
	Script       Script
	Platform     string
	RelativePath string
	Command      func(scriptPath string) (string, []string)
}

var scripts = map[Script]scriptSpec{
	LinuxScript: {
		Script:       LinuxScript,
		Platform:     "linux",
		RelativePath: "intruder-hunter.sh",
		Command: func(scriptPath string) (string, []string) {
			return "bash", []string{scriptPath}
		},
	},
	MacOSScript: {
		Script:       MacOSScript,
		Platform:     "macos",
		RelativePath: "intruder-hunter-macos.sh",
		Command: func(scriptPath string) (string, []string) {
			return "bash", []string{scriptPath}
		},
	},
	WindowsScript: {
		Script:       WindowsScript,
		Platform:     "windows",
		RelativePath: "intruder-hunter.ps1",
		Command: func(scriptPath string) (string, []string) {
			return "powershell.exe", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath}
		},
	},
}

// RunScript verifies platform and privilege requirements, then streams the requested legacy script.
// It never passes automatic hardening answers; any hardening prompt remains controlled by the user.
func RunScript(ctx context.Context, script Script, config Config) (*runner.Result, error) {
	if ctx == nil {
		return nil, errors.New("legacy: nil context")
	}

	spec, ok := scripts[script]
	if !ok {
		return nil, fmt.Errorf("legacy: unknown script %q", script)
	}

	platform := normalizePlatform(config.Platform)
	if platform == "" {
		platform = normalizePlatform(runtime.GOOS)
	}
	if platform != spec.Platform {
		return nil, fmt.Errorf("legacy %s requires %s; current platform is %s", spec.Script, spec.Platform, platform)
	}

	adminChecker := config.AdminChecker
	if adminChecker == nil {
		adminChecker = DefaultAdminChecker
	}
	adminStatus, err := adminChecker(ctx, platform)
	if err != nil {
		return nil, fmt.Errorf("legacy %s admin check failed: %w", spec.Script, err)
	}
	if !adminStatus.Available {
		detail := strings.TrimSpace(adminStatus.Evidence)
		if detail == "" {
			detail = "administrator/root privileges were not detected"
		}
		return nil, fmt.Errorf("legacy %s requires administrator/root privileges: %s", spec.Script, detail)
	}

	repoRoot := strings.TrimSpace(config.RepoRoot)
	if repoRoot == "" {
		repoRoot, err = findRepoRoot(spec.RelativePath)
		if err != nil {
			return nil, err
		}
	}
	repoRoot, err = filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("legacy: resolve repository root: %w", err)
	}

	scriptPath := filepath.Join(repoRoot, spec.RelativePath)
	info, err := os.Stat(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("legacy %s script not found at %s: %w", spec.Script, scriptPath, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("legacy %s script path is a directory: %s", spec.Script, scriptPath)
	}

	name, args := spec.Command(scriptPath)
	if spec.Script == WindowsScript {
		name, err = windowsScriptShell(ctx, adminStatus, config.PowerShellResolver)
		if err != nil {
			return nil, err
		}
	}
	run := config.Runner
	if run == nil {
		run = runner.Run
	}

	return run(ctx, name, args, runner.Options{
		Dir:    repoRoot,
		Stdin:  config.Stdin,
		Stdout: config.Stdout,
		Stderr: config.Stderr,
	})
}

// DefaultAdminChecker performs local privilege checks for legacy scripts.
func DefaultAdminChecker(ctx context.Context, platform string) (AdminStatus, error) {
	switch normalizePlatform(platform) {
	case "linux", "macos":
		if os.Geteuid() == 0 {
			return AdminStatus{Available: true, Evidence: "effective user id is 0"}, nil
		}
		return AdminStatus{Available: false, Evidence: fmt.Sprintf("effective user id is %d", os.Geteuid())}, nil
	case "windows":
		return windowsAdminStatus(ctx)
	default:
		return AdminStatus{Available: false, Evidence: fmt.Sprintf("unsupported platform %q", platform)}, nil
	}
}

func windowsAdminStatus(ctx context.Context) (AdminStatus, error) {
	command := "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
	for _, shell := range powerShellCandidates() {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		result, err := runner.Run(probeCtx, shell, []string{"-NoProfile", "-NonInteractive", "-Command", command}, runner.Options{})
		cancel()
		if errors.Is(err, runner.ErrCommandNotFound) {
			continue
		}
		if err != nil {
			continue
		}

		switch strings.TrimSpace(strings.ToLower(string(result.Stdout))) {
		case "true":
			return AdminStatus{Available: true, Evidence: fmt.Sprintf("%s reports Administrator role", shell), Shell: shell}, nil
		case "false":
			return AdminStatus{Available: false, Evidence: fmt.Sprintf("%s reports non-Administrator role", shell), Shell: shell}, nil
		}

	}

	return AdminStatus{Available: false, Evidence: "PowerShell administrator probe was unavailable"}, nil
}

func windowsScriptShell(ctx context.Context, adminStatus AdminStatus, resolve PowerShellResolver) (string, error) {
	if shell := strings.TrimSpace(adminStatus.Shell); shell != "" {
		return shell, nil
	}
	if resolve == nil {
		resolve = resolvePowerShell
	}
	shell, err := resolve(ctx)
	if err != nil {
		return "", fmt.Errorf("legacy %s PowerShell command not found: %w", WindowsScript, err)
	}
	return shell, nil
}

func resolvePowerShell(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", errors.New("legacy: nil context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for _, shell := range powerShellCandidates() {
		path, err := exec.LookPath(shell)
		if err == nil {
			return path, nil
		}
	}
	return "", runner.ErrCommandNotFound
}

func powerShellCandidates() []string {
	return []string{"powershell.exe", "powershell", "pwsh.exe", "pwsh"}
}

func findRepoRoot(scriptPath string) (string, error) {
	start, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("legacy: get working directory: %w", err)
	}

	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("legacy: resolve working directory: %w", err)
	}

	for {
		candidate := filepath.Join(dir, scriptPath)
		info, statErr := os.Stat(candidate)
		if statErr == nil && !info.IsDir() {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("legacy: could not find %s from current directory; pass --repo-root", scriptPath)
}

func normalizePlatform(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "darwin", "mac", "macos", "osx":
		return "macos"
	case "windows", "win32":
		return "windows"
	case "linux":
		return "linux"
	default:
		return strings.ToLower(strings.TrimSpace(platform))
	}
}
