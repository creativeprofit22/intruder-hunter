package state

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// DirName is the private Intruder Hunter state directory rooted at the
	// caller-provided base directory.
	DirName = ".intruder-hunter"

	// RunsDirName stores immutable per-run snapshots.
	RunsDirName = "runs"

	// LatestDirName stores stable pointers or copies for consumers that only
	// need the newest report.
	LatestDirName = "latest"

	// RawDirName stores optional raw artifacts captured during a run.
	RawDirName = "raw"

	metadataFileName = "metadata.json"
	reportFileName   = "report.json"

	stateDirMode  = 0o700
	stateFileMode = 0o600
)

// Path returns the root Intruder Hunter state directory for baseDir.
func Path(baseDir string) string {
	return filepath.Join(baseDir, DirName)
}

// RunsPath returns the immutable run snapshot directory root for baseDir.
func RunsPath(baseDir string) string {
	return filepath.Join(Path(baseDir), RunsDirName)
}

// LatestPath returns the latest report directory for baseDir.
func LatestPath(baseDir string) string {
	return filepath.Join(Path(baseDir), LatestDirName)
}

func ensureDir(path string) error {
	if err := os.MkdirAll(path, stateDirMode); err != nil {
		return err
	}

	return os.Chmod(path, stateDirMode)
}

func writeJSONAtomic(path string, value any) error {
	body, err := marshalDeterministicJSON(value)
	if err != nil {
		return err
	}

	return writeFileAtomic(path, body)
}

func marshalDeterministicJSON(value any) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}

	return append(body, '\n'), nil
}

func writeFileAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(stateFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	cleanup = false
	fsyncDir(dir)
	return nil
}

func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer func() { _ = in.Close() }()

	dir := filepath.Dir(dst)
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(dst)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(stateFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	cleanup = false
	fsyncDir(dir)
	return nil
}

func fsyncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}

	handle, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = handle.Sync()
	_ = handle.Close()
}

func safeRelativePath(path string) (string, error) {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if cleaned == "." || cleaned == string(filepath.Separator) || filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("unsafe raw artifact path %q", path)
	}

	parts := strings.Split(cleaned, string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("unsafe raw artifact path %q", path)
		}
	}

	return cleaned, nil
}

func utcTimestamp(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC().Truncate(time.Second)
	}

	return t.UTC().Truncate(time.Second)
}
