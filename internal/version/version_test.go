package version

import (
	"strings"
	"testing"
)

func TestVersionDefaultsAreRenderable(t *testing.T) {
	if Name != "intruder-hunter" {
		t.Fatalf("Name = %q, want intruder-hunter", Name)
	}
	if strings.TrimSpace(Version) == "" {
		t.Fatal("Version is empty")
	}
	if strings.TrimSpace(Commit) == "" {
		t.Fatal("Commit is empty")
	}
}
