package check

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type stubCheck struct {
	id            string
	title         string
	category      Category
	platforms     []Platform
	requiresAdmin bool
}

func (s stubCheck) ID() string {
	return s.id
}

func (s stubCheck) Title() string {
	return s.title
}

func (s stubCheck) Category() Category {
	return s.category
}

func (s stubCheck) Platforms() []Platform {
	return append([]Platform(nil), s.platforms...)
}

func (s stubCheck) RequiresAdmin() bool {
	return s.requiresAdmin
}

func (s stubCheck) Run(_ context.Context, _ Context) ([]report.Finding, error) {
	return nil, nil
}

func TestNewRegistryRejectsDuplicateIDs(t *testing.T) {
	_, err := NewRegistry(
		stubCheck{id: "linux.processes.miner", category: CategoryProcesses, platforms: []Platform{PlatformLinux}},
		stubCheck{id: "linux.processes.miner", category: CategoryNetwork, platforms: []Platform{PlatformLinux}},
	)
	if !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("NewRegistry() error = %v, want ErrDuplicateID", err)
	}
}

func TestRegistryForPlatformFiltersChecks(t *testing.T) {
	registry, err := NewRegistry(
		stubCheck{id: "macos.users.admin", category: CategoryUsers, platforms: []Platform{PlatformMacOS}},
		stubCheck{id: "linux.network.ssh", category: CategoryNetwork, platforms: []Platform{PlatformLinux}},
		stubCheck{id: "shared.processes.miner", category: CategoryProcesses, platforms: []Platform{PlatformLinux, PlatformMacOS}},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	got := checkIDs(registry.ForPlatform(PlatformLinux))
	want := []string{"shared.processes.miner", "linux.network.ssh"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ForPlatform(linux) = %v, want %v", got, want)
	}
}

func TestRegistryChecksUseStableModuleOrderingThenID(t *testing.T) {
	registry, err := NewRegistry(
		stubCheck{id: "linux.logs.failed-login", category: CategoryLogs, platforms: []Platform{PlatformLinux}},
		stubCheck{id: "linux.processes.zzz", category: CategoryProcesses, platforms: []Platform{PlatformLinux}},
		stubCheck{id: "linux.processes.aaa", category: CategoryProcesses, platforms: []Platform{PlatformLinux}},
		stubCheck{id: "linux.system.info", category: CategorySystem, platforms: []Platform{PlatformLinux}},
		stubCheck{id: "linux.network.ssh", category: CategoryNetwork, platforms: []Platform{PlatformLinux}},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	got := checkIDs(registry.Checks())
	want := []string{
		"linux.system.info",
		"linux.processes.aaa",
		"linux.processes.zzz",
		"linux.network.ssh",
		"linux.logs.failed-login",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Checks() = %v, want %v", got, want)
	}
}

func checkIDs(checks []Check) []string {
	ids := make([]string, 0, len(checks))
	for _, check := range checks {
		ids = append(ids, check.ID())
	}
	return ids
}
