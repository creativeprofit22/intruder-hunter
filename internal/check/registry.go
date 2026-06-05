package check

import (
	"errors"
	"fmt"
	"sort"
)

// ErrDuplicateID indicates that two checks share the same stable ID.
var ErrDuplicateID = errors.New("duplicate check ID")

// Registry stores checks in deterministic execution order.
type Registry struct {
	checks []Check
}

// NewRegistry validates and orders checks by category, then stable ID.
func NewRegistry(checks ...Check) (*Registry, error) {
	ordered := append([]Check(nil), checks...)
	seen := make(map[string]struct{}, len(ordered))
	for _, check := range ordered {
		if check == nil {
			return nil, errors.New("nil check")
		}
		id := check.ID()
		if id == "" {
			return nil, errors.New("empty check ID")
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateID, id)
		}
		seen[id] = struct{}{}
	}

	sortChecks(ordered)
	return &Registry{checks: ordered}, nil
}

// MustRegistry builds a registry or panics. It is intended for package-level fixture wiring only.
func MustRegistry(checks ...Check) *Registry {
	registry, err := NewRegistry(checks...)
	if err != nil {
		panic(err)
	}
	return registry
}

// Checks returns all registered checks in deterministic order.
func (r *Registry) Checks() []Check {
	if r == nil {
		return nil
	}
	return append([]Check(nil), r.checks...)
}

// ForPlatform returns checks supporting platform in deterministic order.
func (r *Registry) ForPlatform(platform Platform) []Check {
	if r == nil {
		return nil
	}

	filtered := make([]Check, 0, len(r.checks))
	for _, check := range r.checks {
		if SupportsPlatform(check, platform) {
			filtered = append(filtered, check)
		}
	}
	return filtered
}

func sortChecks(checks []Check) {
	sort.SliceStable(checks, func(i, j int) bool {
		left := checks[i]
		right := checks[j]
		if left.Category() != right.Category() {
			return categoryRank(left.Category()) < categoryRank(right.Category())
		}
		return left.ID() < right.ID()
	})
}

func categoryRank(category Category) int {
	switch category {
	case CategorySystem:
		return 10
	case CategoryProcesses:
		return 20
	case CategoryNetwork:
		return 30
	case CategoryUsers:
		return 40
	case CategoryMalware:
		return 50
	case CategorySecurity:
		return 60
	case CategoryVulnerabilities:
		return 70
	case CategoryLogs:
		return 80
	case CategoryDefender:
		return 90
	case CategoryScheduledTasks:
		return 100
	case CategoryHardening:
		return 110
	default:
		return 1000
	}
}
