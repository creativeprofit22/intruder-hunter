package check

import (
	"context"

	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

// Platform identifies an operating system supported by Intruder Hunter checks.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "macos"
	PlatformWindows Platform = "windows"
)

// Category identifies the current diagnostic module a check belongs to.
type Category string

const (
	CategorySystem          Category = "system"
	CategoryProcesses       Category = "processes"
	CategoryNetwork         Category = "network"
	CategoryUsers           Category = "users"
	CategoryMalware         Category = "malware"
	CategorySecurity        Category = "security"
	CategoryVulnerabilities Category = "vulnerabilities"
	CategoryLogs            Category = "logs"
	CategoryDefender        Category = "defender"
	CategoryScheduledTasks  Category = "scheduled_tasks"
	CategoryHardening       Category = "hardening"
)

// Check is the core contract implemented by all Go-native diagnostics.
type Check interface {
	ID() string
	Title() string
	Category() Category
	Platforms() []Platform
	RequiresAdmin() bool
	Run(ctx context.Context, checkCtx Context) ([]report.Finding, error)
}

// SupportsPlatform reports whether check declares support for platform.
func SupportsPlatform(check Check, platform Platform) bool {
	if check == nil {
		return false
	}

	for _, supported := range check.Platforms() {
		if supported == platform {
			return true
		}
	}
	return false
}
