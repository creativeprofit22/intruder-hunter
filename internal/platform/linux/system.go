package linux

import (
	"context"
	"os"
	"runtime"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type systemCheck struct{ linuxCheck }

func (systemCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	base := linuxCheck{id: "linux.system.info", title: "Linux system information", category: check.CategorySystem}
	osName := readOSRelease()
	hostname, _ := os.Hostname()
	kernel, err := commandOutput(ctx, checkCtx, "uname", "-r")
	if err != nil {
		kernel = "unknown"
	}
	uptime, err := commandOutput(ctx, checkCtx, "uptime", "-p")
	if err != nil {
		uptime = "unknown"
	}
	return []report.Finding{infoFinding(base.findingID("profile"), base.moduleName(), "system_profile", "Linux host profile collected", "Basic platform context was collected for interpreting other findings.", []string{"hostname=" + firstNonEmpty(hostname), "os=" + firstNonEmpty(osName), "kernel=" + strings.TrimSpace(kernel), "uptime=" + strings.TrimSpace(uptime), "arch=" + runtime.GOARCH})}, nil
}

func readOSRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	return "unknown"
}
