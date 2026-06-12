package windows

import (
	"context"
	"fmt"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type systemCheck struct{ windowsCheck }

type windowsSystemInfo struct {
	Caption        string `json:"Caption"`
	Version        string `json:"Version"`
	BuildNumber    string `json:"BuildNumber"`
	InstallDate    string `json:"InstallDate"`
	LastBootUpTime string `json:"LastBootUpTime"`
	ComputerName   string `json:"ComputerName"`
	UserName       string `json:"UserName"`
}

const systemScript = `Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,InstallDate,LastBootUpTime,@{Name='ComputerName';Expression={$_.CSName}},@{Name='UserName';Expression={$env:USERNAME}} | ConvertTo-Json -Compress -Depth 3`

func (c systemCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	out, err := powerShellOutput(ctx, checkCtx, systemScript)
	if err != nil {
		return []report.Finding{commandInfoFinding(c.findingID("powershell_unavailable"), c.moduleName(), "system_info", "powershell.exe", err)}, nil
	}
	info, err := parseWindowsSystemInfo(out)
	if err != nil {
		return nil, err
	}
	return []report.Finding{infoFinding(c.findingID("os"), c.moduleName(), "system_info", "Windows system information collected", "Operating system version, build, current user, install date, and boot time were collected for scan context.", []string{fmt.Sprintf("computer=%s user=%s caption=%s version=%s build=%s install=%s last_boot=%s", info.ComputerName, info.UserName, info.Caption, info.Version, info.BuildNumber, info.InstallDate, info.LastBootUpTime)})}, nil
}

func parseWindowsSystemInfo(output string) (windowsSystemInfo, error) {
	return parseJSONValue[windowsSystemInfo](output)
}
