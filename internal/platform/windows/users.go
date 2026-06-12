package windows

import (
	"context"
	"fmt"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type usersCheck struct{ windowsCheck }

type windowsUserState struct {
	Administrators []string           `json:"Administrators"`
	Users          []windowsLocalUser `json:"Users"`
}

type windowsLocalUser struct {
	Name        string `json:"Name"`
	Enabled     bool   `json:"Enabled"`
	SID         string `json:"SID"`
	Description string `json:"Description"`
	LastLogon   string `json:"LastLogon"`
}

const usersScript = `$admins = @(Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }); if (-not $admins) { $admins = @(Get-LocalGroupMember -Group Administradores -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }; $users = @(Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,SID,Description,LastLogon); [pscustomobject]@{ Administrators=$admins; Users=$users } | ConvertTo-Json -Compress -Depth 4`

func (c usersCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	out, err := powerShellOutput(ctx, checkCtx, usersScript)
	if err != nil {
		return []report.Finding{commandInfoFinding(c.findingID("powershell_unavailable"), c.moduleName(), "local_users", "powershell.exe", err)}, nil
	}
	state, err := parseWindowsUserState(out)
	if err != nil {
		return nil, err
	}
	findings := make([]report.Finding, 0, 4)
	if len(state.Administrators) > 0 {
		findings = append(findings, infoFinding(c.findingID("administrators"), c.moduleName(), "administrators", "Local administrators collected", "Review local administrator membership for unexpected users or groups.", state.Administrators))
		if len(state.Administrators) > 2 {
			findings = append(findings, finding(c.findingID("administrators_many"), c.moduleName(), "administrators", report.SeverityWarning, "Multiple local administrator principals", fmt.Sprintf("Local Administrators membership contains %d principals.", len(state.Administrators)), state.Administrators, "Review each administrator principal and remove unexpected membership only after validating business impact.", nil))
		}
	} else {
		findings = append(findings, finding(c.findingID("administrators_unreadable"), c.moduleName(), "administrators", report.SeverityWarning, "Local administrators could not be listed", "No local administrator members were returned; permissions or platform support may be limiting visibility.", nil, "Run PowerShell as Administrator if local account auditing is required.", nil))
	}
	flagged := 0
	for _, user := range state.Users {
		if strings.HasSuffix(user.Name, "$") || strings.HasPrefix(user.Name, ".") {
			flagged++
			findings = append(findings, finding(c.findingID("hidden_"+sanitizeID(user.Name)), c.moduleName(), "hidden_users", report.SeverityWarning, "Local user has hidden or machine-account style name", "A local user name starts with a dot or ends with '$', which deserves review if unexpected.", []string{formatWindowsUser(user)}, "Confirm the account owner and disable or remove only after validating business impact.", nil))
		}
	}
	if flagged == 0 {
		findings = append(findings, okFinding(c.findingID("hidden_users_ok"), c.moduleName(), "hidden_users", "No hidden-style local users found", "No local user names started with a dot or ended with '$'.", nil))
	}
	findings = append(findings, infoFinding(c.findingID("disabled_users"), c.moduleName(), "disabled_users", "Disabled local users summarized", "Disabled accounts may be normal; review privileged disabled accounts before re-enabling anything.", disabledWindowsUsers(state.Users)))
	return findings, nil
}

func parseWindowsUserState(output string) (windowsUserState, error) {
	return parseJSONValue[windowsUserState](output)
}

func formatWindowsUser(user windowsLocalUser) string {
	return fmt.Sprintf("name=%s enabled=%s sid=%s last_logon=%s description=%s", user.Name, boolWord(user.Enabled), user.SID, user.LastLogon, user.Description)
}

func disabledWindowsUsers(users []windowsLocalUser) []string {
	out := make([]string, 0, len(users))
	for _, user := range users {
		if !user.Enabled {
			out = append(out, formatWindowsUser(user))
		}
	}
	return limitEvidence(out, 10)
}

func sanitizeID(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
