package macos

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type usersCheck struct{ macOSCheck }

func (c usersCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	findings := make([]report.Finding, 0, 4)
	if out, err := commandOutput(ctx, checkCtx, "dscl", ".", "-list", "/Users", "UserShell"); err == nil {
		findings = append(findings, shellUserFinding(c.macOSCheck, out))
	} else {
		findings = append(findings, commandInfoFinding(c.findingID("shell_users_unavailable"), c.moduleName(), "shell_users", "dscl", err))
	}
	if out, err := commandOutput(ctx, checkCtx, "dscl", ".", "-read", "/Groups/admin", "GroupMembership"); err == nil {
		findings = append(findings, adminUsersFinding(c.macOSCheck, out))
	} else {
		findings = append(findings, commandInfoFinding(c.findingID("admin_users_unavailable"), c.moduleName(), "admin_users", "dscl", err))
	}
	if out, err := commandOutput(ctx, checkCtx, "dscl", ".", "-list", "/Users"); err == nil {
		findings = append(findings, hiddenUsersFinding(c.macOSCheck, out))
	} else {
		findings = append(findings, commandInfoFinding(c.findingID("hidden_users_unavailable"), c.moduleName(), "hidden_users", "dscl", err))
	}
	findings = append(findings, sshKeysFinding(c.macOSCheck))
	return findings, nil
}

func shellUserFinding(base macOSCheck, output string) report.Finding {
	var users []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasSuffix(line, "/bin/bash") || strings.HasSuffix(line, "/bin/zsh") || strings.HasSuffix(line, "/bin/sh") {
			users = append(users, strings.TrimSpace(line))
		}
	}
	if len(users) == 0 {
		return okFinding(base.findingID("shell_users_none"), base.moduleName(), "shell_users", "No local shell users reported", "No users with bash, zsh, or sh shells were reported by dscl.", nil)
	}
	return infoFinding(base.findingID("shell_users"), base.moduleName(), "shell_users", "Users with shell access", "Review interactive shell users if unfamiliar.", limitLines(users, 30))
}

func adminUsersFinding(base macOSCheck, output string) report.Finding {
	output = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(output), "GroupMembership:"))
	admins := strings.Fields(output)
	if len(admins) > 2 {
		return finding(base.findingID("admin_users_many"), base.moduleName(), "admin_users", report.SeverityWarning, "Multiple admin users", fmt.Sprintf("%d admin group members were reported; this may be normal but should be reviewed.", len(admins)), admins, "Confirm each admin user is expected; do not remove accounts until ownership and recovery access are understood.", map[string]string{"confidence": "low"})
	}
	return okFinding(base.findingID("admin_users_ok"), base.moduleName(), "admin_users", "Admin user count is normal", fmt.Sprintf("%d admin group member(s) reported.", len(admins)), admins)
}

func hiddenUsersFinding(base macOSCheck, output string) report.Finding {
	var hidden []string
	for _, user := range strings.Fields(output) {
		if strings.HasPrefix(user, ".") && user != ".localized" {
			hidden = append(hidden, user)
		}
	}
	if len(hidden) == 0 {
		return okFinding(base.findingID("hidden_users_ok"), base.moduleName(), "hidden_users", "No hidden dot-prefixed users", "No dot-prefixed local user accounts were reported by dscl.", nil)
	}
	return finding(base.findingID("hidden_users"), base.moduleName(), "hidden_users", report.SeverityWarning, "Hidden user accounts found", "Dot-prefixed macOS user accounts can be legitimate but are unusual and should be reviewed.", hidden, "Confirm each hidden account is authorized before changing or deleting it.", map[string]string{"confidence": "medium"})
}

func sshKeysFinding(base macOSCheck) report.Finding {
	var evidence []string
	entries, err := os.ReadDir("/Users")
	if err != nil {
		return infoFinding(base.findingID("ssh_keys_unavailable"), base.moduleName(), "ssh_authorized_keys", "SSH key scan unavailable", "Could not enumerate /Users for authorized_keys files.", []string{err.Error()})
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join("/Users", entry.Name(), ".ssh", "authorized_keys")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				count++
			}
		}
		if count > 0 {
			evidence = append(evidence, fmt.Sprintf("%s: %d authorized key(s)", entry.Name(), count))
		}
	}
	if len(evidence) == 0 {
		return okFinding(base.findingID("ssh_keys_none"), base.moduleName(), "ssh_authorized_keys", "No SSH authorized keys found", "No non-empty authorized_keys files were found under /Users/*/.ssh.", nil)
	}
	return infoFinding(base.findingID("ssh_keys"), base.moduleName(), "ssh_authorized_keys", "SSH authorized keys found", "SSH keys are not inherently suspicious, but unexpected keys can provide persistent remote access.", evidence)
}
