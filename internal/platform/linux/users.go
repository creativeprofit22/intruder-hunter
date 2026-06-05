package linux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type usersCheck struct{ linuxCheck }

type passwdUser struct {
	Name  string
	UID   string
	Home  string
	Shell string
}

func (usersCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	_ = ctx
	_ = checkCtx
	base := linuxCheck{id: "linux.users.accounts", title: "Linux users and authentication", category: check.CategoryUsers}
	users := readPasswdUsers()
	findings := make([]report.Finding, 0, 6)
	rootUsers := make([]string, 0)
	shellUsers := make([]string, 0)
	for _, user := range users {
		if user.UID == "0" {
			rootUsers = append(rootUsers, user.Name)
		}
		if hasLoginShell(user.Shell) {
			shellUsers = append(shellUsers, fmt.Sprintf("%s uid=%s shell=%s", user.Name, user.UID, user.Shell))
		}
	}
	if len(rootUsers) > 1 {
		findings = append(findings, finding(base.findingID("multiple_uid0"), base.moduleName(), "uid0_users", report.SeverityCritical, "Multiple UID 0 accounts", "More than one account has root-equivalent UID 0.", rootUsers, "Investigate every UID 0 account and remove or lock unexpected root-equivalent users after validating system requirements.", map[string]string{"confidence": "high"}))
	} else {
		findings = append(findings, okFinding(base.findingID("uid0_ok"), base.moduleName(), "uid0_users", "UID 0 account baseline", "Only the expected root-equivalent account was found.", rootUsers))
	}
	findings = append(findings, infoFinding(base.findingID("shell_users"), base.moduleName(), "shell_users", "Users with login shells", fmt.Sprintf("Found %d account(s) with common login shells.", len(shellUsers)), shellUsers))

	if sudoUsers := readSudoUsers(); len(sudoUsers) > 0 {
		findings = append(findings, infoFinding(base.findingID("sudo_users"), base.moduleName(), "sudo_users", "Sudo-capable users", "Users in sudo or wheel groups were found.", sudoUsers))
	}
	if nopasswd := grepReadableFiles([]string{"/etc/sudoers", "/etc/sudoers.d"}, "NOPASSWD"); len(nopasswd) > 0 {
		findings = append(findings, finding(base.findingID("nopasswd"), base.moduleName(), "sudoers_nopasswd", report.SeverityWarning, "Passwordless sudo entries found", "NOPASSWD can be legitimate automation, but it weakens local privilege boundaries if broad or unexpected.", nopasswd, "Review whether each NOPASSWD entry is scoped to a specific command and required by policy.", map[string]string{"confidence": "medium"}))
	} else {
		findings = append(findings, okFinding(base.findingID("nopasswd_ok"), base.moduleName(), "sudoers_nopasswd", "No NOPASSWD entries found", "No uncommented NOPASSWD sudoers lines were readable and found.", nil))
	}
	if keys := authorizedKeySummary(users); len(keys) > 0 {
		findings = append(findings, infoFinding(base.findingID("ssh_keys"), base.moduleName(), "ssh_authorized_keys", "SSH authorized keys present", "Authorized key files were found; unexpected keys can enable persistent access.", keys))
	} else {
		findings = append(findings, okFinding(base.findingID("ssh_keys_none"), base.moduleName(), "ssh_authorized_keys", "No SSH authorized keys found", "No non-empty authorized_keys files were found in common home directories.", nil))
	}
	return findings, nil
}

func readPasswdUsers() []passwdUser {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	var users []passwdUser
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 7 {
			users = append(users, passwdUser{Name: parts[0], UID: parts[2], Home: parts[5], Shell: parts[6]})
		}
	}
	return users
}

func hasLoginShell(shell string) bool {
	return strings.HasSuffix(shell, "/bash") || strings.HasSuffix(shell, "/sh") || strings.HasSuffix(shell, "/zsh")
}

func readSudoUsers() []string {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil
	}

	wanted := map[string]struct{}{"sudo": {}, "wheel": {}}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		if _, ok := wanted[parts[0]]; ok && strings.TrimSpace(parts[3]) != "" {
			out = append(out, parts[0]+":"+parts[3])
		}
	}
	return out
}

func grepReadableFiles(paths []string, needle string) []string {
	var out []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			_ = filepath.WalkDir(path, func(child string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					out = append(out, grepFile(child, needle)...)
				}
				return nil
			})
			continue
		}
		out = append(out, grepFile(path, needle)...)
	}
	return out
}

func grepFile(path, needle string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, needle) {
			out = append(out, path+":"+trimmed)
		}
	}
	return out
}

func authorizedKeySummary(users []passwdUser) []string {
	seen := map[string]struct{}{}
	var homes []string
	for _, user := range users {
		if user.Home != "" && user.Home != "/" {
			homes = append(homes, user.Name+":"+user.Home)
		}
	}
	homes = append(homes, "root:/root")
	var out []string
	for _, entry := range homes {
		parts := strings.SplitN(entry, ":", 2)
		path := filepath.Join(parts[1], ".ssh", "authorized_keys")
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				count++
			}
		}
		if count > 0 {
			out = append(out, fmt.Sprintf("%s: %d key(s)", parts[0], count))
		}
	}
	return out
}
