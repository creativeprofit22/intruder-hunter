package linux

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type vulnerabilitiesCheck struct{ linuxCheck }

type updateCount struct {
	Manager string
	Count   int
	Known   bool
}

func (vulnerabilitiesCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	base := linuxCheck{id: "linux.vulnerabilities.posture", title: "Linux vulnerability posture", category: check.CategoryVulnerabilities}
	findings := make([]report.Finding, 0, 4)
	findings = append(findings, updateFinding(ctx, checkCtx, base))
	findings = append(findings, firewallFinding(ctx, checkCtx, base))
	findings = append(findings, sshConfigFindings(base)...)
	return findings, nil
}

func updateFinding(ctx context.Context, checkCtx check.Context, base linuxCheck) report.Finding {
	for _, manager := range []string{"apt", "dnf", "yum", "pacman"} {
		count, err := collectUpdateCount(ctx, checkCtx, manager)
		if err != nil || !count.Known {
			continue
		}
		if count.Count > 10 {
			return finding(base.findingID("updates_many"), base.moduleName(), "package_updates", report.SeverityWarning, "Many package updates appear pending", fmt.Sprintf("%s reports %d pending package update(s). This is a hygiene signal, not proof of compromise.", manager, count.Count), nil, "Plan updates with backups and a maintenance window appropriate for this system.", map[string]string{"manager": manager, "count": fmt.Sprint(count.Count)})
		}
		if count.Count > 0 {
			return infoFinding(base.findingID("updates_some"), base.moduleName(), "package_updates", "Package updates appear pending", fmt.Sprintf("%s reports %d pending package update(s).", manager, count.Count), nil)
		}
		return okFinding(base.findingID("updates_none"), base.moduleName(), "package_updates", "No package updates reported", manager+" did not report pending updates using a non-mutating check.", nil)
	}
	return infoFinding(base.findingID("updates_unsupported"), base.moduleName(), "package_updates", "No supported package manager detected", "Could not check updates because apt, dnf, yum, and pacman were unavailable or unsupported on this host.", nil)
}

func collectUpdateCount(ctx context.Context, checkCtx check.Context, manager string) (updateCount, error) {
	switch manager {
	case "apt":
		out, err := commandOutput(ctx, checkCtx, "apt", "list", "--upgradable")
		return parseUpdateCount("apt", out), err
	case "dnf":
		out, err := commandOutput(ctx, checkCtx, "dnf", "check-update", "--quiet")
		if err != nil && strings.TrimSpace(out) == "" {
			return updateCount{Manager: manager}, err
		}
		return parseUpdateCount("dnf", out), nil
	case "yum":
		out, err := commandOutput(ctx, checkCtx, "yum", "check-update", "--quiet")
		if err != nil && strings.TrimSpace(out) == "" {
			return updateCount{Manager: manager}, err
		}
		return parseUpdateCount("yum", out), nil
	case "pacman":
		out, err := commandOutput(ctx, checkCtx, "pacman", "-Qu")
		return parseUpdateCount("pacman", out), err
	default:
		return updateCount{Manager: manager}, fmt.Errorf("unsupported package manager %s", manager)
	}
}

func parseUpdateCount(manager, output string) updateCount {
	lines := compactEvidence(strings.Split(output, "\n"))
	count := 0
	pkgLine := regexp.MustCompile(`^[A-Za-z0-9_.+:-]+\s+`)
	for _, line := range lines {
		lower := strings.ToLower(line)
		switch manager {
		case "apt":
			if strings.Contains(lower, "upgradable") && !strings.HasPrefix(lower, "listing") {
				count++
			}
		case "dnf", "yum":
			if pkgLine.MatchString(line) && !strings.Contains(lower, "last metadata") && !strings.Contains(lower, "obsoleting") {
				count++
			}
		case "pacman":
			if pkgLine.MatchString(line) {
				count++
			}
		}
	}
	return updateCount{Manager: manager, Count: count, Known: true}
}

func firewallFinding(ctx context.Context, checkCtx check.Context, base linuxCheck) report.Finding {
	var evidence []string
	if out, err := commandOutput(ctx, checkCtx, "ufw", "status"); err == nil {
		line := firstLine(out)
		evidence = append(evidence, "ufw: "+line)
		if ufwIsActive(line) {
			return okFinding(base.findingID("firewall_ufw_active"), base.moduleName(), "firewall_status", "UFW firewall is active", "UFW reports active status.", evidence)
		}
	}
	if out, err := commandOutput(ctx, checkCtx, "firewall-cmd", "--state"); err == nil {
		state := strings.TrimSpace(out)
		evidence = append(evidence, "firewalld: "+state)
		if state == "running" {
			return okFinding(base.findingID("firewall_firewalld_active"), base.moduleName(), "firewall_status", "firewalld is running", "firewalld reports running status.", evidence)
		}
	}
	if out, err := commandOutput(ctx, checkCtx, "nft", "list", "ruleset"); err == nil && strings.TrimSpace(out) != "" {
		return infoFinding(base.findingID("firewall_nft_rules"), base.moduleName(), "firewall_status", "nftables ruleset present", "nft returned a non-empty ruleset; effectiveness depends on rules and network profile.", []string{firstLine(out)})
	}
	if len(evidence) == 0 {
		return infoFinding(base.findingID("firewall_unknown"), base.moduleName(), "firewall_status", "No supported host firewall status found", "UFW, firewalld, and nftables did not report an active firewall. Cloud or endpoint controls may still apply.", nil)
	}
	return finding(base.findingID("firewall_inactive"), base.moduleName(), "firewall_status", report.SeverityWarning, "Host firewall appears inactive", "Supported local firewall tools did not report active filtering.", evidence, "Confirm whether another firewall controls exposure. Enable or configure a host firewall only after allowing required SSH/RDP/app/VPN ports.", map[string]string{"confidence": "medium"})
}

func sshConfigFindings(base linuxCheck) []report.Finding {
	data, err := osReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return []report.Finding{infoFinding(base.findingID("sshd_config_missing"), base.moduleName(), "ssh_config", "SSH daemon config not readable", "Could not read /etc/ssh/sshd_config; SSH may be absent or permissions may restrict this check.", nil)}
	}
	settings := parseSSHSettings(data)
	var findings []report.Finding
	if strings.EqualFold(settings["permitrootlogin"], "yes") {
		findings = append(findings, finding(base.findingID("ssh_root_login"), base.moduleName(), "ssh_config", report.SeverityWarning, "SSH permits root login", "PermitRootLogin yes allows direct root authentication if sshd is running and reachable.", []string{"PermitRootLogin yes"}, "Set PermitRootLogin to prohibit-password or no if operationally appropriate, and confirm remote access before reloading sshd.", map[string]string{"confidence": "medium"}))
	} else {
		findings = append(findings, okFinding(base.findingID("ssh_root_restricted"), base.moduleName(), "ssh_config", "SSH root login is not explicitly enabled", "PermitRootLogin was not set to yes in readable sshd_config.", nil))
	}
	if strings.EqualFold(settings["passwordauthentication"], "yes") {
		findings = append(findings, infoFinding(base.findingID("ssh_password_auth"), base.moduleName(), "ssh_config", "SSH password authentication enabled", "PasswordAuthentication yes may be expected, but key-only access reduces brute-force exposure if SSH is reachable.", []string{"PasswordAuthentication yes"}))
	}
	return findings
}

func parseSSHSettings(data string) map[string]string {
	settings := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			settings[strings.ToLower(fields[0])] = fields[1]
		}
	}
	return settings
}

func ufwIsActive(line string) bool {
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "status: active" || line == "active"
}

func firstLine(value string) string {
	lines := compactEvidence(strings.Split(value, "\n"))
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func osReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}
