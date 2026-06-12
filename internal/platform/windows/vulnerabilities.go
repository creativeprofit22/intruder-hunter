package windows

import (
	"context"
	"fmt"
	"strings"

	"github.com/creativeprofit22/intruder-hunter/internal/check"
	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

type vulnerabilitiesCheck struct{ windowsCheck }

type windowsPosture struct {
	FirewallProfiles []windowsFirewallProfile `json:"FirewallProfiles"`
	UACEnabled       string                   `json:"UACEnabled"`
	RDPDenyTS        string                   `json:"RDPDenyTSConnections"`
	SMB1Server       string                   `json:"SMB1Server"`
	PendingUpdates   int                      `json:"PendingUpdates"`
}

type windowsFirewallProfile struct {
	Name    string `json:"Name"`
	Enabled bool   `json:"Enabled"`
}

const vulnerabilitiesScript = `$fw = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled); $uac = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA; $rdp = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections; $smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol; $pending = 0; try { $session = New-Object -ComObject Microsoft.Update.Session; $searcher = $session.CreateUpdateSearcher(); $pending = ($searcher.Search("IsInstalled=0 and Type='Software'").Updates).Count } catch { $pending = -1 }; [pscustomobject]@{ FirewallProfiles=$fw; UACEnabled=[string]$uac; RDPDenyTSConnections=[string]$rdp; SMB1Server=[string]$smb1; PendingUpdates=[int]$pending } | ConvertTo-Json -Compress -Depth 4`

func (c vulnerabilitiesCheck) Run(ctx context.Context, checkCtx check.Context) ([]report.Finding, error) {
	out, err := powerShellOutput(ctx, checkCtx, vulnerabilitiesScript)
	if err != nil {
		return []report.Finding{commandInfoFinding(c.findingID("powershell_unavailable"), c.moduleName(), "security_posture", "powershell.exe", err)}, nil
	}
	posture, err := parseWindowsPosture(out)
	if err != nil {
		return nil, err
	}
	findings := make([]report.Finding, 0, 6)
	if len(posture.FirewallProfiles) == 0 {
		findings = append(findings, infoFinding(c.findingID("firewall_profiles_unavailable"), c.moduleName(), "firewall_profiles", "Windows Firewall profiles unavailable", "No firewall profile records were returned, so firewall status is unknown.", nil))
	} else {
		firewallWarnings := 0
		for _, profile := range posture.FirewallProfiles {
			if !profile.Enabled {
				firewallWarnings++
				findings = append(findings, finding(c.findingID("firewall_"+sanitizeID(profile.Name)), c.moduleName(), "firewall_profiles", report.SeverityWarning, "Windows Firewall profile is disabled", fmt.Sprintf("The %s firewall profile is disabled.", profile.Name), []string{fmt.Sprintf("profile=%s enabled=false", profile.Name)}, "Enable the firewall only after allowing required SSH/RDP/VPN/app ports and confirming managed-device policy.", nil))
			}
		}
		if firewallWarnings == 0 {
			findings = append(findings, okFinding(c.findingID("firewall_profiles_ok"), c.moduleName(), "firewall_profiles", "Windows Firewall profiles are enabled", "All returned Windows Firewall profiles report enabled.", firewallEvidence(posture.FirewallProfiles)))
		}
	}
	if posture.UACEnabled == "0" {
		findings = append(findings, finding(c.findingID("uac_disabled"), c.moduleName(), "uac", report.SeverityWarning, "User Account Control is disabled", "UAC EnableLUA is set to 0.", []string{"EnableLUA=0"}, "Re-enable UAC only after confirming application compatibility and maintenance timing.", nil))
	} else if posture.UACEnabled == "1" {
		findings = append(findings, okFinding(c.findingID("uac_enabled"), c.moduleName(), "uac", "User Account Control is enabled", "UAC EnableLUA is set to 1.", []string{"EnableLUA=1"}))
	}
	if posture.RDPDenyTS == "0" {
		findings = append(findings, finding(c.findingID("rdp_enabled"), c.moduleName(), "remote_access", report.SeverityWarning, "Remote Desktop appears enabled", "RDP connections are allowed according to fDenyTSConnections=0.", []string{"fDenyTSConnections=0"}, "If RDP is not required, disable it. If required, restrict exposure with VPN/firewall and strong authentication.", nil))
	} else if posture.RDPDenyTS == "1" {
		findings = append(findings, okFinding(c.findingID("rdp_disabled"), c.moduleName(), "remote_access", "Remote Desktop appears disabled", "RDP connections are denied according to fDenyTSConnections=1.", []string{"fDenyTSConnections=1"}))
	}
	if strings.EqualFold(posture.SMB1Server, "true") {
		findings = append(findings, finding(c.findingID("smb1_enabled"), c.moduleName(), "smb", report.SeverityCritical, "SMBv1 server is enabled", "SMBv1 is obsolete and materially increases exposure to known wormable attack paths.", []string{"EnableSMB1Protocol=True"}, "Disable SMBv1 after confirming no legacy dependency remains.", nil))
	} else if strings.EqualFold(posture.SMB1Server, "false") {
		findings = append(findings, okFinding(c.findingID("smb1_disabled"), c.moduleName(), "smb", "SMBv1 server is disabled", "SMBv1 server support reports disabled.", []string{"EnableSMB1Protocol=False"}))
	}
	switch {
	case posture.PendingUpdates > 0:
		findings = append(findings, finding(c.findingID("pending_updates"), c.moduleName(), "updates", report.SeverityWarning, "Windows software updates are pending", fmt.Sprintf("Windows Update reports %d pending software updates.", posture.PendingUpdates), []string{fmt.Sprintf("pending_updates=%d", posture.PendingUpdates)}, "Apply updates during an approved maintenance window with backups for important systems.", nil))
	case posture.PendingUpdates == 0:
		findings = append(findings, okFinding(c.findingID("pending_updates_ok"), c.moduleName(), "updates", "No pending Windows software updates reported", "Windows Update COM search returned zero pending software updates.", nil))
	default:
		findings = append(findings, infoFinding(c.findingID("pending_updates_unknown"), c.moduleName(), "updates", "Windows Update pending count unavailable", "The Windows Update COM search failed or was blocked, so pending update status is unknown.", nil))
	}
	return findings, nil
}

func parseWindowsPosture(output string) (windowsPosture, error) {
	return parseJSONValue[windowsPosture](output)
}

func firewallEvidence(profiles []windowsFirewallProfile) []string {
	out := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, fmt.Sprintf("profile=%s enabled=%s", profile.Name, boolWord(profile.Enabled)))
	}
	return out
}
