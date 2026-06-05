package windows

import (
	"strings"
	"testing"

	"github.com/creativeprofit22/intruder-hunter/internal/report"
)

func TestParseWindowsProcessesAndAssessMinerContext(t *testing.T) {
	jsonText := `[
		{"Name":"xmrig.exe","ProcessId":4242,"ParentProcessId":100,"ExecutablePath":"C:\\Users\\Public\\xmrig.exe","CommandLine":"xmrig.exe --url stratum+tcp://pool.example:3333 --algo randomx","CreationDate":"20260501000000.000000+000","CPU":91.5},
		{"Name":"notepad.exe","ProcessId":12,"ParentProcessId":4,"ExecutablePath":"C:\\Windows\\System32\\notepad.exe","CommandLine":"notepad.exe","CreationDate":"20260501000000.000000+000","CPU":0.1}
	]`
	processes, err := parseWindowsProcesses(jsonText)
	if err != nil {
		t.Fatalf("parseWindowsProcesses() error = %v", err)
	}
	if len(processes) != 2 {
		t.Fatalf("len(processes) = %d, want 2", len(processes))
	}
	assessment := assessWindowsProcess(processes[0])
	if assessment.Severity != report.SeverityCritical {
		t.Fatalf("assessment severity = %q, want critical; reasons=%v", assessment.Severity, assessment.Reasons)
	}
	if assessment.Score < 6 {
		t.Fatalf("assessment score = %d, want >= 6", assessment.Score)
	}
}

func TestParseWindowsListenersAndAssessPublicRDP(t *testing.T) {
	jsonText := `{"LocalAddress":"0.0.0.0","LocalPort":3389,"OwningProcess":888,"ProcessName":"svchost.exe","Path":"C:\\Windows\\System32\\svchost.exe","ServiceNames":"TermService"}`
	listeners, err := parseWindowsListeners(jsonText)
	if err != nil {
		t.Fatalf("parseWindowsListeners() error = %v", err)
	}
	if len(listeners) != 1 {
		t.Fatalf("len(listeners) = %d, want 1", len(listeners))
	}
	severity, reason := assessWindowsListener(listeners[0])
	if severity != report.SeverityWarning {
		t.Fatalf("severity = %q, want warning; reason=%s", severity, reason)
	}
	if !strings.Contains(reason, "RDP") {
		t.Fatalf("reason = %q, want RDP context", reason)
	}
}

func TestParseWindowsDefenderStatus(t *testing.T) {
	jsonText := `{"AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"AntispywareEnabled":true,"BehaviorMonitorEnabled":true,"IoavProtectionEnabled":true,"NISEnabled":true,"AntivirusSignatureLastUpdated":"2026-05-01T10:00:00","QuickScanAge":9,"FullScanAge":30}`
	status, err := parseWindowsDefenderStatus(jsonText)
	if err != nil {
		t.Fatalf("parseWindowsDefenderStatus() error = %v", err)
	}
	if status.RealTimeProtectionEnabled {
		t.Fatal("RealTimeProtectionEnabled = true, want false")
	}
	if got := defenderEvidence(status); len(got) != 3 {
		t.Fatalf("len(defenderEvidence) = %d, want 3", len(got))
	}
}

func TestParsePersistenceTaskUserAndPostureSamples(t *testing.T) {
	items, err := parseWindowsPersistenceItems(`[{"Source":"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","Name":"Updater","Command":"C:\\Users\\bob\\AppData\\Local\\Temp\\updater.exe --url stratum+ssl://pool","Path":"","State":"","StartMode":"","Description":""}]`)
	if err != nil {
		t.Fatalf("parseWindowsPersistenceItems() error = %v", err)
	}
	severity, reasons := assessPersistenceItem(items[0])
	if severity != report.SeverityCritical || len(reasons) == 0 {
		t.Fatalf("persistence severity=%q reasons=%v, want critical with reasons", severity, reasons)
	}

	tasks, err := parseWindowsScheduledTasks(`[{"TaskName":"Updater","TaskPath":"\\","State":"Ready","Author":"Unknown","Actions":"powershell.exe -EncodedCommand AAAA","Principal":"SYSTEM"}]`)
	if err != nil {
		t.Fatalf("parseWindowsScheduledTasks() error = %v", err)
	}
	taskSeverity, _ := assessWindowsScheduledTask(tasks[0])
	if taskSeverity != report.SeverityWarning {
		t.Fatalf("task severity = %q, want warning", taskSeverity)
	}

	users, err := parseWindowsUserState(`{"Administrators":["HOST\\Administrator","HOST\\Alice"],"Users":[{"Name":"backup$","Enabled":true,"SID":"S-1-5-21-1","Description":"","LastLogon":""},{"Name":"Guest","Enabled":false,"SID":"S-1-5-21-2","Description":"Built-in","LastLogon":""}]}`)
	if err != nil {
		t.Fatalf("parseWindowsUserState() error = %v", err)
	}
	if len(users.Administrators) != 2 || users.Users[0].Name != "backup$" {
		t.Fatalf("unexpected users parse: %+v", users)
	}

	posture, err := parseWindowsPosture(`{"FirewallProfiles":[{"Name":"Domain","Enabled":true},{"Name":"Public","Enabled":false}],"UACEnabled":"1","RDPDenyTSConnections":"0","SMB1Server":"True","PendingUpdates":3}`)
	if err != nil {
		t.Fatalf("parseWindowsPosture() error = %v", err)
	}
	if len(posture.FirewallProfiles) != 2 || posture.PendingUpdates != 3 || !strings.EqualFold(posture.SMB1Server, "true") {
		t.Fatalf("unexpected posture parse: %+v", posture)
	}
}
