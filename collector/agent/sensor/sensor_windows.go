//go:build windows

package sensor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// etw subscription channel — Security log event IDs we care about.
// PowerShell EvtSubscribe is used here as the Go ETW binding layer.
// This provides sub-second latency vs the 5-second polling approach.
var securityEventIDs = []string{
	// DCSync / Replication
	"4662", "4929",
	// Directory changes
	"5136", "5137", "5141",
	// Kerberos
	"4768", "4769", "4771",
	// NTLM / Logon
	"4624", "4625", "4648", "4672",
	// Account management
	"4720", "4722", "4723", "4724", "4726", "4738",
	"4728", "4729", "4732", "4733", "4756", "4757",
	// Process / Service
	"4688", "7045", "4697",
	// LSASS access
	"4656", "4663",
	// Evasion
	"1102", "4698", "4702",
	// Certificate
	"4886", "4887",
	// NTLM
	"4776",
}

// startPlatformSensors starts Windows-specific sensor subsystems.
func (s *Sensor) startPlatformSensors(ctx context.Context) {
	go s.runETWSubscriber(ctx)
	go s.runProcessWatcher(ctx)
	go s.runServiceWatcher(ctx)
	go s.runSysmonReader(ctx)
	go s.runLSASSProtectionMonitor(ctx)

	s.health.mu.Lock()
	s.health.ETWActive = true
	s.health.mu.Unlock()
	s.logger.Info("Windows sensor subsystems started")
}

// runETWSubscriber uses PowerShell's EvtSubscribe to stream Security events in real time.
func (s *Sensor) runETWSubscriber(ctx context.Context) {
	idFilter := strings.Join(securityEventIDs, ",")
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$ids = @(%s)
$query = ($ids | ForEach-Object { "EventID=$_" }) -join ' or '
$xpath = "*[System[($query)]]"
$sub = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher
$sub = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new(
    [System.Diagnostics.Eventing.Reader.EventLogQuery]::new('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath),
    $null, $true)
Register-ObjectEvent -InputObject $sub -EventName EventRecordWritten -Action {
    $rec = $Event.SourceArgs[1].EventRecord
    if ($rec -ne $null) {
        $xml = $rec.ToXml()
        Write-Host $xml
    }
} | Out-Null
$sub.Enabled = $true
while ($true) { Start-Sleep -Seconds 3600 }
`, idFilter)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cmd := exec.CommandContext(ctx, "powershell.exe",
			"-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			s.logger.Error("ETW subscriber start failed", zap.Error(err))
			time.Sleep(5 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "<Event") {
				if e, err := parseWindowsEventXML([]byte(line)); err == nil {
					s.Emit(e)
				}
			}
		}
		cmd.Wait()
		time.Sleep(2 * time.Second) // restart on exit
	}
}

// runProcessWatcher monitors 4688 events for offensive tool process names.
func (s *Sensor) runProcessWatcher(ctx context.Context) {
	script := `
$ErrorActionPreference = 'SilentlyContinue'
while ($true) {
    $evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddSeconds(-6)} -ErrorAction SilentlyContinue
    foreach ($e in $evts) {
        $xml = [xml]$e.ToXml()
        $procName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text'
        $actor    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
        $pid      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessId'}).'#text'
        Write-Host "$($e.TimeCreated.ToString('o'))|$actor|$procName|$pid"
    }
    Start-Sleep -Seconds 5
}
`
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		s.logger.Error("process watcher start failed", zap.Error(err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "|", 4)
		if len(parts) != 4 {
			continue
		}
		ts, _ := time.Parse(time.RFC3339Nano, parts[0])
		actor, procName, pid := parts[1], parts[2], parts[3]

		e := Event{
			Source:     "Security",
			EventID:    "4688",
			OccurredAt: ts,
			Actor:      actor,
			Attributes: map[string]string{"process_name": procName, "pid": pid},
		}
		if IsOffensiveTool(procName) {
			e.Attributes["offensive_tool"] = "true"
			s.logger.Warn("offensive tool process detected",
				zap.String("process", procName), zap.String("actor", actor))
		}
		s.Emit(e)
	}
	cmd.Wait()
}

// runServiceWatcher monitors 7045 events for suspicious service installations.
func (s *Sensor) runServiceWatcher(ctx context.Context) {
	script := `
$ErrorActionPreference = 'SilentlyContinue'
while ($true) {
    $evts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddSeconds(-6)} -ErrorAction SilentlyContinue
    foreach ($e in $evts) {
        $xml = [xml]$e.ToXml()
        $svcName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ServiceName'}).'#text'
        $svcFile = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ImagePath'}).'#text'
        $account = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'AccountName'}).'#text'
        Write-Host "$($e.TimeCreated.ToString('o'))|$svcName|$svcFile|$account"
    }
    Start-Sleep -Seconds 5
}
`
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		s.logger.Error("service watcher start failed", zap.Error(err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "|", 4)
		if len(parts) != 4 {
			continue
		}
		ts, _ := time.Parse(time.RFC3339Nano, parts[0])
		svcName, svcFile, account := parts[1], parts[2], parts[3]
		s.Emit(Event{
			Source:     "System",
			EventID:    "7045",
			OccurredAt: ts,
			Attributes: map[string]string{
				"service_name": svcName,
				"image_path":   svcFile,
				"account_name": account,
			},
		})
	}
	cmd.Wait()
}

// runSysmonReader reads Sysmon events if Sysmon is deployed.
func (s *Sensor) runSysmonReader(ctx context.Context) {
	script := `
$ErrorActionPreference = 'SilentlyContinue'
$logExists = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
if (-not $logExists) { exit 0 }
while ($true) {
    $evts = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddSeconds(-6)} -ErrorAction SilentlyContinue
    foreach ($e in $evts) {
        $xml = $e.ToXml()
        Write-Host $xml
    }
    Start-Sleep -Seconds 5
}
`
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "<Event") {
			if e, err := parseWindowsEventXML([]byte(line)); err == nil {
				e.Source = "Sysmon"
				s.Emit(e)
				s.health.mu.Lock()
				s.health.SysmonActive = true
				s.health.mu.Unlock()
			}
		}
	}
	cmd.Wait()
}

// runLSASSProtectionMonitor checks LSASS protection status every 60s.
func (s *Sensor) runLSASSProtectionMonitor(ctx context.Context) {
	check := func() {
		script := `
try {
    $lsass = Get-Process -Name lsass -ErrorAction Stop
    $protected = (Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").GetValue("RunAsPPL")
    @{lsass_pid=$lsass.Id; ppl_enabled=($protected -eq 1); check_time=(Get-Date -Format o)} | ConvertTo-Json -Compress
} catch {
    @{error=$_.Exception.Message} | ConvertTo-Json -Compress
}
`
		cmd := exec.CommandContext(ctx, "powershell.exe",
			"-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
		out, _ := cmd.Output()
		s.logger.Debug("LSASS protection check", zap.String("result", strings.TrimSpace(string(out))))
	}

	check()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// windowsEventXML is a minimal struct for parsing Windows XML event records.
type windowsEventXML struct {
	System struct {
		EventID   string `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
		Channel  string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func parseWindowsEventXML(data []byte) (Event, error) {
	var raw windowsEventXML
	if err := xml.NewDecoder(bytes.NewReader(data)).Decode(&raw); err != nil {
		return Event{}, err
	}
	ts, _ := time.Parse(time.RFC3339Nano, raw.System.TimeCreated.SystemTime)
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	attrs := map[string]string{}
	var actor, actorSID, target string
	for _, d := range raw.EventData.Data {
		attrs[d.Name] = d.Value
		switch d.Name {
		case "SubjectUserName":
			actor = d.Value
		case "SubjectUserSid":
			actorSID = d.Value
		case "ObjectDN", "TargetUserName", "NewProcessName":
			target = d.Value
		}
	}
	return Event{
		Source:     raw.System.Channel,
		EventID:    raw.System.EventID,
		OccurredAt: ts,
		SourceHost:  raw.System.Computer,
		Actor:      actor,
		ActorSID:   actorSID,
		Target:     target,
		Attributes: attrs,
	}, nil
}
