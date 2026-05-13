package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"ad-assessment/defense-shared/catalog"
	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/messaging"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/server"
	"ad-assessment/defense-shared/storage"
	"ad-assessment/defense-shared/store"
)

func main() {
	cfg := config.Load("detector-engine", "8093", "9093")
	cat, err := catalog.LoadDefault()
	if err != nil {
		log.Fatalf("load detector catalog: %v", err)
	}
	pool, err := storage.Open(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Fatalf("open db pool: %v", err)
	}
	defer pool.Close()

	nc, js, err := messaging.Connect(cfg.NATSURL)
	if err != nil {
		log.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	if err := messaging.EnsureDefenseStream(js); err != nil {
		log.Fatalf("ensure stream: %v", err)
	}
	if err := messaging.StartConsumer(js, messaging.SubjectSignalsNormalized, "detector-engine", func(data []byte) error {
		var event events.NormalizedEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return err
		}

		detections := detectFromEvent(event)
		for _, detection := range detections {
			if _, err := store.UpsertDetection(context.Background(), pool, detection); err != nil {
				log.Printf("persist stream detection: %v", err)
			}
			if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectDetectionsRaw, detection); err != nil {
				log.Printf("publish stream detection: %v", err)
			}
		}
		return nil
	}); err != nil {
		log.Fatalf("start consumer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))
	mux.HandleFunc("/coverage", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, catalog.BuildCoverageSummary(cat))
	})
	mux.HandleFunc("/detectors", func(w http.ResponseWriter, _ *http.Request) {
		server.WriteJSON(w, http.StatusOK, cat.Detectors)
	})
	mux.HandleFunc("/detections/demo", func(w http.ResponseWriter, _ *http.Request) {
		detections := catalog.DemoDetections(time.Now().UTC())
		for _, detection := range detections {
			if _, err := store.UpsertDetection(context.Background(), pool, detection); err != nil {
				log.Printf("persist detection: %v", err)
			}
			if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectDetectionsRaw, detection); err != nil {
				log.Printf("publish detection: %v", err)
			}
		}
		server.WriteJSON(w, http.StatusOK, detections)
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

func detectFromEvent(event events.NormalizedEvent) []events.Detection {
	var results []events.Detection
	base := func(id, detectorID, title, confidence, severity string) events.Detection {
		return events.Detection{
			ID:           "det-" + detectorID + "-" + event.ID,
			DetectorID:   detectorID,
			Title:        title,
			Confidence:   confidence,
			Severity:     severity,
			OccurredAt:   event.OccurredAt,
			Domain:       event.Domain,
			SourceHost:   event.SourceHost,
			Actor:        event.Actor,
			Target:       event.TargetDN,
			EvidenceRefs: []string{event.RawRef},
			Metadata:     map[string]string{"kind": event.Kind, "channel": event.Channel},
		}
	}
	_ = base

	switch event.Kind {

	// ── CRED-001: DCSync ──────────────────────────────────────────────────────
	case "dc.replication_request":
		d := base("", "CRED-001", "DCSync — suspicious replication request from non-DC actor", "high", "critical")
		results = append(results, d)

	// ── CRED-005: LSASS Memory Dump ──────────────────────────────────────────
	case "proc.lsass_access":
		d := base("", "CRED-005", "LSASS memory access detected", "high", "critical")
		d.Metadata["pid"] = event.Attributes["pid"]
		results = append(results, d)

	// ── KRB-001: Kerberoasting ────────────────────────────────────────────────
	case "auth.kerberos.tgs":
		d := base("", "KRB-001", "Kerberos TGS request spike — possible Kerberoasting", "medium", "high")
		d.Metadata["ticket_encryption"] = event.Attributes["ticket_encryption"]
		results = append(results, d)

	// ── KRB-004: AS-REP Inducement ────────────────────────────────────────────
	case "auth.asreq_no_preauth":
		d := base("", "KRB-004", "AS-REP roasting — account with preauth disabled targeted", "high", "critical")
		results = append(results, d)

	// ── KRB-014: RBCD write ───────────────────────────────────────────────────
	case "dir.attr_write:msDS-AllowedToActOnBehalfOfOtherIdentity":
		d := base("", "KRB-014", "RBCD write — msDS-AllowedToActOnBehalfOfOtherIdentity modified", "high", "critical")
		results = append(results, d)

	// ── NTLM-001: NTLM Relay ─────────────────────────────────────────────────
	case "auth.ntlm":
		if event.Attributes["logon_type"] == "3" || event.Attributes["package"] == "NTLM" {
			d := base("", "NTLM-001", "NTLM network logon — potential relay target", "medium", "high")
			results = append(results, d)
		}

	// ── DC-001: DCShadow ─────────────────────────────────────────────────────
	case "dir.dc_object_add":
		d := base("", "DC-001", "DCShadow — rogue DC object registered in directory", "high", "critical")
		results = append(results, d)

	// ── ADCS-001: ESC1 cert enroll ───────────────────────────────────────────
	case "cert.enroll":
		if event.Attributes["san_override"] == "true" || event.Attributes["ct_flag_enrollee_supplied"] == "true" {
			d := base("", "ADCS-001", "ADCS ESC1 — certificate enrolled with attacker-supplied SAN", "high", "critical")
			results = append(results, d)
		}

	// ── ADCS-008: ESC8 (NTLM relay to ADCS) ─────────────────────────────────
	case "auth.ntlm_relay":
		d := base("", "ADCS-008", "ADCS ESC8 — NTLM relay to AD CS web enrollment endpoint", "high", "critical")
		results = append(results, d)

	// ── ACL-004: Shadow Credentials ──────────────────────────────────────────
	case "dir.attr_write:msDS-KeyCredentialLink":
		d := base("", "ACL-004", "Shadow credential write — msDS-KeyCredentialLink modified", "high", "critical")
		results = append(results, d)

	// ── ACL-011: ForceChangePassword ─────────────────────────────────────────
	case "dir.password_reset":
		if event.Actor != event.Attributes["target_account"] {
			d := base("", "ACL-011", "Delegated password reset — ForceChangePassword right exercised", "medium", "high")
			results = append(results, d)
		}

	// ── PERS-002: Scheduled Task persistence ─────────────────────────────────
	case "persist.scheduled_task":
		d := base("", "PERS-002", "Scheduled task created — possible persistence mechanism", "medium", "high")
		d.Metadata["task_name"] = event.Attributes["task_name"]
		results = append(results, d)

	// ── LAT-005: PsExec / Remote Service ─────────────────────────────────────
	case "svc.install":
		if name := event.Attributes["service_name"]; name != "" {
			d := base("", "LAT-005", "Service installation on remote host — possible lateral movement", "medium", "high")
			d.Metadata["service_name"] = name
			results = append(results, d)
		}

	// ── GPO-001: GPO modification ─────────────────────────────────────────────
	case "dir.object_modify":
		if event.ObjectClass == "groupPolicyContainer" {
			d := base("", "GPO-001", "GPO object modified in directory", "medium", "high")
			results = append(results, d)
		}
		if event.Attributes["attribute"] == "userAccountControl" {
			d := base("", "KRB-004", "userAccountControl write — preauth may have been disabled", "medium", "high")
			results = append(results, d)
		}

	// ── EVADE-001: Log clearing ───────────────────────────────────────────────
	case "evade.log_clear":
		d := base("", "EVADE-001", "Security event log cleared — active evasion in progress", "high", "critical")
		results = append(results, d)

	// ── TOOL-001: Offensive tool process ─────────────────────────────────────
	case "proc.create":
		if event.Attributes["offensive_tool"] == "true" {
			d := base("", "TOOL-001", "Offensive tool process detected: "+event.Attributes["process_name"], "critical", "critical-confirmed")
			d.Metadata["process_name"] = event.Attributes["process_name"]
			results = append(results, d)
		}

	// ── ACL-017 / dir.group_member_add ────────────────────────────────────────
	case "dir.group_member_add":
		if isPrivilegedGroup(event.TargetDN) {
			d := base("", "ACL-017", "Privileged group membership added — potential privilege escalation", "high", "critical")
			results = append(results, d)
		}

	// ── TRUST-007: auth.explicit_cred_logon ───────────────────────────────────
	case "auth.explicit_cred_logon":
		d := base("", "TRUST-007", "Explicit credential logon — RunAs or pass-the-ticket pattern", "medium", "high")
		results = append(results, d)
	}

	return results
}

func isPrivilegedGroup(targetDN string) bool {
	privileged := []string{
		"Domain Admins", "Enterprise Admins", "Schema Admins",
		"Administrators", "Account Operators", "Backup Operators",
		"Group Policy Creator Owners",
	}
	upper := strings.ToUpper(targetDN)
	for _, g := range privileged {
		if strings.Contains(upper, strings.ToUpper(g)) {
			return true
		}
	}
	return false
}
