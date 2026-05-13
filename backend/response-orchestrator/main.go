package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/messaging"
	"ad-assessment/defense-shared/server"
	"ad-assessment/defense-shared/storage"
	"ad-assessment/defense-shared/store"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	cfg := config.Load("response-orchestrator", "8095", "9095")
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

	// Subscribe to incoming incidents and plan responses
	if err := messaging.StartConsumer(js, messaging.SubjectIncidents, "response-orchestrator-planner", func(data []byte) error {
		var incident events.Incident
		if err := json.Unmarshal(data, &incident); err != nil {
			return err
		}
		actions := planResponse(incident)
		for _, action := range actions {
			if _, err := store.SaveResponseAction(context.Background(), pool, action); err != nil {
				log.Printf("persist response action: %v", err)
			}
		}
		if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectResponsesRequested, actions); err != nil {
			log.Printf("publish response actions: %v", err)
		}
		return nil
	}); err != nil {
		log.Fatalf("start planner consumer: %v", err)
	}

	// Subscribe to planned responses and attempt execution
	if err := messaging.StartConsumer(js, messaging.SubjectResponsesRequested, "response-orchestrator-executor", func(data []byte) error {
		var actions []events.ResponseAction
		if err := json.Unmarshal(data, &actions); err != nil {
			return err
		}
		for _, action := range actions {
			if action.Mode == "automatic" {
				executed := executeAction(pool, action)
				if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectResponsesExecuted, executed); err != nil {
					log.Printf("publish executed action: %v", err)
				}
			}
		}
		return nil
	}); err != nil {
		log.Fatalf("start executor consumer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))

	mux.HandleFunc("/plan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var incident events.Incident
		if err := json.NewDecoder(r.Body).Decode(&incident); err != nil {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		actions := planResponse(incident)
		for _, action := range actions {
			if _, err := store.SaveResponseAction(context.Background(), pool, action); err != nil {
				log.Printf("persist response action: %v", err)
			}
		}
		if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectResponsesRequested, actions); err != nil {
			log.Printf("publish response actions: %v", err)
		}
		server.WriteJSON(w, http.StatusOK, actions)
	})

	mux.HandleFunc("/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var action events.ResponseAction
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		result := executeAction(pool, action)
		server.WriteJSON(w, http.StatusOK, result)
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

// protectedAccounts must never be auto-disabled (require manual approval even at critical).
var protectedAccounts = []string{
	"krbtgt", "administrator", "svc-backup", "svc-monitoring",
}

func isProtected(actor string) bool {
	lower := strings.ToLower(strings.TrimSpace(actor))
	for _, p := range protectedAccounts {
		if lower == p || strings.HasSuffix(lower, "\\"+p) {
			return true
		}
	}
	return false
}

func planResponse(incident events.Incident) []events.ResponseAction {
	actions := []events.ResponseAction{}
	chain := incident.Metadata["chain"]

	// Evidence collection — always automatic for critical
	if incident.Severity == "critical" || incident.Severity == "high" {
		actions = append(actions, events.ResponseAction{
			IncidentID:  incident.ID,
			ActionType:  "collect-evidence",
			Mode:        "automatic",
			Status:      "planned",
			TargetType:  "domain",
			TargetValue: incident.Metadata["domain"],
			Metadata: map[string]string{
				"reason":   "Snapshot AD state for forensic review: " + incident.Title,
				"rollback": "N/A — evidence collection is non-destructive",
			},
		})
	}

	// Account-level responses
	if incident.PrimaryActor != "" {
		mode := "approval-required"
		if incident.Severity == "critical" && incident.Confidence == "critical-confirmed" && !isProtected(incident.PrimaryActor) {
			mode = "automatic"
		}
		actions = append(actions, events.ResponseAction{
			IncidentID:  incident.ID,
			ActionType:  "disable-account",
			Mode:        mode,
			Status:      "planned",
			TargetType:  "account",
			TargetValue: incident.PrimaryActor,
			Metadata: map[string]string{
				"reason":    "Primary actor in: " + incident.Title,
				"rollback":  "Re-enable via: Enable-ADAccount -Identity '" + incident.PrimaryActor + "'",
				"protected": fmt.Sprintf("%v", isProtected(incident.PrimaryActor)),
			},
		})

		// Revoke Kerberos tickets for DCSync, Shadow Creds, RBCD chains, and offensive tooling
		if chain == "DCSync Attack" || chain == "Shadow Credentials Attack" || chain == "RBCD Privilege Escalation" || chain == "Offensive Tooling Detected" {
			actions = append(actions, events.ResponseAction{
				IncidentID:  incident.ID,
				ActionType:  "revoke-tickets",
				Mode:        "approval-required",
				Status:      "planned",
				TargetType:  "account",
				TargetValue: incident.PrimaryActor,
				Metadata: map[string]string{
					"reason":   "Invalidate Kerberos tickets for compromised actor",
					"rollback": "User re-authenticates after ticket expiry",
				},
			})
		}

		// Reset password for privilege escalation chains
		if incident.Severity == "critical" {
			actions = append(actions, events.ResponseAction{
				IncidentID:  incident.ID,
				ActionType:  "reset-password",
				Mode:        "approval-required",
				Status:      "planned",
				TargetType:  "account",
				TargetValue: incident.PrimaryActor,
				Metadata: map[string]string{
					"reason":   "Force password reset to invalidate stolen credentials",
					"rollback": "Inform user of new password via secure channel",
				},
			})
		}
	}

	// Host isolation for LSASS dump or lateral movement
	if chain == "Credential Extraction via LSASS" || chain == "NTLM Relay Chain" {
		if incident.PrimaryTarget != "" {
			actions = append(actions, events.ResponseAction{
				IncidentID:  incident.ID,
				ActionType:  "block-network",
				Mode:        "approval-required",
				Status:      "planned",
				TargetType:  "host",
				TargetValue: incident.PrimaryTarget,
				Metadata: map[string]string{
					"reason":   "Isolate compromised host from lateral movement",
					"rollback": "Remove Windows Firewall block rule added by response",
				},
			})
		}
	}

	// Certificate revocation for ADCS chains
	if chain == "NTLM Relay Chain" || strings.Contains(incident.Title, "ADCS") {
		actions = append(actions, events.ResponseAction{
			IncidentID:  incident.ID,
			ActionType:  "revoke-certificate",
			Mode:        "approval-required",
			Status:      "planned",
			TargetType:  "certificate",
			TargetValue: incident.PrimaryActor,
			Metadata: map[string]string{
				"reason":   "Revoke certificates issued via relay or ESC attack",
				"rollback": "Re-enroll via legitimate certificate request",
			},
		})
	}

	// Computer quarantine for DCShadow or service install lateral movement
	if chain == "GPO Abuse for Persistence" {
		actions = append(actions, events.ResponseAction{
			IncidentID:  incident.ID,
			ActionType:  "quarantine-computer",
			Mode:        "approval-required",
			Status:      "planned",
			TargetType:  "computer",
			TargetValue: incident.PrimaryTarget,
			Metadata: map[string]string{
				"reason":   "Remove compromised computer from production OUs",
				"rollback": "Move computer account back to production OU",
			},
		})
	}

	return actions
}

// executeAction dispatches an approved response action.
// For disable-account it calls the defense-api agent endpoint.
// For collect-evidence it posts to the evidence-ledger.
func executeAction(pool *pgxpool.Pool, action events.ResponseAction) events.ResponseAction {
	action.Status = "executing"
	updateActionStatus(pool, action.ID, "executing", "")

	var resultSummary string
	var execErr error

	switch action.ActionType {
	case "disable-account":
		execErr = dispatchAgentCommand(pool, action.TargetValue, "disable-account")
		if execErr == nil {
			resultSummary = "Account disable command dispatched to agent"
		} else {
			resultSummary = "Agent dispatch failed: " + execErr.Error()
		}
	case "reset-password":
		execErr = dispatchAgentCommand(pool, action.TargetValue, "reset-password")
		if execErr == nil {
			resultSummary = "Password reset command dispatched to agent"
		} else {
			resultSummary = "Agent dispatch failed: " + execErr.Error()
		}
	case "revoke-tickets":
		execErr = dispatchAgentCommand(pool, action.TargetValue, "revoke-tickets")
		if execErr == nil {
			resultSummary = "Kerberos ticket revocation dispatched to agent"
		} else {
			resultSummary = "Agent dispatch failed: " + execErr.Error()
		}
	case "block-network":
		execErr = dispatchAgentCommand(pool, action.TargetValue, "block-network")
		if execErr == nil {
			resultSummary = "Network block command dispatched to agent"
		} else {
			resultSummary = "Agent dispatch failed: " + execErr.Error()
		}
	case "revoke-certificate":
		execErr = dispatchAgentCommand(pool, action.TargetValue, "revoke-certificate")
		if execErr == nil {
			resultSummary = "Certificate revocation dispatched to agent"
		} else {
			resultSummary = "Agent dispatch failed: " + execErr.Error()
		}
	case "quarantine-computer":
		execErr = dispatchAgentCommand(pool, action.TargetValue, "quarantine-computer")
		if execErr == nil {
			resultSummary = "Computer quarantine dispatched to agent"
		} else {
			resultSummary = "Agent dispatch failed: " + execErr.Error()
		}
	case "collect-evidence":
		execErr = collectEvidenceBundle(action)
		if execErr == nil {
			resultSummary = "Evidence bundle collection triggered"
		} else {
			resultSummary = "Evidence collection failed: " + execErr.Error()
		}
	default:
		resultSummary = "Action type " + action.ActionType + " queued for manual review"
	}

	if execErr != nil {
		action.Status = "failed"
	} else {
		action.Status = "completed"
	}

	updateActionStatus(pool, action.ID, action.Status, resultSummary)
	return action
}

func dispatchAgentCommand(pool *pgxpool.Pool, targetAccount, command string) error {
	// Find an online agent with defense_mode enabled
	var defenseURL string
	var apiKey string
	err := pool.QueryRow(context.Background(), `
		SELECT COALESCE(defense_url, ''), api_key
		FROM   agents
		WHERE  defense_mode = TRUE AND status = 'online'
		ORDER  BY last_seen DESC
		LIMIT  1
	`).Scan(&defenseURL, &apiKey)
	if err != nil {
		return fmt.Errorf("query online defense agent: %w", err)
	}
	if defenseURL == "" {
		return fmt.Errorf("no online defense agent with defense_url configured")
	}

	payload, _ := json.Marshal(map[string]string{
		"command": command,
		"target":  targetAccount,
	})
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		defenseURL+"/defend/execute", bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("agent command rejected with status %d", resp.StatusCode)
	}
	return nil
}

func collectEvidenceBundle(action events.ResponseAction) error {
	payload, _ := json.Marshal(map[string]string{
		"incident_id": action.IncidentID,
		"trigger":     action.ActionType,
		"target":      action.TargetValue,
	})
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"http://evidence-ledger:8096/evidence/bundle", bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func updateActionStatus(pool *pgxpool.Pool, id, status, result string) {
	if id == "" {
		return
	}
	_, err := pool.Exec(context.Background(), `
		UPDATE defense_response_actions
		SET    status = $2, result_summary = $3, executed_at = NOW()
		WHERE  id = $1
	`, id, status, result)
	if err != nil {
		log.Printf("update action status: %v", err)
	}
}
