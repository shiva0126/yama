package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

func planResponse(incident events.Incident) []events.ResponseAction {
	actions := []events.ResponseAction{}

	if incident.PrimaryActor != "" {
		mode := "approval-required"
		if incident.Severity == "critical" && incident.Confidence == "critical-confirmed" {
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
				"reason":   "Primary actor implicated in " + incident.Title,
				"rollback": "Re-enable via AD Users and Computers after investigation",
			},
		})
	}

	if incident.Severity == "critical" {
		actions = append(actions, events.ResponseAction{
			IncidentID:  incident.ID,
			ActionType:  "collect-evidence",
			Mode:        "automatic",
			Status:      "planned",
			TargetType:  "domain",
			TargetValue: incident.Metadata["domain"],
			Metadata: map[string]string{
				"reason": "Critical incident — snapshot AD state for forensic review",
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
