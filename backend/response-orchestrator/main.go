package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/messaging"
	"ad-assessment/defense-shared/server"
	"ad-assessment/defense-shared/storage"
	"ad-assessment/defense-shared/store"
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

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

func planResponse(incident events.Incident) []events.ResponseAction {
	return []events.ResponseAction{
		{
			ID:          "resp-demo-001",
			IncidentID:  incident.ID,
			ActionType:  "disable-account",
			Mode:        "approval-required",
			Status:      "planned",
			TargetType:  "account",
			TargetValue: incident.PrimaryActor,
			Metadata: map[string]string{
				"reason":   "Primary actor tied to credential replication or forged-auth chain",
				"rollback": "Re-enable account after investigation if false positive",
			},
		},
		{
			ID:          "resp-demo-002",
			IncidentID:  incident.ID,
			ActionType:  "revert-attribute",
			Mode:        "approval-required",
			Status:      "planned",
			TargetType:  "attribute",
			TargetValue: "msDS-KeyCredentialLink",
			Metadata: map[string]string{
				"reason":   "Shadow credentials or certificate mapping takeover path detected",
				"rollback": "Restore previous attribute state from evidence bundle",
			},
		},
	}
}
