package main

import (
	"encoding/json"
	"log"
	"net/http"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/server"
)

func main() {
	cfg := config.Load("response-orchestrator", "8095", "9095")

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

		server.WriteJSON(w, http.StatusOK, planResponse(incident))
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
