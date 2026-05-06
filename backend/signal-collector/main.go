package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/messaging"
	"ad-assessment/defense-shared/server"
)

type telemetryBatch struct {
	AgentID string            `json:"agent_id"`
	Source  string            `json:"source"`
	Count   int               `json:"count"`
	Labels  map[string]string `json:"labels"`
}

func main() {
	cfg := config.Load("signal-collector", "8091", "9091")
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
	mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}

		var batch telemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectSignalsRaw, batch); err != nil {
			log.Printf("publish raw batch: %v", err)
		}
		server.WriteJSON(w, http.StatusAccepted, map[string]any{
			"status":      "accepted",
			"received_at": time.Now().UTC(),
			"agent_id":    batch.AgentID,
			"source":      batch.Source,
			"count":       batch.Count,
			"next":        "publish to NATS JetStream raw signal subject",
		})
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}
