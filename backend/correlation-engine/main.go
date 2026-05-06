package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"ad-assessment/defense-shared/catalog"
	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/messaging"
	"ad-assessment/defense-shared/server"
	"ad-assessment/defense-shared/storage"
	"ad-assessment/defense-shared/store"
)

func main() {
	cfg := config.Load("correlation-engine", "8094", "9094")
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
	mux.HandleFunc("/incidents/demo", func(w http.ResponseWriter, _ *http.Request) {
		incidents := catalog.DemoIncidents(time.Now().UTC())
		for _, incident := range incidents {
			if _, err := store.UpsertIncident(context.Background(), pool, incident); err != nil {
				log.Printf("persist incident: %v", err)
			}
			if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectIncidents, incident); err != nil {
				log.Printf("publish incident: %v", err)
			}
		}
		server.WriteJSON(w, http.StatusOK, incidents)
	})
	mux.HandleFunc("/correlate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}

		var detections []events.Detection
		if err := json.NewDecoder(r.Body).Decode(&detections); err != nil {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		incidents := correlateDetections(detections)
		for _, incident := range incidents {
			if _, err := store.UpsertIncident(context.Background(), pool, incident); err != nil {
				log.Printf("persist correlated incident: %v", err)
			}
			if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectIncidents, incident); err != nil {
				log.Printf("publish correlated incident: %v", err)
			}
		}
		server.WriteJSON(w, http.StatusOK, incidents)
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

func correlateDetections(detections []events.Detection) []events.Incident {
	if len(detections) == 0 {
		return []events.Incident{}
	}

	incident := events.Incident{
		ID:            "inc-corr-demo-001",
		Title:         "Correlated AD defense incident",
		Severity:      highestSeverity(detections),
		Confidence:    highestConfidence(detections),
		Status:        "open",
		PrimaryActor:  detections[0].Actor,
		PrimaryTarget: detections[0].Target,
		OpenedAt:      detections[0].OccurredAt,
		LastUpdatedAt: time.Now().UTC(),
		Metadata: map[string]string{
			"story": "Grouped by actor, target, and attack window for the demo correlation path.",
		},
	}

	for _, detection := range detections {
		incident.DetectionIDs = append(incident.DetectionIDs, detection.ID)
	}

	return []events.Incident{incident}
}

func highestSeverity(detections []events.Detection) string {
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		for _, detection := range detections {
			if detection.Severity == severity {
				return severity
			}
		}
	}
	return "low"
}

func highestConfidence(detections []events.Detection) string {
	for _, confidence := range []string{"critical-confirmed", "high", "medium", "low"} {
		for _, detection := range detections {
			if detection.Confidence == confidence {
				return confidence
			}
		}
	}
	return "low"
}
