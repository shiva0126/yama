package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"ad-assessment/defense-shared/catalog"
	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/messaging"
	"ad-assessment/defense-shared/server"
	"ad-assessment/defense-shared/storage"
	"ad-assessment/defense-shared/store"
)

// correlationWindow holds recent detections per actor for windowed correlation.
type correlationWindow struct {
	mu         sync.Mutex
	byActor    map[string][]events.Detection
	windowSize time.Duration
}

func newCorrelationWindow() *correlationWindow {
	cw := &correlationWindow{
		byActor:    make(map[string][]events.Detection),
		windowSize: 5 * time.Minute,
	}
	go cw.expire()
	return cw
}

func (cw *correlationWindow) add(d events.Detection) []events.Detection {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	key := d.Actor + "@" + d.Domain
	if key == "@" {
		key = d.DetectorID
	}
	cw.byActor[key] = append(cw.byActor[key], d)
	return append([]events.Detection{}, cw.byActor[key]...)
}

func (cw *correlationWindow) expire() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-cw.windowSize)
		cw.mu.Lock()
		for key, dets := range cw.byActor {
			var fresh []events.Detection
			for _, d := range dets {
				if d.OccurredAt.After(cutoff) {
					fresh = append(fresh, d)
				}
			}
			if len(fresh) == 0 {
				delete(cw.byActor, key)
			} else {
				cw.byActor[key] = fresh
			}
		}
		cw.mu.Unlock()
	}
}

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

	cw := newCorrelationWindow()

	// Subscribe to raw detections and correlate into incidents
	if err := messaging.StartConsumer(js, messaging.SubjectDetectionsRaw, "correlation-engine", func(data []byte) error {
		var detection events.Detection
		if err := json.Unmarshal(data, &detection); err != nil {
			return err
		}

		// Add to window and check if we have enough to open/update an incident
		windowDets := cw.add(detection)
		incidents := correlateDetections(windowDets)

		for _, incident := range incidents {
			if _, err := store.UpsertIncident(context.Background(), pool, incident); err != nil {
				log.Printf("persist correlated incident: %v", err)
			}
			if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectIncidents, incident); err != nil {
				log.Printf("publish incident: %v", err)
			}
		}
		return nil
	}); err != nil {
		log.Fatalf("start consumer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))

	// Seed demo incidents for UI development
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

	// Manual correlation endpoint for testing
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

	// Group by actor+domain and open an incident when ≥2 detections exist
	type groupKey struct{ actor, domain string }
	byGroup := map[groupKey][]events.Detection{}
	for _, d := range detections {
		k := groupKey{d.Actor, d.Domain}
		byGroup[k] = append(byGroup[k], d)
	}

	var incidents []events.Incident
	for key, dets := range byGroup {
		if len(dets) < 1 {
			continue
		}
		earliest := dets[0].OccurredAt
		for _, d := range dets[1:] {
			if d.OccurredAt.Before(earliest) {
				earliest = d.OccurredAt
			}
		}

		title := "Correlated AD incident"
		if key.actor != "" {
			title = "Suspicious activity from " + key.actor
		}
		if len(dets) == 1 {
			title = dets[0].Title
		}

		var ids []string
		for _, d := range dets {
			ids = append(ids, d.ID)
		}

		incident := events.Incident{
			Title:         title,
			Severity:      highestSeverity(dets),
			Confidence:    highestConfidence(dets),
			Status:        "open",
			PrimaryActor:  key.actor,
			PrimaryTarget: dets[0].Target,
			OpenedAt:      earliest,
			LastUpdatedAt: time.Now().UTC(),
			DetectionIDs:  ids,
			Metadata: map[string]string{
				"domain":          key.domain,
				"detection_count": string(rune('0' + len(dets))),
			},
		}
		incidents = append(incidents, incident)
	}
	return incidents
}

func highestSeverity(detections []events.Detection) string {
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		for _, d := range detections {
			if d.Severity == severity {
				return severity
			}
		}
	}
	return "low"
}

func highestConfidence(detections []events.Detection) string {
	for _, confidence := range []string{"critical-confirmed", "high", "medium", "low"} {
		for _, d := range detections {
			if d.Confidence == confidence {
				return confidence
			}
		}
	}
	return "low"
}
