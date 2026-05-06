package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
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
	switch event.Kind {
	case "dc.replication_request":
		return []events.Detection{{
			ID:           "det-stream-" + event.ID,
			DetectorID:   "CRED-001",
			Title:        "Stream detected suspicious replication request",
			Confidence:   "high",
			Severity:     "critical",
			OccurredAt:   event.OccurredAt,
			Domain:       event.Domain,
			SourceHost:   event.SourceHost,
			Actor:        event.Actor,
			Target:       event.TargetDN,
			EvidenceRefs: []string{event.RawRef},
			Metadata: map[string]string{
				"kind":    event.Kind,
				"channel": event.Channel,
			},
		}}
	case "dir.object_modify":
		if event.Attributes["attribute"] == "msDS-KeyCredentialLink" {
			return []events.Detection{{
				ID:           "det-stream-" + event.ID,
				DetectorID:   "ACL-004",
				Title:        "Stream detected shadow credential write",
				Confidence:   "high",
				Severity:     "critical",
				OccurredAt:   event.OccurredAt,
				Domain:       event.Domain,
				SourceHost:   event.SourceHost,
				Actor:        event.Actor,
				Target:       event.TargetDN,
				EvidenceRefs: []string{event.RawRef},
				Metadata: map[string]string{
					"kind":      event.Kind,
					"attribute": event.Attributes["attribute"],
				},
			}}
		}
	case "auth.kerberos.tgs":
		return []events.Detection{{
			ID:           "det-stream-" + event.ID,
			DetectorID:   "KRB-001",
			Title:        "Stream detected Kerberos service ticket spike",
			Confidence:   "medium",
			Severity:     "high",
			OccurredAt:   event.OccurredAt,
			Domain:       event.Domain,
			SourceHost:   event.SourceHost,
			Actor:        event.Actor,
			Target:       event.TargetDN,
			EvidenceRefs: []string{event.RawRef},
			Metadata: map[string]string{
				"kind": event.Kind,
			},
		}}
	}

	return nil
}
