package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/messaging"
	"ad-assessment/defense-shared/server"
)

type rawTelemetryBatch struct {
	AgentID string            `json:"agent_id"`
	Source  string            `json:"source"`
	Count   int               `json:"count"`
	Labels  map[string]string `json:"labels"`
}

type rawSignal struct {
	Kind       string            `json:"kind"`
	Channel    string            `json:"channel"`
	Domain     string            `json:"domain"`
	SourceHost string            `json:"source_host"`
	TargetHost string            `json:"target_host"`
	Actor      string            `json:"actor"`
	ActorSID   string            `json:"actor_sid"`
	TargetDN   string            `json:"target_dn"`
	ObjectClass string           `json:"object_class"`
	EventID    string            `json:"event_id"`
	OccurredAt string            `json:"occurred_at"`
	Attributes map[string]string `json:"attributes"`
}

func main() {
	cfg := config.Load("signal-normalizer", "8092", "9092")
	nc, js, err := messaging.Connect(cfg.NATSURL)
	if err != nil {
		log.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	if err := messaging.EnsureDefenseStream(js); err != nil {
		log.Fatalf("ensure stream: %v", err)
	}
	if err := messaging.StartConsumer(js, messaging.SubjectSignalsRaw, "signal-normalizer", func(data []byte) error {
		var batch rawTelemetryBatch
		if err := json.Unmarshal(data, &batch); err != nil {
			return err
		}

		normalized := normalizeBatch(batch)
		return messaging.PublishJSON(context.Background(), js, messaging.SubjectSignalsNormalized, normalized)
	}); err != nil {
		log.Fatalf("start consumer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))
	mux.HandleFunc("/normalize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}

		var raw rawSignal
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		normalized := normalizeRawSignal(raw)
		if err := messaging.PublishJSON(context.Background(), js, messaging.SubjectSignalsNormalized, normalized); err != nil {
			log.Printf("publish normalized event: %v", err)
		}
		server.WriteJSON(w, http.StatusOK, normalized)
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

func normalizeBatch(batch rawTelemetryBatch) events.NormalizedEvent {
	kind := batch.Labels["kind"]
	if kind == "" {
		kind = batch.Labels["event_kind"]
	}
	if kind == "" {
		kind = inferBatchKind(batch)
	}

	attrs := map[string]string{
		"agent_id": batch.AgentID,
		"source":   batch.Source,
		"count":    strconv.Itoa(batch.Count),
	}
	for k, v := range batch.Labels {
		attrs[k] = v
	}

	return events.NormalizedEvent{
		ID:          "norm-batch-" + batch.AgentID,
		Kind:        kind,
		OccurredAt:  time.Now().UTC(),
		Domain:      batch.Labels["domain"],
		SourceHost:  batch.AgentID,
		TargetHost:  batch.Labels["target_host"],
		Actor:       batch.Labels["actor"],
		ActorSID:    batch.Labels["actor_sid"],
		TargetDN:    batch.Labels["target_dn"],
		ObjectClass: batch.Labels["object_class"],
		Channel:     batch.Source,
		RawRef:      batch.AgentID + ":" + batch.Source,
		Attributes:  attrs,
	}
}

func inferBatchKind(batch rawTelemetryBatch) string {
	switch batch.Labels["event_id"] {
	case "4662":
		return "dc.replication_request"
	case "5136":
		return "dir.object_modify"
	case "4769":
		return "auth.kerberos.tgs"
	default:
		return "raw.signal"
	}
}

func normalizeRawSignal(raw rawSignal) events.NormalizedEvent {
	occurredAt := time.Now().UTC()
	if raw.OccurredAt != "" {
		if parsed, err := time.Parse(time.RFC3339, raw.OccurredAt); err == nil {
			occurredAt = parsed.UTC()
		}
	}

	kind := raw.Kind
	if kind == "" {
		kind = inferKind(raw)
	}

	attributes := raw.Attributes
	if attributes == nil {
		attributes = make(map[string]string)
	}
	if raw.EventID != "" {
		attributes["event_id"] = raw.EventID
	}

	return events.NormalizedEvent{
		ID:          "norm-demo-" + strings.ToLower(strings.ReplaceAll(kind, ".", "-")),
		Kind:        kind,
		OccurredAt:  occurredAt,
		Domain:      raw.Domain,
		SourceHost:  raw.SourceHost,
		TargetHost:  raw.TargetHost,
		Actor:       raw.Actor,
		ActorSID:    raw.ActorSID,
		TargetDN:    raw.TargetDN,
		ObjectClass: raw.ObjectClass,
		Channel:     raw.Channel,
		RawRef:      raw.Channel + ":" + raw.EventID,
		Attributes:  attributes,
	}
}

func inferKind(raw rawSignal) string {
	switch {
	case raw.EventID == "4662":
		return "dc.replication_request"
	case raw.EventID == "5136":
		return "dir.object_modify"
	case raw.EventID == "4769":
		return "auth.kerberos.tgs"
	case raw.EventID == "4768":
		return "auth.kerberos.tgt"
	default:
		return "raw.signal"
	}
}
