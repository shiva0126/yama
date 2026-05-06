package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/server"
)

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
		server.WriteJSON(w, http.StatusOK, normalized)
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
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
