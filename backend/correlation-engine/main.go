package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
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

// attackChain defines a named multi-step attack pattern that fires when all
// required detector IDs fire for the same actor within the correlation window.
type attackChain struct {
	Name        string
	Severity    string
	Confidence  string
	Required    []string // detector IDs that must all be present
	Optional    []string // detector IDs that boost confidence when present
	Tier0Target bool     // escalate to critical if target is a Tier-0 asset
}

var chains = []attackChain{
	{
		Name:       "DCSync Attack",
		Severity:   "critical",
		Confidence: "high",
		Required:   []string{"CRED-001"},
		Optional:   []string{"ACL-017", "TRUST-007"},
		Tier0Target: true,
	},
	{
		Name:       "Shadow Credentials Attack",
		Severity:   "critical",
		Confidence: "high",
		Required:   []string{"ACL-004"},
		Optional:   []string{"KRB-014", "CRED-001"},
		Tier0Target: true,
	},
	{
		Name:       "RBCD Privilege Escalation",
		Severity:   "critical",
		Confidence: "high",
		Required:   []string{"KRB-014"},
		Optional:   []string{"CRED-001", "LAT-005"},
	},
	{
		Name:       "NTLM Relay Chain",
		Severity:   "critical",
		Confidence: "high",
		Required:   []string{"NTLM-001"},
		Optional:   []string{"ADCS-008", "ACL-004"},
	},
	{
		Name:       "GPO Abuse for Persistence",
		Severity:   "high",
		Confidence: "high",
		Required:   []string{"GPO-001"},
		Optional:   []string{"PERS-002", "ACL-017"},
	},
	{
		Name:       "Kerberoasting Campaign",
		Severity:   "high",
		Confidence: "medium",
		Required:   []string{"KRB-001"},
		Optional:   []string{"KRB-004", "CRED-001"},
	},
	{
		Name:       "Evasion + Attack Combo",
		Severity:   "critical",
		Confidence: "high",
		Required:   []string{"EVADE-001"},
		Optional:   []string{"CRED-001", "CRED-005", "LAT-005", "TOOL-001"},
		Tier0Target: true,
	},
	{
		Name:       "Credential Extraction via LSASS",
		Severity:   "critical",
		Confidence: "high",
		Required:   []string{"CRED-005"},
		Optional:   []string{"LAT-005", "CRED-001", "TOOL-001"},
	},
	{
		Name:       "Offensive Tooling Detected",
		Severity:   "critical",
		Confidence: "critical-confirmed",
		Required:   []string{"TOOL-001"},
		Optional:   []string{"CRED-001", "CRED-005", "KRB-001", "EVADE-001"},
		Tier0Target: true,
	},
}

// tier0Assets are AD objects that, if targeted, escalate an incident to critical.
var tier0Assets = []string{
	"krbtgt", "domain admins", "enterprise admins", "schema admins",
	"domain controllers", "administrators", "CN=krbtgt",
}

func isTier0Target(target string) bool {
	lower := strings.ToLower(target)
	for _, t := range tier0Assets {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

func correlateDetections(detections []events.Detection) []events.Incident {
	if len(detections) == 0 {
		return []events.Incident{}
	}

	// Group by actor+domain
	type groupKey struct{ actor, domain string }
	byGroup := map[groupKey][]events.Detection{}
	for _, d := range detections {
		k := groupKey{d.Actor, d.Domain}
		byGroup[k] = append(byGroup[k], d)
	}

	var incidents []events.Incident
	for key, dets := range byGroup {
		if len(dets) == 0 {
			continue
		}

		earliest := dets[0].OccurredAt
		for _, d := range dets[1:] {
			if d.OccurredAt.Before(earliest) {
				earliest = d.OccurredAt
			}
		}

		// Index detections by detector ID for chain matching
		detByDetectorID := map[string]events.Detection{}
		for _, d := range dets {
			detByDetectorID[d.DetectorID] = d
		}

		// Check Tier-0 targeting
		tier0 := false
		for _, d := range dets {
			if isTier0Target(d.Target) {
				tier0 = true
				break
			}
		}

		// Try each named chain template
		matched := false
		for _, chain := range chains {
			allPresent := true
			for _, req := range chain.Required {
				if _, ok := detByDetectorID[req]; !ok {
					allPresent = false
					break
				}
			}
			if !allPresent {
				continue
			}

			// Count optional hits for confidence boost
			optionalHits := 0
			for _, opt := range chain.Optional {
				if _, ok := detByDetectorID[opt]; ok {
					optionalHits++
				}
			}

			sev := chain.Severity
			conf := chain.Confidence
			if (chain.Tier0Target && tier0) || optionalHits >= 2 {
				sev = "critical"
				conf = "critical-confirmed"
			} else if optionalHits == 1 {
				conf = "high"
			}

			var ids []string
			for _, d := range dets {
				ids = append(ids, d.ID)
			}
			title := chain.Name
			if key.actor != "" {
				title = chain.Name + " by " + key.actor
			}

			incident := events.Incident{
				Title:         title,
				Severity:      sev,
				Confidence:    conf,
				Status:        "open",
				PrimaryActor:  key.actor,
				PrimaryTarget: dets[0].Target,
				OpenedAt:      earliest,
				LastUpdatedAt: time.Now().UTC(),
				DetectionIDs:  ids,
				Metadata: map[string]string{
					"domain":          key.domain,
					"detection_count": strconv.Itoa(len(dets)),
					"chain":           chain.Name,
					"tier0_target":    strconv.FormatBool(tier0),
					"optional_hits":   strconv.Itoa(optionalHits),
				},
			}
			incidents = append(incidents, incident)
			matched = true
			break // only emit one named chain per actor group
		}

		// Fall back: open a generic incident for any single detection
		if !matched {
			var ids []string
			for _, d := range dets {
				ids = append(ids, d.ID)
			}
			title := "Suspicious AD activity"
			if key.actor != "" {
				title = "Suspicious activity from " + key.actor
			}
			if len(dets) == 1 {
				title = dets[0].Title
			}
			sev := highestSeverity(dets)
			if tier0 {
				sev = "critical"
			}
			incident := events.Incident{
				Title:         title,
				Severity:      sev,
				Confidence:    highestConfidence(dets),
				Status:        "open",
				PrimaryActor:  key.actor,
				PrimaryTarget: dets[0].Target,
				OpenedAt:      earliest,
				LastUpdatedAt: time.Now().UTC(),
				DetectionIDs:  ids,
				Metadata: map[string]string{
					"domain":          key.domain,
					"detection_count": strconv.Itoa(len(dets)),
					"tier0_target":    strconv.FormatBool(tier0),
				},
			}
			incidents = append(incidents, incident)
		}
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
