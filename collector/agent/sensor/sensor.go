// Package sensor provides platform-agnostic sensor management for the Yama agent.
// On Windows, ETW-based real-time event subscription is used (see sensor_windows.go).
// On all platforms, the PowerShell polling bridge is available as fallback.
package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Event is a raw security event captured by a sensor component.
type Event struct {
	Source     string            `json:"source"`
	EventID    string            `json:"event_id"`
	OccurredAt time.Time         `json:"occurred_at"`
	AgentID    string            `json:"agent_id"`
	Domain     string            `json:"domain"`
	SourceHost string            `json:"source_host"`
	Actor      string            `json:"actor"`
	ActorSID   string            `json:"actor_sid"`
	Target     string            `json:"target"`
	ObjectClass string           `json:"object_class"`
	Attributes map[string]string `json:"attributes"`
}

// Sensor is the runtime sensor coordinator for a single agent instance.
type Sensor struct {
	agentID          string
	domain           string
	hostname         string
	signalCollectorURL string
	logger           *zap.Logger
	events           chan Event
	health           *HealthState
	mu               sync.RWMutex
}

// HealthState tracks sensor subsystem status for the /sensor/health endpoint.
type HealthState struct {
	mu            sync.RWMutex
	ETWActive     bool      `json:"etw_active"`
	PSPollActive  bool      `json:"ps_poll_active"`
	SysmonActive  bool      `json:"sysmon_active"`
	LastEventAt   time.Time `json:"last_event_at"`
	EventsTotal   int64     `json:"events_total"`
	ErrorsTotal   int64     `json:"errors_total"`
	StartedAt     time.Time `json:"started_at"`
}

func New(agentID, domain, hostname, signalCollectorURL string, logger *zap.Logger) *Sensor {
	return &Sensor{
		agentID:            agentID,
		domain:             domain,
		hostname:           hostname,
		signalCollectorURL: signalCollectorURL,
		logger:             logger,
		events:             make(chan Event, 512),
		health: &HealthState{
			StartedAt: time.Now().UTC(),
		},
	}
}

// Start launches all sensor subsystems and begins forwarding events.
func (s *Sensor) Start(ctx context.Context) {
	go s.forwardLoop(ctx)
	s.startPlatformSensors(ctx)
}

// Health returns a snapshot of the sensor health state.
func (s *Sensor) Health() HealthState {
	s.health.mu.RLock()
	defer s.health.mu.RUnlock()
	return *s.health
}

// Emit injects an event from an external source (e.g. Sysmon pipe, ETW).
func (s *Sensor) Emit(e Event) {
	if e.AgentID == "" {
		e.AgentID = s.agentID
	}
	if e.Domain == "" {
		e.Domain = s.domain
	}
	if e.SourceHost == "" {
		e.SourceHost = s.hostname
	}
	select {
	case s.events <- e:
		s.health.mu.Lock()
		s.health.EventsTotal++
		s.health.LastEventAt = time.Now().UTC()
		s.health.mu.Unlock()
	default:
		s.logger.Warn("sensor event channel full — dropping event", zap.String("event_id", e.EventID))
	}
}

// forwardLoop drains the event channel and ships to signal-collector.
func (s *Sensor) forwardLoop(ctx context.Context) {
	batch := make([]Event, 0, 32)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		for _, e := range batch {
			if err := s.forward(e); err != nil {
				s.logger.Warn("forward failed", zap.Error(err))
				s.health.mu.Lock()
				s.health.ErrorsTotal++
				s.health.mu.Unlock()
			}
		}
		batch = batch[:0]
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case e := <-s.events:
			batch = append(batch, e)
			if len(batch) >= 32 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *Sensor) forward(e Event) error {
	if s.signalCollectorURL == "" {
		return nil
	}
	payload := map[string]interface{}{
		"agent_id":   e.AgentID,
		"source":     e.Source,
		"count":      1,
		"labels": map[string]string{
			"event_id":    e.EventID,
			"domain":      e.Domain,
			"actor":       e.Actor,
			"actor_sid":   e.ActorSID,
			"target_host": e.Target,
			"object_class": e.ObjectClass,
			"occurred_at": e.OccurredAt.Format(time.RFC3339),
		},
	}
	for k, v := range e.Attributes {
		payload["labels"].(map[string]string)[k] = v
	}
	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.signalCollectorURL+"/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("signal-collector returned %d", resp.StatusCode)
	}
	return nil
}

// offensiveToolSignatures are process names and patterns that indicate offensive tooling.
var offensiveToolSignatures = []string{
	"mimikatz", "mimi", "sekurlsa", "lsadump",
	"rubeus", "kekeo", "impacket",
	"bloodhound", "sharphound",
	"cobalt strike", "beacon",
	"meterpreter", "metasploit",
	"invoke-mimikatz", "invoke-kerberoast",
	"procdump", "nanodump",
}

// IsOffensiveTool returns true when the process name matches a known offensive tool.
func IsOffensiveTool(processName string) bool {
	lower := processName
	for i := 0; i < len(lower); i++ {
		if lower[i] >= 'A' && lower[i] <= 'Z' {
			lower = lower[:i] + string(lower[i]+32) + lower[i+1:]
		}
	}
	for _, sig := range offensiveToolSignatures {
		if len(lower) >= len(sig) {
			for i := 0; i <= len(lower)-len(sig); i++ {
				if lower[i:i+len(sig)] == sig {
					return true
				}
			}
		}
	}
	return false
}

// EnvSignalCollectorURL returns the SIGNAL_COLLECTOR_URL environment variable.
func EnvSignalCollectorURL() string {
	return os.Getenv("SIGNAL_COLLECTOR_URL")
}
