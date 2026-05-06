package events

import "time"

// NormalizedEvent is the common unit of telemetry that all defense-plane services
// should exchange. Specific event kinds can extend this shape later, but keeping
// a stable common envelope early avoids tightly coupling detectors to raw Windows logs.
type NormalizedEvent struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	OccurredAt  time.Time         `json:"occurred_at"`
	Domain      string            `json:"domain"`
	SourceHost  string            `json:"source_host"`
	TargetHost  string            `json:"target_host"`
	Actor       string            `json:"actor"`
	ActorSID    string            `json:"actor_sid"`
	TargetDN    string            `json:"target_dn"`
	ObjectClass string            `json:"object_class"`
	Channel     string            `json:"channel"`
	RawRef      string            `json:"raw_ref"`
	Attributes  map[string]string `json:"attributes"`
}

// Detection is emitted by detector-engine workers after evaluating normalized signals.
type Detection struct {
	ID           string            `json:"id"`
	DetectorID   string            `json:"detector_id"`
	Title        string            `json:"title"`
	Confidence   string            `json:"confidence"`
	Severity     string            `json:"severity"`
	OccurredAt   time.Time         `json:"occurred_at"`
	Domain       string            `json:"domain"`
	SourceHost   string            `json:"source_host"`
	Actor        string            `json:"actor"`
	Target       string            `json:"target"`
	EvidenceRefs []string          `json:"evidence_refs"`
	Metadata     map[string]string `json:"metadata"`
}

// Incident is a correlated collection of one or more detections plus the response
// and evidence context required for operator review and automated containment.
type Incident struct {
	ID              string            `json:"id"`
	Title           string            `json:"title"`
	Severity        string            `json:"severity"`
	Confidence      string            `json:"confidence"`
	Status          string            `json:"status"`
	PrimaryActor    string            `json:"primary_actor"`
	PrimaryTarget   string            `json:"primary_target"`
	OpenedAt        time.Time         `json:"opened_at"`
	LastUpdatedAt   time.Time         `json:"last_updated_at"`
	DetectionIDs    []string          `json:"detection_ids"`
	ResponseActions []string          `json:"response_actions"`
	Metadata        map[string]string `json:"metadata"`
}

// ResponseAction is the normalized representation of a containment or approval
// step chosen by the response plane.
type ResponseAction struct {
	ID          string            `json:"id"`
	IncidentID  string            `json:"incident_id"`
	ActionType  string            `json:"action_type"`
	Mode        string            `json:"mode"`
	Status      string            `json:"status"`
	TargetType  string            `json:"target_type"`
	TargetValue string            `json:"target_value"`
	Metadata    map[string]string `json:"metadata"`
}

// EvidenceBundle is a metadata-first representation of a forensic bundle before
// the object payload is written to MinIO.
type EvidenceBundle struct {
	ID          string            `json:"id"`
	IncidentID  string            `json:"incident_id"`
	StorageKey  string            `json:"storage_key"`
	SHA256      string            `json:"sha256"`
	ContentType string            `json:"content_type"`
	SizeBytes   int64             `json:"size_bytes"`
	Metadata    map[string]string `json:"metadata"`
}
