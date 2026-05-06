package messaging

// JetStream subjects are centralized here so service modules stay aligned on the
// event backbone contract. These are intentionally explicit because subject drift
// across services is a common source of operational bugs.
const (
	SubjectSignalsRaw          = "yama.defense.signals.raw"
	SubjectSignalsNormalized   = "yama.defense.signals.normalized"
	SubjectDetectionsRaw       = "yama.defense.detections.raw"
	SubjectIncidents           = "yama.defense.incidents"
	SubjectResponsesRequested  = "yama.defense.responses.requested"
	SubjectResponsesExecuted   = "yama.defense.responses.executed"
	SubjectEvidenceEvents      = "yama.defense.evidence.events"
)
