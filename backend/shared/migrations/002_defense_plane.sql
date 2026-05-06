-- Defense plane schema

CREATE TABLE IF NOT EXISTS defense_detector_families (
    id            VARCHAR(100) PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    description   TEXT,
    priority      INT NOT NULL DEFAULT 100,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS defense_detectors (
    id                  VARCHAR(100) PRIMARY KEY,
    family_id           VARCHAR(100) REFERENCES defense_detector_families(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    type                VARCHAR(50) NOT NULL,
    mitre_ids           TEXT[] DEFAULT '{}',
    aliases             TEXT[] DEFAULT '{}',
    description         TEXT,
    core_preconditions  JSONB DEFAULT '[]'::jsonb,
    required_signals    JSONB DEFAULT '[]'::jsonb,
    optional_signals    JSONB DEFAULT '[]'::jsonb,
    response_candidates JSONB DEFAULT '[]'::jsonb,
    detector_priority   VARCHAR(20) DEFAULT 'medium',
    response_priority   VARCHAR(20) DEFAULT 'medium',
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS defense_incidents (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title             VARCHAR(255) NOT NULL,
    severity          VARCHAR(20) NOT NULL,
    confidence        VARCHAR(30) NOT NULL,
    status            VARCHAR(30) NOT NULL DEFAULT 'open',
    primary_actor     VARCHAR(255),
    primary_target    VARCHAR(255),
    domain            VARCHAR(255),
    metadata          JSONB DEFAULT '{}'::jsonb,
    opened_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    closed_at         TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS defense_detections (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    detector_id       VARCHAR(100) REFERENCES defense_detectors(id),
    incident_id       UUID REFERENCES defense_incidents(id) ON DELETE SET NULL,
    title             VARCHAR(255) NOT NULL,
    severity          VARCHAR(20) NOT NULL,
    confidence        VARCHAR(30) NOT NULL,
    domain            VARCHAR(255),
    source_host       VARCHAR(255),
    actor             VARCHAR(255),
    target            VARCHAR(255),
    metadata          JSONB DEFAULT '{}'::jsonb,
    evidence_refs     JSONB DEFAULT '[]'::jsonb,
    detected_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS defense_response_actions (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id       UUID REFERENCES defense_incidents(id) ON DELETE CASCADE,
    action_type       VARCHAR(100) NOT NULL,
    mode              VARCHAR(30) NOT NULL,
    status            VARCHAR(30) NOT NULL DEFAULT 'queued',
    target_type       VARCHAR(100),
    target_value      VARCHAR(255),
    requested_by      VARCHAR(255),
    approved_by       VARCHAR(255),
    result_summary    TEXT,
    rollback_data     JSONB,
    executed_at       TIMESTAMP WITH TIME ZONE,
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS defense_exclusions (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scope_type        VARCHAR(50) NOT NULL,
    scope_value       VARCHAR(255) NOT NULL,
    reason            TEXT,
    expires_at        TIMESTAMP WITH TIME ZONE,
    created_by        VARCHAR(255),
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS defense_evidence_bundles (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id       UUID REFERENCES defense_incidents(id) ON DELETE CASCADE,
    storage_key       TEXT NOT NULL,
    sha256            VARCHAR(64),
    content_type      VARCHAR(100),
    size_bytes        BIGINT,
    metadata          JSONB DEFAULT '{}'::jsonb,
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_defense_detectors_family_id ON defense_detectors(family_id);
CREATE INDEX IF NOT EXISTS idx_defense_incidents_status ON defense_incidents(status);
CREATE INDEX IF NOT EXISTS idx_defense_incidents_opened_at ON defense_incidents(opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_defense_detections_incident_id ON defense_detections(incident_id);
CREATE INDEX IF NOT EXISTS idx_defense_detections_detector_id ON defense_detections(detector_id);
CREATE INDEX IF NOT EXISTS idx_defense_detections_detected_at ON defense_detections(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_defense_response_actions_incident_id ON defense_response_actions(incident_id);
