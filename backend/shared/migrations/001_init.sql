-- AD Assessment Database Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- Agents
-- ============================================================
CREATE TABLE IF NOT EXISTS agents (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(255) NOT NULL,
    hostname    VARCHAR(255) NOT NULL,
    domain      VARCHAR(255) NOT NULL,
    ip_address  VARCHAR(45),
    api_key     VARCHAR(64) UNIQUE NOT NULL,
    status      VARCHAR(20) DEFAULT 'offline',
    last_seen   TIMESTAMP WITH TIME ZONE,
    version     VARCHAR(50),
    capabilities TEXT[],
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================
-- Scans
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID REFERENCES agents(id),
    domain          VARCHAR(255) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    progress        INT DEFAULT 0,
    error           TEXT,
    snapshot_id     UUID,
    overall_score   INT,
    critical_count  INT DEFAULT 0,
    high_count      INT DEFAULT 0,
    medium_count    INT DEFAULT 0,
    low_count       INT DEFAULT 0,
    info_count      INT DEFAULT 0,
    total_findings  INT DEFAULT 0,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at      TIMESTAMP WITH TIME ZONE,
    completed_at    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_scans_agent_id ON scans(agent_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);

-- ============================================================
-- Scan Tasks
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_tasks (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id      UUID REFERENCES scans(id) ON DELETE CASCADE,
    task_type    VARCHAR(50) NOT NULL,
    status       VARCHAR(20) NOT NULL DEFAULT 'pending',
    items_found  INT DEFAULT 0,
    error        TEXT,
    started_at   TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_scan_tasks_scan_id ON scan_tasks(scan_id);

-- ============================================================
-- Inventory Snapshots
-- ============================================================
CREATE TABLE IF NOT EXISTS inventory_snapshots (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id     UUID REFERENCES scans(id),
    taken_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    domain      VARCHAR(255) NOT NULL,
    forest      JSONB,
    summary     JSONB  -- counts of objects
);

-- ============================================================
-- AD Objects (stored as JSONB for flexibility)
-- ============================================================
CREATE TABLE IF NOT EXISTS ad_users (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_id      UUID REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
    scan_id          UUID REFERENCES scans(id) ON DELETE CASCADE,
    sam_account_name VARCHAR(255),
    distinguished_name TEXT,
    domain           VARCHAR(255),
    data             JSONB NOT NULL,
    is_privileged    BOOLEAN DEFAULT FALSE,
    is_kerberoastable BOOLEAN DEFAULT FALSE,
    is_asrep_roastable BOOLEAN DEFAULT FALSE,
    has_spn          BOOLEAN DEFAULT FALSE,
    enabled          BOOLEAN DEFAULT TRUE,
    last_logon       TIMESTAMP WITH TIME ZONE,
    pwd_last_set     TIMESTAMP WITH TIME ZONE,
    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_ad_users_snapshot_id ON ad_users(snapshot_id);
CREATE INDEX idx_ad_users_scan_id ON ad_users(scan_id);
CREATE INDEX idx_ad_users_is_privileged ON ad_users(is_privileged);

CREATE TABLE IF NOT EXISTS ad_groups (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_id      UUID REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
    scan_id          UUID REFERENCES scans(id) ON DELETE CASCADE,
    name             VARCHAR(255),
    distinguished_name TEXT,
    domain           VARCHAR(255),
    is_privileged    BOOLEAN DEFAULT FALSE,
    member_count     INT DEFAULT 0,
    data             JSONB NOT NULL,
    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_ad_groups_snapshot_id ON ad_groups(snapshot_id);
CREATE INDEX idx_ad_groups_scan_id ON ad_groups(scan_id);

CREATE TABLE IF NOT EXISTS ad_computers (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_id      UUID REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
    scan_id          UUID REFERENCES scans(id) ON DELETE CASCADE,
    name             VARCHAR(255),
    distinguished_name TEXT,
    domain           VARCHAR(255),
    os               VARCHAR(255),
    is_dc            BOOLEAN DEFAULT FALSE,
    enabled          BOOLEAN DEFAULT TRUE,
    laps_enabled     BOOLEAN DEFAULT FALSE,
    unconstrained_delegation BOOLEAN DEFAULT FALSE,
    data             JSONB NOT NULL,
    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_ad_computers_snapshot_id ON ad_computers(snapshot_id);
CREATE INDEX idx_ad_computers_scan_id ON ad_computers(scan_id);
CREATE INDEX idx_ad_computers_is_dc ON ad_computers(is_dc);

CREATE TABLE IF NOT EXISTS ad_gpos (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_id      UUID REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
    scan_id          UUID REFERENCES scans(id) ON DELETE CASCADE,
    name             VARCHAR(255),
    guid             VARCHAR(50),
    domain           VARCHAR(255),
    is_linked        BOOLEAN DEFAULT FALSE,
    data             JSONB NOT NULL,
    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_ad_gpos_snapshot_id ON ad_gpos(snapshot_id);
CREATE INDEX idx_ad_gpos_scan_id ON ad_gpos(scan_id);

CREATE TABLE IF NOT EXISTS ad_domain_controllers (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_id      UUID REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
    scan_id          UUID REFERENCES scans(id) ON DELETE CASCADE,
    name             VARCHAR(255),
    domain           VARCHAR(255),
    os               VARCHAR(255),
    is_read_only     BOOLEAN DEFAULT FALSE,
    data             JSONB NOT NULL,
    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================
-- Findings
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id          UUID REFERENCES scans(id) ON DELETE CASCADE,
    indicator_id     VARCHAR(10) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    severity         VARCHAR(20) NOT NULL,
    category         VARCHAR(100) NOT NULL,
    risk_score       INT DEFAULT 0,
    affected_objects JSONB,
    remediation      TEXT,
    "references"     TEXT[],
    mitre            TEXT[],
    is_new           BOOLEAN DEFAULT TRUE,
    detected_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_findings_indicator_id ON findings(indicator_id);

-- ============================================================
-- Reports
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id      UUID REFERENCES scans(id),
    format       VARCHAR(10) NOT NULL DEFAULT 'html',
    domain       VARCHAR(255),
    score        INT DEFAULT 0,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_reports_scan_id ON reports(scan_id);
