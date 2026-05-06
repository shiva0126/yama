package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"ad-assessment/defense-shared/catalog"
	"ad-assessment/defense-shared/events"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SeedCatalog ensures the defense catalog is materialized in PostgreSQL so the
// UI and downstream services can read from a real system-of-record instead of
// only the embedded YAML copy.
func SeedCatalog(ctx context.Context, pool *pgxpool.Pool, cat *catalog.Catalog) error {
	if pool == nil || cat == nil {
		return errors.New("pool and catalog are required")
	}

	for _, family := range cat.Families {
		if _, err := pool.Exec(ctx, `
			INSERT INTO defense_detector_families (id, name, description, priority)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (id) DO UPDATE
			SET name = EXCLUDED.name,
				description = EXCLUDED.description,
				priority = EXCLUDED.priority
		`, family.ID, family.Name, family.Description, family.Priority); err != nil {
			return err
		}
	}

	for _, detector := range cat.Detectors {
		if _, err := pool.Exec(ctx, `
			INSERT INTO defense_detectors (
				id, family_id, name, type, mitre_ids, aliases, description,
				core_preconditions, required_signals, optional_signals,
				response_candidates, detector_priority, response_priority, enabled, updated_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12, $13, $14, NOW())
			ON CONFLICT (id) DO UPDATE
			SET family_id = EXCLUDED.family_id,
				name = EXCLUDED.name,
				type = EXCLUDED.type,
				mitre_ids = EXCLUDED.mitre_ids,
				aliases = EXCLUDED.aliases,
				description = EXCLUDED.description,
				core_preconditions = EXCLUDED.core_preconditions,
				required_signals = EXCLUDED.required_signals,
				optional_signals = EXCLUDED.optional_signals,
				response_candidates = EXCLUDED.response_candidates,
				detector_priority = EXCLUDED.detector_priority,
				response_priority = EXCLUDED.response_priority,
				enabled = EXCLUDED.enabled,
				updated_at = NOW()
		`, detector.ID, detector.FamilyID, detector.Name, detector.Type, detector.MitreIDs, detector.Aliases, detector.Description,
			jsonMust(detector.CorePreconditions), jsonMust(detector.RequiredSignals), jsonMust(detector.OptionalSignals),
			jsonMust(detector.ResponseCandidates), detector.DetectorPriority, detector.ResponsePriority, true); err != nil {
			return err
		}
	}

	return nil
}

func UpsertIncident(ctx context.Context, pool *pgxpool.Pool, incident events.Incident) (string, error) {
	if pool == nil {
		return "", errors.New("pool is required")
	}

	id := incident.ID
	if id == "" {
		id = uuid.NewString()
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO defense_incidents (
			id, title, severity, confidence, status, primary_actor, primary_target,
			domain, metadata, opened_at, last_updated_at, closed_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12)
		ON CONFLICT (id) DO UPDATE
		SET title = EXCLUDED.title,
			severity = EXCLUDED.severity,
			confidence = EXCLUDED.confidence,
			status = EXCLUDED.status,
			primary_actor = EXCLUDED.primary_actor,
			primary_target = EXCLUDED.primary_target,
			domain = EXCLUDED.domain,
			metadata = EXCLUDED.metadata,
			last_updated_at = EXCLUDED.last_updated_at,
			closed_at = EXCLUDED.closed_at
	`, id, incident.Title, incident.Severity, incident.Confidence, incident.Status, incident.PrimaryActor, incident.PrimaryTarget,
		incident.Metadata["domain"], jsonMust(incident.Metadata), incident.OpenedAt, incident.LastUpdatedAt, nil)
	if err != nil {
		return "", err
	}

	return id, nil
}

func UpsertDetection(ctx context.Context, pool *pgxpool.Pool, detection events.Detection) (string, error) {
	if pool == nil {
		return "", errors.New("pool is required")
	}

	id := detection.ID
	if id == "" {
		id = uuid.NewString()
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO defense_detections (
			id, detector_id, incident_id, title, severity, confidence, domain, source_host,
			actor, target, metadata, evidence_refs, detected_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, $13)
		ON CONFLICT (id) DO NOTHING
	`, id, detection.DetectorID, nil, detection.Title, detection.Severity, detection.Confidence, detection.Domain, detection.SourceHost,
		detection.Actor, detection.Target, jsonMust(detection.Metadata), jsonMust(detection.EvidenceRefs), detection.OccurredAt)
	if err != nil {
		return "", err
	}

	return id, nil
}

func SaveResponseAction(ctx context.Context, pool *pgxpool.Pool, action events.ResponseAction) (string, error) {
	if pool == nil {
		return "", errors.New("pool is required")
	}

	id := action.ID
	if id == "" {
		id = uuid.NewString()
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO defense_response_actions (
			id, incident_id, action_type, mode, status, target_type, target_value,
			result_summary, rollback_data, executed_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, NOW())
		ON CONFLICT (id) DO NOTHING
	`, id, action.IncidentID, action.ActionType, action.Mode, action.Status, action.TargetType, action.TargetValue,
		action.Metadata["reason"], jsonMust(action.Metadata), time.Now().UTC())
	if err != nil {
		return "", err
	}

	return id, nil
}

func SaveEvidenceBundle(ctx context.Context, pool *pgxpool.Pool, bundle events.EvidenceBundle) (string, error) {
	if pool == nil {
		return "", errors.New("pool is required")
	}

	id := bundle.ID
	if id == "" {
		id = uuid.NewString()
	}

	_, err := pool.Exec(ctx, `
		INSERT INTO defense_evidence_bundles (
			id, incident_id, storage_key, sha256, content_type, size_bytes, metadata, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())
		ON CONFLICT (id) DO NOTHING
	`, id, bundle.IncidentID, bundle.StorageKey, bundle.SHA256, bundle.ContentType, bundle.SizeBytes, jsonMust(bundle.Metadata))
	if err != nil {
		return "", err
	}

	return id, nil
}

func LoadDefenseSummary(ctx context.Context, pool *pgxpool.Pool) (map[string]any, error) {
	if pool == nil {
		return nil, errors.New("pool is required")
	}

	var families, detectors, critical, high, demoReady int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM defense_detector_families`).Scan(&families); err != nil {
		return nil, err
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM defense_detectors`).Scan(&detectors); err != nil {
		return nil, err
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM defense_detectors WHERE detector_priority = 'critical'`).Scan(&critical); err != nil {
		return nil, err
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM defense_detectors WHERE detector_priority = 'high'`).Scan(&high); err != nil {
		return nil, err
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM defense_detectors WHERE enabled = true`).Scan(&demoReady); err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
		SELECT f.name, COUNT(d.id)
		FROM defense_detector_families f
		LEFT JOIN defense_detectors d ON d.family_id = f.id
		GROUP BY f.name
		ORDER BY f.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byFamily := map[string]int{}
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		byFamily[name] = count
	}

	return map[string]any{
		"family_count":       families,
		"detector_count":     detectors,
		"critical_count":     critical,
		"high_count":         high,
		"demo_ready_count":   demoReady,
		"by_family":          byFamily,
		"response_profiles": map[string]int{
			"high":   high,
			"medium": detectors - high - critical,
		},
	}, nil
}

func jsonMust(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
