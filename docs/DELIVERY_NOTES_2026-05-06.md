# Delivery Notes — 2026-05-06

## What Was Built

This pass moved the new defense plane from architecture-only documents into backend scaffolding that is demoable.

Built in this pass:

- machine-readable detector catalog extensions in `backend/defense-shared/catalog`
- embedded detector seed YAML so defense services can run from containers without mounted catalog files
- normalized event, detection, incident, response, and evidence models
- HTTP demo endpoints for:
  - `signal-collector`
  - `signal-normalizer`
  - `detector-engine`
  - `correlation-engine`
  - `response-orchestrator`
  - `evidence-ledger`
  - `policy-engine`
  - `defense-api`
- Dockerfiles for all new defense services
- `docker-compose.yml` expansion for:
  - `nats` with JetStream enabled
  - `minio`
  - all new defense services
- research document:
  - `docs/ATTACK_PATTERN_SIGNAL_RESEARCH.md`

## Why It Was Built

The goal was to get past static planning and produce a backend-first demo path showing:

1. signal ingestion
2. normalization
3. detector coverage
4. correlation
5. response planning
6. evidence packaging

That is the minimum believable shape for the defense product story.

## Attack Pattern Direction

The implementation is intentionally attack-technique driven.

The detector catalog and research were aligned around:

- DCSync and replication abuse
- Kerberos abuse
- NTLM relay chains
- Shadow Credentials
- RBCD
- AD CS abuse
- ForceChangePassword
- SPN-jacking
- SIDHistory injection
- GPO abuse
- MachineAccountQuota abuse

These are the highest-value early detector families for the demo and for later production work.

## Errors / Blockers Faced

### 1. No Go toolchain on PATH

The environment does not currently expose `go`.

Observed blocker:

- `go: command not found`

Impact:

- I could not compile or run `go build ./...`
- I could not run `gofmt`
- I could not generate protobuf stubs with `protoc`

Mitigation:

- kept the code limited to simple standard-library patterns where possible
- embedded the detector YAML to remove runtime file-path fragility
- left protobuf contracts on disk for the next pass once the toolchain is available

### 2. Container image runtime assumptions

Initial `docker-compose` healthchecks for `nats` and `minio` risked failing because vendor images may not include tools like `curl` or `wget`.

Mitigation:

- removed those fragile healthchecks for the demo path

## Next Backend Steps

- add real NATS JetStream publishing/subscribing
- add PostgreSQL repositories for incidents, detections, actions, and evidence metadata
- generate gRPC stubs from the protobuf contracts
- implement catalog seeding into `defense_detectors`
- add MinIO evidence object writes
- add first real detector workers starting with:
  - `CRED-001`
  - `ACL-004`
  - `KRB-014`
  - `ADCS-008`

## Demo Story

For the current demo, the clean sequence is:

1. show the attack-pattern research and detector catalog
2. show `defense-api /catalog/summary`
3. show `signal-normalizer /normalize`
4. show `detector-engine /detections/demo`
5. show `correlation-engine /incidents/demo`
6. show `response-orchestrator /plan`
7. show `evidence-ledger /evidence/bundle`
