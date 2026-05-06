# Phase 2 Backend Build Notes

## What Was Built

- Defense-plane backend services in Go for signal ingest, normalization, detection, correlation, response planning, evidence capture, and defense API access.
- Shared defense runtime helpers for Postgres persistence, NATS JetStream publishing/consuming, and a normalized event model.
- Frontend defense console pages that surface the new defense plane APIs.

## Why These Changes Were Made

- Keep the assessment plane and defense plane separate but connected.
- Move the product from demo-style UI and stubbed backend flows to a production-shaped defense stack.
- Use the shared defense catalog as the system of record for detector coverage.

## Build Issues Encountered

- Docker builds initially failed because the service modules were missing `go.sum` entries for shared runtime dependencies.
- `go mod tidy` on the shared module pulled in Go 1.23 test-only dependencies, which conflicted with the original Go 1.22 build images.
- `x/sys` needed to be pinned to the runtime-compatible `v0.16.0` checksum set to satisfy the `x/crypto` path used by `pgx`.
- The defense service Dockerfiles were updated to use Go 1.23 images and `go build -mod=mod` so the container build can resolve the final module graph without blocking on tidy-only noise.

## Result

- Defense services now build successfully in Docker.
- The repo keeps a pinned, reproducible module set for the defense plane.
- The runtime graph stays aligned with the assessment and defense architecture described in the docs.
