# Yama Defense Stack Technology Decision

## Decision

The preferred technology stack for the defense plane is:

- Go
- PostgreSQL
- Redis
- NATS JetStream
- MinIO
- gRPC + Protobuf

Kafka is not the preferred first implementation choice.

## Why This Stack

### Go

Use for all defense-plane backend services.

Reasons:

- already aligned with the existing Yama backend
- strong concurrency for detector and correlation workloads
- low operational complexity
- easy static deployment
- good fit for long-running services and streaming consumers

### PostgreSQL

Use as the system of record.

Store:

- detector metadata
- detector versions
- incidents
- alert history
- response actions
- approvals
- evidence metadata
- exclusions and policy
- incident annotations
- baseline snapshots and drift markers

Reason:

- reliable transactional store
- already in the product
- easier to manage than introducing another operational database early

### Redis

Use for:

- ephemeral state
- caches
- UI live status
- short-lived correlation windows if needed
- rate limiting
- distributed locks where justified

Do not use Redis as the long-term event backbone or system of record.

### NATS JetStream

Use as the event backbone.

Reason:

- simpler operational model than Kafka
- durable streams when needed
- lightweight for a product of this scale
- strong fit for internal service fan-out
- easier to demo and operate during early product build

Use subjects for:

- raw signals
- normalized events
- detector outputs
- incidents
- response workflows
- evidence events

### MinIO

Use as S3-compatible object storage for:

- raw evidence bundles
- exported event packets
- snapshots
- rollback artifacts
- incident attachments

Reason:

- easy local and on-prem deployment
- aligns with future S3-compatible production storage

### gRPC + Protobuf

Use for service-to-service contracts.

Reason:

- strongly typed interfaces
- explicit schema evolution
- better service contracts than ad hoc JSON between internal services
- efficient for internal APIs

Use REST only for operator-facing APIs and convenience endpoints.

## Why Not Kafka First

Kafka is appropriate only if one or more of these become true:

- very high sustained event throughput
- long replay retention across large event volumes
- many independent downstream consumers with heavy scaling requirements
- multi-team platform requirements beyond the current product stage

Today it adds more operational cost than value.

For Yama’s current stage:

- NATS JetStream is faster to integrate
- easier to operate
- easier to demo
- easier to keep aligned with the existing Go microservice approach

## Final Recommendation

Build the first production-capable defense backend with:

- Go
- PostgreSQL
- Redis
- NATS JetStream
- MinIO
- gRPC + Protobuf

Revisit Kafka only if scale, replay, or platform complexity later demands it.
