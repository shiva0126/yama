module ad-assessment/response-orchestrator

go 1.22

require ad-assessment/defense-shared v0.0.0

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgx/v5 v5.5.5 // indirect
	github.com/nats-io/nats.go v1.37.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace ad-assessment/defense-shared => ../defense-shared
