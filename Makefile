.PHONY: up down build dev-backend dev-frontend

# Start all services with Docker Compose
up:
	docker compose up -d

# Stop all services
down:
	docker compose down

# Build all Docker images
build:
	docker compose build

# Start databases only (for local dev)
dev-infra:
	docker compose up -d postgres redis

# Run frontend in dev mode
dev-frontend:
	cd frontend && npm install && npm run dev

# Build all Go services
build-go:
	@for svc in api-gateway scan-orchestrator inventory-service analysis-engine report-service; do \
		echo "Building $$svc..."; \
		cd backend/$$svc && go build ./... && cd ../..; \
	done

# Build collector agent (Windows binary) — also placed at repo root for Docker mount
build-agent:
	cd collector/agent && GOOS=windows GOARCH=amd64 go build -o ../../yama-agent.exe .
	@echo "Built yama-agent.exe — restart scan-orchestrator to pick it up"

# Run DB migrations
migrate:
	docker exec -i ad_postgres psql -U adassess -d adassessment < backend/shared/migrations/001_init.sql

# View logs
logs:
	docker compose logs -f

# Generate API key for a new agent (helper)
gen-apikey:
	openssl rand -hex 32
