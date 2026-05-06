FROM golang:1.22-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off

# Build the Linux orchestrator service
COPY backend/shared/ ./shared/
COPY backend/scan-orchestrator/ ./scan-orchestrator/
WORKDIR /workspace/scan-orchestrator
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/service .

# Cross-compile the Windows collector agent binary
WORKDIR /workspace/collector-agent
COPY collector/agent/ .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o /app/yama-agent.exe .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./scan-orchestrator
COPY --from=builder /app/yama-agent.exe ./yama-agent.exe
EXPOSE 8081
ENV AGENT_BINARY_PATH=/app/yama-agent.exe
CMD ["./scan-orchestrator"]
