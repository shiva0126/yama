FROM golang:1.22-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off
COPY shared/ ./shared/
COPY scan-orchestrator/ ./scan-orchestrator/
WORKDIR /workspace/scan-orchestrator
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/service .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./scan-orchestrator
# yama-agent.exe is mounted at runtime via docker-compose volume (see build-agent)
EXPOSE 8081
ENV AGENT_BINARY_PATH=/app/yama-agent.exe
CMD ["./scan-orchestrator"]
