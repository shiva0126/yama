FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o yama-agent .

# ── runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates wget

WORKDIR /app
COPY --from=builder /build/yama-agent .

# PowerShell modules are mounted at runtime via volume (./collector/powershell -> /app/powershell)
# Create placeholder dir so the container starts even without the volume
RUN mkdir -p /app/powershell/modules /app/csharp/bin

ENV AGENT_API_KEY=""
ENV AGENT_PORT="9090"

EXPOSE 9090

ENTRYPOINT ["/app/yama-agent"]
CMD ["--port", "9090", "--ps-dir", "/app/powershell/modules", "--cs-dir", "/app/csharp/bin"]
