FROM golang:1.23-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off
COPY defense-shared/ ./defense-shared/
COPY correlation-engine/ ./correlation-engine/
WORKDIR /workspace/correlation-engine
RUN go mod download && (cd /workspace/defense-shared && go mod download)
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -ldflags="-s -w" -o /app/service .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./correlation-engine
EXPOSE 8094
CMD ["./correlation-engine"]
