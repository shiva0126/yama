FROM golang:1.23-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off
COPY defense-shared/ ./defense-shared/
COPY evidence-ledger/ ./evidence-ledger/
WORKDIR /workspace/evidence-ledger
RUN go mod download && (cd /workspace/defense-shared && go mod download)
RUN go get github.com/minio/minio-go/v7@v7.0.70 && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -ldflags="-s -w" -o /app/service .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./evidence-ledger
EXPOSE 8096
CMD ["./evidence-ledger"]
