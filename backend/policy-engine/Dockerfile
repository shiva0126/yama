FROM golang:1.22-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off
COPY defense-shared/ ./defense-shared/
COPY policy-engine/ ./policy-engine/
WORKDIR /workspace/policy-engine
RUN go mod download && (cd /workspace/defense-shared && go mod download)
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -ldflags="-s -w" -o /app/service .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./policy-engine
EXPOSE 8097
CMD ["./policy-engine"]
