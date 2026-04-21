FROM golang:1.22-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off
COPY shared/ ./shared/
COPY analysis-engine/ ./analysis-engine/
WORKDIR /workspace/analysis-engine
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/service .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./analysis-engine
EXPOSE 8083
CMD ["./analysis-engine"]
