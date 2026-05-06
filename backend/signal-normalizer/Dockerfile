FROM golang:1.22-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off
COPY defense-shared/ ./defense-shared/
COPY signal-normalizer/ ./signal-normalizer/
WORKDIR /workspace/signal-normalizer
RUN go mod download && (cd /workspace/defense-shared && go mod download)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/service .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./signal-normalizer
EXPOSE 8092
CMD ["./signal-normalizer"]
