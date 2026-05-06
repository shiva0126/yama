FROM golang:1.22-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off
COPY defense-shared/ ./defense-shared/
COPY defense-api/ ./defense-api/
WORKDIR /workspace/defense-api
RUN go mod download && (cd /workspace/defense-shared && go mod download)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/service .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./defense-api
EXPOSE 8098
CMD ["./defense-api"]
