FROM golang:1.22-alpine AS builder
WORKDIR /workspace
ENV GOWORK=off
COPY shared/ ./shared/
COPY inventory-service/ ./inventory-service/
WORKDIR /workspace/inventory-service
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/service .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/service ./inventory-service
EXPOSE 8082
CMD ["./inventory-service"]
