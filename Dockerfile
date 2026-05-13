FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod main.go ./
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o qr-auth .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/qr-auth .
EXPOSE 8080
USER 65534
CMD ["./qr-auth"]
