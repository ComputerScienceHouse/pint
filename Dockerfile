FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o pint ./cmd/pint/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/pint .
COPY --from=builder /build/templates ./templates

EXPOSE 8080
ENTRYPOINT ["./pint"]
