FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN git config --system --add safe.directory '*'
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X github.com/ComputerScienceHouse/pint/internal/version.GitCommit=$(git rev-parse --short HEAD)" \
    -o pint ./cmd/pint/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/pint .
COPY --from=builder /build/templates ./templates

EXPOSE 8080
ENTRYPOINT ["./pint"]
