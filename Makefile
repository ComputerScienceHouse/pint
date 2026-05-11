.PHONY: build test lint dev dev-stop clean

BINARY=pint
STUB=freeipa-stub

build:
	go build -o $(BINARY) ./cmd/pint/

build-stub:
	go build -o $(STUB) ./dev/freeipa-stub/

test:
	go test ./... -v

lint:
	go vet ./...

dev: build build-stub
	@pkill -x $(STUB) 2>/dev/null || true
	@echo "Starting FreeIPA stub on :8088..."
	@set -a && . .env.dev && set +a && ./$(STUB) &
	@sleep 1
	@echo "Starting PINT..."
	@set -a && . .env.dev && set +a && ./$(BINARY)

k8s-dev:
	kubectl apply -f k8s/dev-deploy.yaml

docker-build:
	docker build -t pint:dev .

clean:
	rm -f $(BINARY) $(STUB)
	pkill $(STUB) 2>/dev/null || true
