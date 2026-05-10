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
	@echo "Starting FreeIPA stub on :8088..."
	./$(STUB) &
	@echo "Starting PINT..."
	@set -a && . .env.dev && set +a && ./$(BINARY)

k8s-dev:
	kubectl apply -k deploy/overlays/dev

k8s-prod:
	kubectl apply -k deploy/overlays/prod

docker-build:
	docker build -t pint:dev .

clean:
	rm -f $(BINARY) $(STUB)
	pkill $(STUB) 2>/dev/null || true
