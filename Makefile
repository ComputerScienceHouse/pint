.PHONY: build test lint dev dev-stop dev-setup dev-cluster dev-freeradius dev-logs dev-forward clean

BINARY    = pint
STUB      = freeipa-stub
CLUSTER   = pint-dev
NAMESPACE = pint
FR_IMAGE  = pint-freeradius:dev

build:
	go build -o $(BINARY) ./cmd/pint/

build-stub:
	go build -o $(STUB) ./dev/freeipa-stub/

test:
	go test ./... -v

lint:
	go vet ./...

# ── Local dev ──────────────────────────────────────────────────────────────────

dev: build build-stub
	@pkill -x $(STUB) 2>/dev/null || true
	@echo "Starting FreeIPA stub on :8088..."
	@set -a && . .env.dev && set +a && ./$(STUB) &
	@sleep 1
	@echo "Starting PINT on :8080..."
	@set -a && . .env.dev && set +a && ./$(BINARY)

dev-stop:
	@pkill -x $(STUB) 2>/dev/null || true
	@pkill -x $(BINARY) 2>/dev/null || true

# ── Kubernetes dev cluster ─────────────────────────────────────────────────────

# Full one-shot setup: create cluster, deploy RBAC, build and load FreeRADIUS.
# Run once before 'make dev'.  Safe to re-run (idempotent).
dev-setup: dev-cluster dev-freeradius
	@echo ""
	@echo "Dev cluster ready.  Fill in .env.dev then run:  make dev"

# Create kind cluster with port 32083 exposed for RadSec, then apply RBAC.
dev-cluster:
	@which kind > /dev/null || (echo "Error: kind not installed. See https://kind.sigs.k8s.io/docs/user/quick-start/#installation" && exit 1)
	@kind get clusters 2>/dev/null | grep -q $(CLUSTER) \
		|| kind create cluster --name $(CLUSTER) --config dev/kind-cluster.yaml
	@kubectl get namespace $(NAMESPACE) 2>/dev/null || kubectl create namespace $(NAMESPACE)
	kubectl apply -f k8s/dev-deploy.yaml

# Build FreeRADIUS dev image and load it into the kind cluster.
dev-freeradius:
	docker build -t $(FR_IMAGE) dev/freeradius/
	kind load docker-image $(FR_IMAGE) --name $(CLUSTER)
	kubectl rollout restart deployment/freeradius -n $(NAMESPACE) 2>/dev/null || true

# Stream FreeRADIUS logs (useful for watching auth attempts).
dev-logs:
	kubectl logs -n $(NAMESPACE) -l app=freeradius -f

# Port-forward RadSec to localhost:2083 (alternative to NodePort 32083).
dev-forward:
	kubectl port-forward -n $(NAMESPACE) service/freeradius 2083:2083

# ── Docker / K8s production build ──────────────────────────────────────────────

k8s-dev:
	kubectl apply -f k8s/dev-deploy.yaml

docker-build:
	docker build -t pint:dev .

# ── Cleanup ────────────────────────────────────────────────────────────────────

clean:
	rm -f $(BINARY) $(STUB)
	pkill -x $(STUB) 2>/dev/null || true
