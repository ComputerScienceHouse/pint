.PHONY: build test lint dev dev-stop dev-setup dev-cluster dev-freeradius dev-secret dev-logs dev-forward radsec-smoketest clean

BINARY          = pint
STUB            = freeipa-stub
CLUSTER         = pint-dev
NAMESPACE       = pint
FR_IMAGE        = pint-freeradius:dev
SMOKETEST_IMAGE = pint-smoketest:dev
SMOKETEST_POD   = pint-radsec-smoketest

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
	@which overmind > /dev/null || (echo "Error: overmind not installed. Run: brew install overmind" && exit 1)
	overmind start

# ── Kubernetes dev cluster ─────────────────────────────────────────────────────

# Full one-shot setup: create kind cluster, deploy chart, build FreeRADIUS image.
# Run once before 'make dev'.  Safe to re-run (idempotent).
dev-setup: dev-cluster dev-freeradius
	@echo ""
	@echo "Dev cluster ready.  Fill in .env.dev then run:  make dev"
	@echo "To watch FreeRADIUS:                            make dev-logs"

# Create kind cluster (with NodePort 32083 for RadSec) and install the Helm chart.
dev-cluster:
	@which kind > /dev/null || (echo "Error: kind not installed. See https://kind.sigs.k8s.io/docs/user/quick-start/#installation" && exit 1)
	@which helm > /dev/null || (echo "Error: helm not installed. See https://helm.sh/docs/intro/install/" && exit 1)
	@kind get clusters 2>/dev/null | grep -q $(CLUSTER) \
		|| kind create cluster --name $(CLUSTER) --config dev/kind-cluster.yaml
	helm upgrade --install pint chart/ \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--values chart/values-dev.yaml

# Build FreeRADIUS dev image, load it into kind, and trigger a rollout.
dev-freeradius:
	docker build -t $(FR_IMAGE) dev/freeradius/
	kind load docker-image $(FR_IMAGE) --name $(CLUSTER)
	kubectl rollout restart deployment/pint-freeradius -n $(NAMESPACE) 2>/dev/null || true

# Create the pint-env K8s Secret from .env.dev so PINT can run in-cluster.
# Only needed if you want to run PINT in kind (pint.enabled=true) rather than locally.
dev-secret:
	kubectl create secret generic pint-env \
		--namespace $(NAMESPACE) \
		--from-env-file=.env.dev \
		--dry-run=client -o yaml | kubectl apply -f -

# Stream FreeRADIUS logs.
dev-logs:
	kubectl logs -n $(NAMESPACE) -l app.kubernetes.io/name=pint-freeradius -f

# Port-forward RadSec to localhost:2083 (alternative to NodePort 32083).
dev-forward:
	kubectl port-forward -n $(NAMESPACE) service/pint-freeradius 2083:2083

# ── RadSec smoke test ─────────────────────────────────────────────────────────

# Issues test certs via the FreeIPA stub, then runs eapol_test against FreeRADIUS
# inside the kind cluster using radsecproxy as a UDP→RadSec bridge.
# Requires: make dev running (stub on :8088, FreeRADIUS in cluster).
radsec-smoketest:
	docker build -t $(SMOKETEST_IMAGE) dev/smoketest/
	kind load docker-image $(SMOKETEST_IMAGE) --name $(CLUSTER)
	SMOKETEST_IMAGE=$(SMOKETEST_IMAGE) SMOKETEST_POD=$(SMOKETEST_POD) NAMESPACE=$(NAMESPACE) \
		bash dev/smoketest/run-smoketest.sh

# ── Docker build ───────────────────────────────────────────────────────────────

docker-build:
	docker build -t pint:dev .

# ── Cleanup ────────────────────────────────────────────────────────────────────

clean:
	rm -f $(BINARY) $(STUB)
	pkill -x $(STUB) 2>/dev/null || true
