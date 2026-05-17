.PHONY: build test lint dev dev-stop dev-setup dev-cluster dev-freeradius dev-metrics dev-secret dev-logs dev-forward radsec-smoketest scep-smoketest clean

BINARY          = pint
STUB            = freeipa-stub
CLUSTER         = pint-dev
NAMESPACE       = pint
FR_IMAGE        = pint-freeradius:dev
PINT_IMAGE      = pint:dev
SMOKETEST_IMAGE = pint-smoketest:dev
SMOKETEST_POD   = pint-radsec-smoketest
SCEP_PINT_URL  ?= http://localhost:8080
GIT_COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
VERSION_PKG      = github.com/ComputerScienceHouse/pint/internal/version
LDFLAGS          = -ldflags "-X $(VERSION_PKG).GitCommit=$(GIT_COMMIT)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/pint/

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

# Full one-shot setup: create kind cluster, deploy chart, build FreeRADIUS image,
# and install metrics-server so the /status page shows pod CPU/memory.
# Run once before 'make dev'.  Safe to re-run (idempotent).
dev-setup: dev-cluster dev-freeradius dev-metrics
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

# Install metrics-server in the kind cluster with --kubelet-insecure-tls so the
# /status page can show pod CPU/memory usage.  Safe to re-run.
dev-metrics:
	kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
	kubectl patch deployment metrics-server -n kube-system \
		--type='json' \
		-p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
	kubectl rollout status deployment/metrics-server -n kube-system --timeout=90s

# Build FreeRADIUS and PINT dev images, load them into kind, and trigger a rollout.
# Both images are needed: FreeRADIUS runs the RADIUS server; the PINT image
# provides the radsec-agent sidecar for HAProxy agent-check health probes.
dev-freeradius:
	docker build -t $(FR_IMAGE) dev/freeradius/
	docker build -t $(PINT_IMAGE) .
	kind load docker-image $(FR_IMAGE) --name $(CLUSTER)
	kind load docker-image $(PINT_IMAGE) --name $(CLUSTER)
	kubectl rollout restart deployment/pint-freeradius -n $(NAMESPACE) 2>/dev/null || true

# Create the envSecret K8s Secret from .env.dev so PINT can run in-cluster.
# The release name is "pint" so the secret name matches the chart default (envSecret=<fullname>="pint").
# Only needed if you want to run PINT in kind (pint.enabled=true) rather than locally.
dev-secret:
	kubectl create secret generic pint \
		--namespace $(NAMESPACE) \
		--from-env-file=.env.dev \
		--dry-run=client -o yaml | kubectl apply -f -

# Stream FreeRADIUS logs.
dev-logs:
	kubectl logs -n $(NAMESPACE) -l app.kubernetes.io/name=pint-freeradius -f

# Port-forward RadSec to localhost:2083 (alternative to NodePort 32083).
dev-forward:
	kubectl port-forward -n $(NAMESPACE) service/pint-freeradius 2083:2083

# ── SCEP smoke test ───────────────────────────────────────────────────────────

# Tests initial SCEP enrollment (PKCSReq) and certificate renewal (RenewalReq)
# against the local dev stack (make dev must be running).
# Requires: brew install strongswan
scep-smoketest:
	PINT_URL=$(SCEP_PINT_URL) bash dev/scep-smoketest/run-scep-smoketest.sh

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
	docker build -t $(PINT_IMAGE) .

# ── Cleanup ────────────────────────────────────────────────────────────────────

clean:
	rm -f $(BINARY) $(STUB)
	pkill -x $(STUB) 2>/dev/null || true
