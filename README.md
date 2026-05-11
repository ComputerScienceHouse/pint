# PINT - Pouring IPA for Network Trust

PINT is a self-service web portal for [Computer Science House](https://csh.rit.edu) that migrates WiFi authentication from EAP-MSCHAPv2 (password-based) to EAP-TLS (certificate-based). Members log in with their CSH Keycloak account and receive a certificate-backed WiFi profile that works on iOS, macOS, and Android. Home router operators can also provision a RADIUS shared secret and download a RadSec client certificate for internet-facing [RFC 6614](https://www.rfc-editor.org/rfc/rfc6614) connectivity.

## What it does

| Feature | How |
|---|---|
| **iOS / macOS WiFi profile** | Generates an Apple mobileconfig (`.mobileconfig`) containing a FreeIPA-issued EAP-TLS client certificate, the WiFi CA, and 802.1X config. Install it and connect - no password needed. |
| **Android WiFi profile** | Generates a PKCS#12 (`.p12`) bundle with the same certificate for import into Android's WiFi settings. |
| **Home router (RadSec)** | Members can register a RADIUS shared secret and download a RadSec client certificate (`.p12`) to configure a home router for [RFC 6614 RADIUS over TLS](https://www.rfc-editor.org/rfc/rfc6614) on port 2083. |
| **CA distribution** | One-tap download of the WiFi CA and RadSec CA certificates for manual trust store installation. |

## Architecture

```
Browser → Gin HTTP server (port 8080)
            │
            ├─ csh-auth/v2 (Keycloak OIDC cookie middleware)
            │
            ├─ FreeIPA JSON RPC (/ipa/json)
            │    └─ ca_show, cert_request
            │
            └─ Kubernetes API
                 ├─ Secret: pint-radius-clients   (clients.json)
                 ├─ Secret: pint-radius-config    (clients.conf)
                 ├─ Secret: pint-radsec-server    (tls.crt, tls.key)
                 └─ pods/exec → FreeRADIUS SIGHUP
```

Single stateless Go binary, server-rendered HTML templates, no database. All persistent state lives in Kubernetes Secrets. The FreeRADIUS server cert is loaded from the `pint-radsec-server` Secret at startup and renewed via FreeIPA if absent or within 30 days of expiry.

## Routes

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/` | public | Landing page |
| GET | `/auth/login` | public | Begin Keycloak OIDC flow |
| GET | `/auth/callback` | public | OIDC callback |
| GET | `/auth/logout` | public | Clear session cookie |
| GET | `/dashboard` | required | Member home |
| GET | `/profile` | required | Profile generation page |
| POST | `/profile/generate` | required | Issue cert, return mobileconfig (iOS/macOS) or PKCS#12 (Android) |
| GET | `/profile/ca` | required | Download WiFi CA cert |
| GET | `/radius` | required | RADIUS management page |
| POST | `/radius/secret` | required | Register / update RADIUS shared secret |
| POST | `/radius/delete` | required | Remove RADIUS entry |
| GET | `/radius/client-cert` | required | Issue and download RadSec client cert (PKCS#12) |
| GET | `/radius/ca` | required | Download RadSec CA cert |

## Prerequisites

- CSH Keycloak OIDC client (`pint` or similar)
- FreeIPA with:
  - A `pint_wifi` certificate profile for member EAP-TLS certs
  - A `pint_radsec` certificate profile for router client certs
  - An intermediate CA for RadSec (distinct from the WiFi CA)
  - A service account with permission to call `ca_show` and `cert_request`
- FreeRADIUS running as a sidecar pod in the `pint` namespace, with pod label matching `PINT_FREERADIUS_POD_SELECTOR`
- Kubernetes RBAC (provided in `k8s/dev-deploy.yaml`)

## Configuration

All config is read from environment variables. Copy `.env.dev.example` to `.env.dev` and fill in real values.

| Variable | Description |
|---|---|
| `PINT_CLIENT_ID` | Keycloak OIDC client ID |
| `PINT_CLIENT_SECRET` | Keycloak OIDC client secret |
| `PINT_SERVER_URL` | Base URL of this service (e.g. `https://pint.csh.rit.edu`) |
| `PINT_LOGIN_URL` | Full URL of the login route |
| `PINT_CALLBACK_URL` | Full URL of the OIDC callback route |
| `PINT_IPA_HOST` | FreeIPA host and port (e.g. `ipa.csh.rit.edu:443`) |
| `PINT_IPA_SERVICE_ACCOUNT` | FreeIPA service account username |
| `PINT_IPA_PASSWORD` | FreeIPA service account password |
| `PINT_IPA_CA_NAME` | FreeIPA CA name for WiFi certs |
| `PINT_IPA_RADSEC_CA_NAME` | FreeIPA CA name for RadSec certs |
| `PINT_IPA_SKIP_TLS_VERIFY` | Set `true` to skip TLS verification (dev only) |
| `PINT_WIFI_SSID` | SSID name to embed in WiFi profiles |
| `PINT_NAMESPACE` | Kubernetes namespace |
| `PINT_RADIUS_CLIENTS_SECRET` | K8s Secret name for RADIUS client list |
| `PINT_RADIUS_CONFIG_SECRET` | K8s Secret name for `clients.conf` |
| `PINT_RADSEC_CERT_SECRET` | K8s Secret name for FreeRADIUS TLS cert/key |
| `PINT_FREERADIUS_POD_SELECTOR` | Label selector for the FreeRADIUS pod (e.g. `app=freeradius`) |
| `PINT_RADIUS_SERVER` | RadSec server address shown to users (e.g. `radius.csh.rit.edu:2083`) |

## Local development

The repo includes a FreeIPA stub server that generates a real CA at startup and handles `ca_show` and `cert_request` RPC calls.

```bash
# 1. Copy and edit the dev env file
cp .env.dev.example .env.dev
# (edit .env.dev - the stub defaults work as-is for IPA fields)

# 2. Build and start everything
make dev
```

`make dev` builds both binaries, starts the FreeIPA stub on `:8088` in the background, then starts PINT on `:8080` with env vars sourced from `.env.dev`.

Other useful targets:

```
make build        # compile pint binary
make build-stub   # compile freeipa-stub binary
make test         # go test ./... -v
make lint         # go vet ./...
make docker-build # docker build -t pint:dev .
make clean        # remove binaries, kill stub
```

## Deployment

### Build the image

```bash
docker build -t pint:latest .
```

### Create the env secret

```bash
kubectl create secret generic pint-env \
  --from-literal=PINT_CLIENT_ID=pint \
  --from-literal=PINT_CLIENT_SECRET=<secret> \
  --from-literal=PINT_SERVER_URL=https://pint.csh.rit.edu \
  --from-literal=PINT_LOGIN_URL=https://pint.csh.rit.edu/auth/login \
  --from-literal=PINT_CALLBACK_URL=https://pint.csh.rit.edu/auth/callback \
  # ... (all other PINT_* vars)
```

### Apply manifests (Local Dev)

```bash
# Apply the development manifest (uses pint:dev image)
make k8s-dev
```

The manifests live in `k8s/`. Production resources are managed directly in OpenShift.

## Testing

```bash
make test
```

Tests cover the FreeIPA client (including 401 re-auth), certificate generation, mobileconfig generation, RADIUS store CRUD, config rendering, and Gin handlers. The FreeIPA client tests use an `httptest` server; handler tests inject a `*cshauth.Claims` directly into the Gin context.
