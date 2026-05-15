# PINT: Pouring IPA for Network Trust

PINT is a self-service WiFi enrollment portal for [Computer Science House](https://csh.rit.edu). Members log in with their CSH Keycloak account and PINT issues them a certificate from FreeIPA. That certificate is used to authenticate to the WiFi network via EAP-TLS, with no passwords involved. WiFi controllers (home routers, etc.) can also enroll for a RadSec client certificate to proxy authentication back to FreeRADIUS over a mutual-TLS connection.

PINT is a single stateless Go binary. There is no database. All persistent state lives in Kubernetes Secrets that FreeRADIUS mounts directly.

```mermaid
flowchart TD
    U(Member Device) -->|OIDC login\nprofile download| P[PINT :8080]
    U -->|EAP-TLS / 802.1X| C(WiFi Controller)
    C -->|RadSec mTLS\nport 2083| FR[FreeRADIUS]

    P -->|cert_request\nca_show| IPA[(FreeIPA)]
    P -->|write config\nwrite certs| KS[(Kubernetes\nSecrets)]
    P -->|rollout restart| FR

    KS -->|mounted at runtime| FR
```

---

## PINT

### Certificate Generation via FreeIPA

Every certificate PINT issues follows the same path: generate a secp384r1 ECDSA keypair locally, build a CSR, and call FreeIPA's `cert_request` RPC with the appropriate CA and profile. FreeIPA's Dogtag CA signs the cert and returns the DER-encoded result. The private key never leaves PINT; it is either bundled into the download or shown once and discarded.

```mermaid
sequenceDiagram
    participant Client as Browser / CLI
    participant P as PINT
    participant IPA as FreeIPA (Dogtag)

    Client->>P: Request enrollment
    P->>P: Generate secp384r1 keypair + CSR
    P->>IPA: cert_request(CSR, principal, CA, profile)
    IPA-->>P: Signed certificate (DER)
    P->>P: Bundle into profile / p12 / PEM
    P-->>Client: Download
```

PINT authenticates to FreeIPA using a service account specified by `PINT_IPA_SERVICE_ACCOUNT` and `PINT_IPA_PASSWORD`. The session is established at startup and re-authenticated automatically on 401.

#### Profiles

Three custom Dogtag certificate profiles control validity, key usage, and subject enforcement. All profiles force `O=CSH.RIT.EDU` in the issued certificate subject regardless of what the CSR contains, and all require secp384r1 EC keys.

| Profile | Purpose | Validity | EKU |
|---|---|---|---|
| `pint_wifi` | EAP-TLS client certs for member devices | 5 years | `clientAuth` |
| `pint_radsec_client` | mTLS client certs for WiFi controllers | 5 years | `clientAuth` |
| `pint_radsec_server` | mTLS server cert for the FreeRADIUS RadSec listener | 90 days | `serverAuth` |
| `pint_profile_signing` | CMS signing cert for iOS mobileconfig profiles | 1 year | `codeSigning` |

Five-year validity on client certs minimises re-enrollment burden. The 90-day server cert and 1-year profile signing cert are automatically renewed by PINT (see [RadSec Server Cert](#radsec-server-cert) and [Profile Signing Cert](#profile-signing-cert)).

Profile config files live in `ipa/profiles/`. They must be imported into FreeIPA once before PINT can use them. Use `ipa/update_profile.py`, which supports three actions:

| Action | FreeIPA call | When to use |
|---|---|---|
| `update` | `certprofile_mod` | Profile already exists; push changes |
| `show` | `certprofile_show` | Inspect what is currently deployed |
| `reimport` | `certprofile_del` + `certprofile_import` | Profile config is missing from FreeIPA (first import or after manual Dogtag changes) |

```bash
cd ipa
python3 update_profile.py
```

The corresponding environment variables (all optional; defaults shown):

```
PINT_IPA_CERT_PROFILE=pint_wifi
PINT_IPA_RADSEC_CLIENT_CERT_PROFILE=pint_radsec_client
PINT_IPA_RADSEC_SERVER_CERT_PROFILE=pint_radsec_server
PINT_IPA_CODE_SIGNING_CERT_PROFILE=pint_profile_signing
```

### WiFi Profile Generation

Members visit `/profile` and download a platform-specific package. PINT issues a fresh certificate on each download.

| Platform | Output | Contents |
|---|---|---|
| iOS / macOS | `.mobileconfig` (Apple Configuration Profile) | PKCS#12 identity, WiFi CA, root CA, 802.1X/EAP-TLS config; optionally CMS-signed |
| Android | `.p12` (PKCS#12) | Client cert + key + WiFi CA, imported via Android WiFi settings |
| Windows | `.xml` (WLAN profile) + `.p12` (PKCS#12) | EAP-TLS config and CA thumbprint; cert imported separately into the Windows certificate store |

The iOS mobileconfig always embeds the WiFi intermediate CA and root CA so the full trust chain is installed in one step. When `PINT_IPA_CODE_SIGNING_CA_NAME` is set, PINT also embeds the code-signing intermediate CA and wraps the profile in a CMS `SignedData` envelope, letting iOS display it as "Verified" after the CA profile is trusted.

### WiFi Controller Enrollment

Members running home routers or other WiFi controllers can enroll for a RadSec client certificate. This lets their equipment proxy 802.1X authentication requests back to FreeRADIUS over a mutual-TLS connection on port 2083.

**Enrollment:**
1. Member visits `/radius`, enters their controller's source IP, and clicks Enroll.
2. PINT generates a secp384r1 keypair and requests a `pint_radsec_client` certificate from FreeIPA.
3. The private key and certificate PEM are displayed **once**. PINT does not retain them.
4. PINT writes an updated `clients.conf` to the Kubernetes config Secret and triggers a FreeRADIUS rollout restart.
5. The member configures their router with the cert, key, and the RadSec CA chain (downloadable from `/radius/ca`). The RADIUS shared secret is always `radsec` (standard for RFC 6614).

**IP allowlist:** A source IP address is required at enrollment and when updating. Regular members must supply a single bare IP; CIDR ranges are rejected. Requests arriving from any other address are dropped by FreeRADIUS before authentication begins. Only the organisation-level controller (managed via `/admin/radius`) accepts a CIDR range or no restriction.

**Lifecycle:** Members can update their IP allowlist, regenerate credentials (revokes and replaces the cert), or delete their enrollment entirely at any time from `/radius`. Admins (RTP group) have the same controls over any member's enrollment via `/admin/radius`, and can provision an organisation-level controller (`root`) that is not tied to any member account.

### FreeRADIUS Control

PINT manages FreeRADIUS entirely through the Kubernetes API with no direct process communication.

```mermaid
flowchart LR
    P[PINT] -->|clients.json\nclients.conf\nradsec-tls.conf\nstatus config| CS[(pint-config\nSecret)]
    P -->|tls.crt · tls.key\nca.pem · wifi-ca.pem| RS[(pint-radsec-server-\ncertificates Secret)]
    P -->|tls.crt · tls.key| PS[(pint-profile-signing-\ncert Secret)]
    P -->|patch restartedAt\nannotation| D[pint-freeradius\nDeployment]
    CS -->|volume mount\n/etc/pint/config/| FR[FreeRADIUS Pod]
    RS -->|volume mount\n/etc/pint/radsec/| FR
```

**`pint-config` Secret:** PINT writes and owns all keys.

| Key | Description |
|---|---|
| `clients.json` | Enrolled controller list (PINT's source of truth) |
| `clients.conf` | FreeRADIUS client configuration rendered from `clients.json` |
| `radsec-tls.conf` | TLS block for the RadSec listener; CRL checking on/off via `PINT_RADIUS_RADSEC_CHECK_CRL` |
| `status` | Status virtual server client config |
| `status-secret` | Shared secret for status server queries |

**`pint-radsec-server-certificates` Secret:** TLS material for FreeRADIUS.

| Key | Description |
|---|---|
| `tls.crt` / `tls.key` | RadSec server certificate and private key |
| `ca.pem` | RadSec CA chain used to verify controller client certs |
| `wifi-ca.pem` | WiFi CA cert used to verify EAP-TLS user certs |

**`pint-profile-signing-cert` Secret:** CMS signing identity for iOS mobileconfig profiles. Only created when `PINT_IPA_CODE_SIGNING_CA_NAME` is set.

| Key | Description |
|---|---|
| `tls.crt` / `tls.key` | Profile signing certificate and private key |

When any config changes, PINT patches the FreeRADIUS Deployment's `kubectl.kubernetes.io/restartedAt` annotation, triggering a rolling restart that picks up the new Secret contents.

#### RadSec Server Cert

At startup, PINT checks whether the RadSec server certificate has more than 30 days of validity remaining. If the cert is missing or nearing expiry, PINT requests a new `pint_radsec_server` certificate from FreeIPA, writes it to the Secret, and triggers a FreeRADIUS restart. A background goroutine repeats this check every 24 hours, so renewals are fully automatic.

#### Profile Signing Cert

When `PINT_IPA_CODE_SIGNING_CA_NAME` is set, PINT manages a CMS signing certificate using the same pattern as the RadSec server cert. At startup it checks the `pint-profile-signing-cert` Secret; if the cert is missing or within 30 days of expiry, PINT requests a new `pint_profile_signing` certificate from FreeIPA and stores it. A background goroutine renews it daily as needed. Unlike the RadSec cert, a renewed profile signing cert takes effect on the next PINT restart (no FreeRADIUS reload is required).

The signature on a mobileconfig is only verified at installation time — existing installed profiles remain functional even if the signing cert later expires.

---

## FreeRADIUS

The FreeRADIUS image is built from `dev/freeradius/Dockerfile`. It contains the virtual server and module configuration that defines FreeRADIUS's behaviour; the runtime-variable parts (client lists, TLS config, certificate material) are injected by PINT via the Kubernetes Secrets described above.

### Configuration

Understanding what is baked into the image versus what PINT controls at runtime is key to debugging auth failures.

```mermaid
flowchart TB
    subgraph Image ["Baked into image"]
        R[radsec virtual server\n/etc/raddb/sites-enabled/radsec]
        S[status virtual server\n/etc/raddb/sites-enabled/status]
        E[eap module\n/etc/raddb/mods-enabled/eap]
    end

    subgraph Secrets ["Injected at runtime via K8s Secrets"]
        CC[clients.conf\n/etc/pint/config/]
        TLS[radsec-tls.conf\n/etc/pint/config/]
        ST[status config + secret\n/etc/pint/config/]
        CERT[tls.crt · tls.key\nwifi-ca.pem · ca.pem\n/etc/pint/radsec/]
    end

    R -->|"$-INCLUDE"| CC
    R -->|"$INCLUDE"| TLS
    S -->|"$-INCLUDE"| ST
    E --> CERT
```

**`radsec` virtual server** listens on TCP port 2083. It `$INCLUDE`s `radsec-tls.conf` (the TLS block PINT generates, containing cert paths and CRL settings) and `$-INCLUDE`s `clients.conf` (the enrolled controller list). The `$-INCLUDE` variant is FreeRADIUS syntax for an optional include; the server starts even if the file is absent, which lets FreeRADIUS boot before PINT has written its first config.

**`status` virtual server** listens on UDP port 18121. It `$-INCLUDE`s the status client config written by PINT, which defines which CIDRs may query the status server and the shared secret required to do so.

**`eap` module** configures EAP-TLS as the only permitted EAP type. It references the cert files from the `pint-radsec-server-certificates` Secret directly: `tls.crt`, `tls.key`, and `wifi-ca.pem`. The same server certificate is used for both the RadSec listener TLS and EAP-TLS inner authentication.

### RadSec Server

RadSec is RADIUS-over-TLS (RFC 6614). Instead of UDP with a shared secret, controllers open a persistent TCP connection on port 2083 and authenticate with a mutual-TLS handshake. Once the TLS session is established, standard RADIUS packets flow over it.

```mermaid
sequenceDiagram
    participant C as WiFi Controller
    participant FR as FreeRADIUS :2083
    participant EAP as EAP-TLS Module

    C->>FR: TCP connect
    C->>FR: TLS handshake (mutual)
    note over C,FR: Controller presents pint_radsec_client cert<br>FreeRADIUS presents pint_radsec_server cert<br>Both verified against respective CAs
    C->>FR: RADIUS Access-Request (user EAP-TLS identity)
    FR->>EAP: Begin EAP-TLS exchange
    EAP-->>C: EAP-Request (TLS handshake fragments)
    C-->>EAP: EAP-Response (user cert)
    EAP->>EAP: Validate user cert against wifi-ca.pem
    EAP-->>FR: Accept / Reject
    FR-->>C: RADIUS Access-Accept / Access-Reject
```

Source IP allowlists are enforced in `clients.conf` before any authentication occurs. A controller arriving from an unexpected IP is silently dropped at the RADIUS layer.

### EAP Module

EAP-TLS is the only supported authentication method with no password fallback. During the EAP exchange, FreeRADIUS validates the user's client certificate against `wifi-ca.pem` (the WiFi intermediate CA). Only certificates issued through PINT's `pint_wifi` profile will pass, since that profile enforces `clientAuth` EKU and the CA is not publicly trusted.

TLS 1.2 is the minimum version. The cipher list is restricted to `ECDHE+AESGCM:DHE+AESGCM` with `secp384r1` as the negotiated ECDH curve, matching the EC keys in all PINT-issued certificates.

### Status Server

FreeRADIUS exposes a status virtual server on UDP port 18121. PINT queries each pod's status server directly (by pod IP, not through the Service) to surface per-pod statistics on the `/status` page: authentication counters, reject counts, and uptime. The shared secret is stored in `pint-config` under `status-secret`. PINT generates it once on first startup; subsequent restarts reuse the existing value.

---

## Deployment

### Helm Chart

The chart in `chart/` deploys both PINT and FreeRADIUS into a single namespace and wires up the Kubernetes RBAC, Secrets, ConfigMap, and Services they need.

Key values:

```yaml
# Container images; default tags come from Chart.appVersion
pint:
  image:
    repository: pint
    tag: ""

freeradius:
  image:
    repository: pint-freeradius
    tag: ""

# Non-sensitive config rendered into a ConfigMap
config:
  clientID: ""
  serverURL: ""
  ipaHost: ""
  ipaServiceAccount: ""
  wifiSSID: "CSH"
  radiusServer: ""
  # ... (see chart/values.yaml for full list)

# Pre-existing Secret with sensitive credentials (see below)
envSecret: ""

# OpenShift Route (disabled by default)
openshift:
  enabled: false
  route:
    host: ""
```

The FreeRADIUS Service defaults to `LoadBalancer` so port 2083 gets an external IP. In environments without a load balancer (like the dev kind cluster), set `freeradius.service.type=NodePort` and specify a `nodePort`.

To disable the in-cluster PINT deployment and run PINT locally instead (useful during development):

```yaml
pint:
  enabled: false
```

### Publishing

The chart is published to GitHub Pages via `helm/chart-releaser-action` on every push to `main` or `dev` that touches `chart/**`.

- **`main`**: releases the version declared in `chart/Chart.yaml` as a stable release.
- **`dev`**: stamps the version as `<version>-dev.<run_number>` (e.g. `0.1.0-dev.42`) and publishes a pre-release. Useful for testing chart changes before merging.

To add the Helm repository:

```bash
helm repo add pint https://computersciencehouse.github.io/pint
helm repo update
```

### Credentials Secret

PINT splits config into two Kubernetes objects:

- **ConfigMap**: rendered automatically by the chart from the `config:` values block. Contains all non-sensitive settings (`PINT_IPA_HOST`, `PINT_WIFI_SSID`, etc.).
- **Secret**: must be created manually before deploying. Contains only the two sensitive credentials:

```bash
kubectl create secret generic <release-name> -n pint \
  --from-literal=PINT_CLIENT_SECRET=<oidc-secret> \
  --from-literal=PINT_IPA_PASSWORD=<ipa-password>
```

Set `envSecret` in your values to the name of this Secret. The chart's PINT Deployment mounts both objects as environment variables.

---

## Development

### Dependencies

| Tool | Purpose |
|---|---|
| Go 1.26+ | Build PINT and the FreeIPA stub |
| Docker | Build images |
| `kind` | Local Kubernetes cluster for FreeRADIUS |
| `helm` | Deploy the chart into kind |
| `kubectl` | Interact with the dev cluster |
| `overmind` | Run the Procfile (PINT + FreeIPA stub simultaneously) |

### Local Setup

```bash
# One-time: create the kind cluster, install the Helm chart,
# build the FreeRADIUS image, and install metrics-server.
# Safe to re-run; skips steps already complete.
make dev-setup

# Copy and edit the dev env file.
# The stub defaults work for all IPA_* fields out of the box.
cp .env.dev.example .env.dev

# Build both binaries and start everything.
make dev
```

`make dev` starts two processes via `overmind` and the `Procfile`:

- **`ipa-stub`**: FreeIPA stub server on `:8088` (see [FreeIPA Stub](#freeipa-stub) below).
- **`pint`**: the PINT server on `:8080`. It waits for the stub to be ready before starting.

FreeRADIUS runs in the kind cluster and persists between `make dev` sessions. PINT talks to it via the Kubernetes API using your local `~/.kube/config`.

To access RTP-gated routes (`/status` reload button, `/admin/radius`) locally, set `PINT_DEV_RTP=true` in `.env.dev`.

**Other useful targets:**

```
make build           # compile pint binary
make build-stub      # compile freeipa-stub binary
make test            # go test ./... -v
make lint            # go vet ./...
make dev-logs        # stream FreeRADIUS logs from the kind cluster
make dev-forward     # port-forward RadSec to localhost:2083
make dev-metrics     # (re-)install metrics-server (enables CPU/memory on /status)
make docker-build    # build pint:dev Docker image
make clean           # remove binaries, kill stub process
```

### Configuration Reference

All configuration is via environment variables. Copy `.env.dev.example` to `.env.dev` to get started.

**Required:**

| Variable | Description |
|---|---|
| `PINT_CLIENT_ID` | Keycloak OIDC client ID |
| `PINT_CLIENT_SECRET` | Keycloak OIDC client secret |
| `PINT_SERVER_URL` | Public base URL (e.g. `https://pint.csh.rit.edu`) |
| `PINT_IPA_HOST` | FreeIPA hostname (e.g. `ipa.csh.rit.edu`) |
| `PINT_IPA_SERVICE_ACCOUNT` | FreeIPA service account DN (`krbprincipalname=pint/host@REALM,...`) |
| `PINT_IPA_PASSWORD` | FreeIPA service account password |
| `PINT_WIFI_SSID` | SSID embedded in generated WiFi profiles |
| `PINT_RADIUS_SERVER` | RadSec endpoint shown to users (e.g. `radius.csh.rit.edu:2083`) |

**Optional (defaults shown):**

| Variable | Default | Description |
|---|---|---|
| `PINT_IPA_WIRELESS_CA_NAME` | `wireless` | FreeIPA CA for WiFi client certs |
| `PINT_IPA_RADSEC_CA_NAME` | `radsec` | FreeIPA CA for RadSec certs |
| `PINT_IPA_ROOT_CA_NAME` | `ipa` | Root signing CA |
| `PINT_IPA_CERT_PROFILE` | `pint_wifi` | Dogtag profile for WiFi certs |
| `PINT_IPA_RADSEC_CLIENT_CERT_PROFILE` | `pint_radsec_client` | Dogtag profile for controller certs |
| `PINT_IPA_RADSEC_SERVER_CERT_PROFILE` | `pint_radsec_server` | Dogtag profile for the RadSec server cert |
| `PINT_IPA_CODE_SIGNING_CA_NAME` | _(unset)_ | FreeIPA intermediate CA for profile signing certs; enables iOS mobileconfig signing when set |
| `PINT_IPA_CODE_SIGNING_CERT_PROFILE` | `pint_profile_signing` | Dogtag profile for the profile signing cert |
| `PINT_PROFILE_SIGNING_CERT_SECRET` | `pint-profile-signing-cert` | K8s Secret for the profile signing cert and key |
| `PINT_NAMESPACE` | `pint` | Kubernetes namespace |
| `PINT_CONFIG_SECRET` | `pint-config` | K8s Secret for RADIUS config |
| `PINT_RADSEC_CERT_SECRET` | `pint-radsec-server-certificates` | K8s Secret for RadSec TLS material |
| `PINT_FREERADIUS_DEPLOYMENT` | `pint-freeradius` | FreeRADIUS Deployment name |
| `PINT_RADIUS_STATUS_PORT` | `18121` | FreeRADIUS status server port |
| `PINT_RADIUS_RADSEC_CHECK_CRL` | `true` | Enable CRL checking in the RadSec TLS listener |
| `PINT_IPA_SKIP_TLS_VERIFY` | `false` | Skip FreeIPA TLS verification (dev only) |
| `PINT_DISABLE_OIDC` | `false` | Bypass OIDC and inject a static dev user |
| `PINT_DEV_RTP` | `false` | Inject `rtp` group into dev user (requires `PINT_DISABLE_OIDC=true`) |

### FreeIPA Stub

The stub (`dev/freeipa-stub/`) is a minimal HTTPS server that implements just enough of the FreeIPA JSON-RPC API for PINT to function locally. It runs on `:8088` with a self-signed TLS certificate, so `PINT_IPA_SKIP_TLS_VERIFY=true` must be set in `.env.dev`.

**CA structure**

On first run the stub generates a three-tier CA hierarchy and persists it to `dev/freeipa-stub/data/`:

```
Root CA (ipa)
├── WiFi CA  (wireless)              # signs pint_wifi and pint_radsec_server certs
├── RadSec CA (radsec)               # signs pint_radsec_client certs
└── Code Signing CA (code_signing)   # signs pint_profile_signing certs (optional)
```

The CA names are read from `PINT_IPA_WIRELESS_CA_NAME`, `PINT_IPA_RADSEC_CA_NAME`, and `PINT_IPA_ROOT_CA_NAME` at startup and must match the values in `.env.dev`. On subsequent runs the persisted keys and certificates are reloaded, so issued certificates remain valid across restarts.

Profile signing is **optional in local dev**. To enable it, uncomment the three `PINT_IPA_CODE_SIGNING_CA_NAME` lines in `.env.dev`. On the next `make dev` run the stub will generate a `code_signing` intermediate CA under the root, persist it to `dev/freeipa-stub/data/`, and handle `cert_request` calls for the `pint_profile_signing` profile with `codeSigning` EKU. Leaving the variable unset skips signing entirely; PINT starts normally and generates unsigned profiles.

**Implemented RPC methods**

| Method | Behaviour |
|---|---|
| `ca_show` | Returns the DER-encoded certificate for the named CA |
| `cert_request` | Signs the CSR with the requested CA; applies profile-appropriate EKU and validity (see below) |
| `cert_revoke` | No-op; always returns success |

Authentication (`/ipa/session/login_password`) accepts any credentials and returns a stub session cookie.

**Profile handling**

The stub maps profile IDs to EKU and validity:

| Profile ID | EKU | Validity | Notes |
|---|---|---|---|
| `pint_radsec_server` | `serverAuth` | 90 days | DNS SAN set to CSR CN (required for Go TLS verification) |
| `pint_profile_signing` | `codeSigning` | 1 year | Only available when `PINT_IPA_CODE_SIGNING_CA_NAME` is set |
| all others (`pint_wifi`, `pint_radsec_client`, …) | `clientAuth` | 5 years | |

Unlike real FreeIPA/Dogtag, the stub does not enforce subject name patterns or key type constraints defined in the profile config files.

### RadSec Smoketest

An end-to-end integration test that exercises the full EAP-TLS authentication path over a live RadSec connection to the kind cluster.

```bash
# Requires make dev running with the FreeIPA stub on :8088
make radsec-smoketest
```

What it does:

1. Builds a smoketest Docker image (`debian:trixie-slim` + `eapol_test` + `freeradius`) and loads it into kind.
2. Uses the running FreeIPA stub to issue a controller client cert and a user WiFi cert.
3. Launches a Kubernetes pod that starts a local FreeRADIUS instance in proxy-only mode, configured to forward requests over RadSec (mTLS) to `pint-freeradius.pint.svc.cluster.local:2083`.
4. Runs `eapol_test` with the user WiFi cert to perform a real EAP-TLS authentication end to end.
5. Exits 0 on success, 1 on failure. Cleans up the pod and cert Secret either way.
