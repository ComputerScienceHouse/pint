# SCEP Platform Research

PINT already implements SCEP end-to-end for iOS/macOS using Apple's native mobileconfig SCEP payload and automatic renewal. This document covers research into SCEP enrollment for other platforms and the PINT endpoints available for manual enrollment.

---

## PINT SCEP Endpoints

### `GET /scep` / `POST /scep`

The SCEP RA endpoint. Handles `GetCACaps`, `GetCACert`, and `PKIOperation`. No authentication required — the one-time challenge password in the enrollment request is the auth.

### `GET /profile/scep-challenge`

Requires an active PINT session. Issues a one-time challenge token (15-minute TTL) and returns it as JSON:

```json
{"challenge": "a3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5"}
```

Use this token as the challenge password in any SCEP client. A new token is required for each enrollment — tokens are consumed on use.

```bash
# Fetch a token (substitute your session cookie)
TOKEN=$(curl -s -b <session-cookie> https://pint.csh.rit.edu/profile/scep-challenge | jq -r .challenge)
```

---

## Windows

### Current state

Windows has no built-in SCEP client that works against a generic SCEP server. The native tooling (`Get-Certificate`, `certmgr.msc`) only speaks Microsoft's own XCEP/WSTEP protocols. However, the PSCertificateEnrollment PowerShell module wraps Windows's `IX509SCEPEnrollment` COM interface and is documented as compatible with any RFC 8894 server. It is the most practical path today.

### Enrollment with PSCertificateEnrollment

```powershell
# One-time: install the module
Install-Module PSCertificateEnrollment

# Fetch a challenge token from PINT (requires browser session cookie)
$token = (Invoke-RestMethod -Uri https://pint.csh.rit.edu/profile/scep-challenge `
    -Headers @{ Cookie = "<session-cookie>" }).challenge

# Enroll
Get-SCEPCertificate `
    -SCEPServerURL https://pint.csh.rit.edu/scep `
    -ChallengePassword $token `
    -Subject "CN=$env:USERNAME"
```

The certificate is installed directly into the Windows certificate store (Personal). The WLAN XML profile (`/profile/generate?platform=windows`) can then reference it for EAP-TLS.

### Automatic renewal

Renewal is scriptable using the existing certificate as authentication:

```powershell
# Renew using the expiring cert (no new challenge needed)
Get-SCEPCertificate `
    -SCEPServerURL https://pint.csh.rit.edu/scep `
    -SigningCertificate (Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "CN=$env:USERNAME*" })
```

Wrap this in a Task Scheduler job at ~50% of the 1-year cert lifetime (around 6 months) for fully automatic renewal.

### Future: MS-XCEP + MS-WSTEP (native GUI enrollment)

The only path to a true `certmgr.msc` GUI experience on non-domain Windows machines without MDM. The flow:

1. User adds the PINT XCEP URL to `certmgr.msc` under Manage Enrollment Policies (one-time setup).
2. Right-click Personal > Request New Certificate > select the PINT template.
3. Certificate is issued and installed.

Authentication would use FreeIPA username/password via WS-Security UsernameToken — no Active Directory required. The specs (MS-XCEP and MS-WSTEP) are fully published open specifications. No production Go library exists for this; it would need to be implemented from scratch. Estimated effort: 1-3 weeks. Renewal from `certmgr.msc` would also work (right-click the cert > Renew), but automatic background renewal would require additionally implementing MS-CEAS (autoenrollment trigger).

---

## Linux

### Current state

No distro ships a SCEP client by default, but two well-maintained options cover the use case well. Both are packaged for Debian/Ubuntu.

### Option 1: strongSwan `pki --scep` (recommended)

Implements RFC 8894 (the current standard). Ships AES + SHA-256 by default. Better long-term interoperability with PINT's modern SCEP server.

```bash
# Install
apt install strongswan-pki

# Fetch a challenge token
TOKEN=$(curl -s -b <session-cookie> https://pint.csh.rit.edu/profile/scep-challenge | jq -r .challenge)

# Generate a private key
pki --gen --type rsa --size 2048 --outform pem > wifi-client.key

# Enroll
pki --scep \
    --url https://pint.csh.rit.edu/scep \
    --in wifi-client.key \
    --dn "CN=$(whoami),O=CSH.RIT.EDU" \
    --password "$TOKEN" \
    > wifi-client.crt

# Configure wpa_supplicant or NetworkManager to use wifi-client.key + wifi-client.crt
```

Renewal uses the existing cert to authenticate (no new challenge required):

```bash
pki --scep \
    --url https://pint.csh.rit.edu/scep \
    --in wifi-client.key \
    --cert wifi-client.crt \
    --dn "CN=$(whoami),O=CSH.RIT.EDU" \
    > wifi-client.crt.new && mv wifi-client.crt.new wifi-client.crt
```

### Option 2: sscep

Implements an older SCEP draft but works against most servers. Debian-packaged (`apt install sscep`). Useful if strongSwan is not available.

```bash
apt install sscep openssl

TOKEN=$(curl -s -b <session-cookie> https://pint.csh.rit.edu/profile/scep-challenge | jq -r .challenge)

# Generate key and CSR
openssl genrsa -out wifi-client.key 2048
openssl req -new -key wifi-client.key -out wifi-client.csr \
    -subj "/CN=$(whoami)/O=CSH.RIT.EDU"

# Fetch the SCEP CA cert
sscep getca -u https://pint.csh.rit.edu/scep -c scep-ca.crt

# Enroll
sscep enroll \
    -u https://pint.csh.rit.edu/scep \
    -c scep-ca.crt \
    -k wifi-client.key \
    -r wifi-client.csr \
    -l wifi-client.crt \
    -p "$TOKEN"
```

Renewal with sscep (uses existing cert/key, no new challenge):

```bash
sscep enroll \
    -u https://pint.csh.rit.edu/scep \
    -c scep-ca.crt \
    -k wifi-client.key \
    -r wifi-client.csr \
    -l wifi-client.crt \
    -K wifi-client.key \
    -O wifi-client.crt
```

### Automatic renewal via systemd timer

```ini
# /etc/systemd/system/pint-wifi-renew.service
[Unit]
Description=Renew PINT WiFi certificate

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pint-wifi-renew.sh

# /etc/systemd/system/pint-wifi-renew.timer
[Unit]
Description=PINT WiFi certificate renewal check

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
```

The renewal script checks remaining validity with `openssl x509 -checkend` and only re-enrolls if the cert is within 30 days of expiry.

---

## Android

No viable path for unmanaged personal devices. Android's certificate APIs only support SCEP enrollment through a full MDM/EMM enrollment (Intune, Workspace ONE, etc.) — there is no user-initiated flow for installing a SCEP-enrolled certificate into the system keystore for Wi-Fi use without MDM. The current PKCS#12 download flow is the best available option for Android.
