#!/usr/bin/env bash
# SCEP smoke test: verifies initial enrollment (PKCSReq) and certificate renewal
# against a running local pint + freeipa-stub.
#
# Usage:
#   PINT_URL=http://localhost:8080 bash dev/scep-smoketest/run-scep-smoketest.sh
#   make scep-smoketest
#
# Requires: curl, jq, openssl, cmake (to auto-build sscep if not found)
set -euo pipefail

PINT_URL=${PINT_URL:-http://localhost:8080}
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT

# ── Dependency checks ──────────────────────────────────────────────────────────

for cmd in curl jq openssl cmake; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found" >&2; exit 1; }
done

# Locate or build sscep (https://github.com/certnanny/sscep).
# sscep is a C SCEP client that uses OpenSSL directly without extra plugin deps.
if command -v sscep >/dev/null 2>&1; then
    SSCEP="sscep"
elif [ -x "/tmp/sscep/sscep" ]; then
    SSCEP="/tmp/sscep/sscep"
else
    echo "==> sscep not found — building from source (requires cmake + OpenSSL) ..."
    OPENSSL_ROOT=$(brew --prefix openssl 2>/dev/null || echo "")
    CMAKE_ARGS=(-DCMAKE_POLICY_VERSION_MINIMUM=3.5)
    [ -n "$OPENSSL_ROOT" ] && CMAKE_ARGS+=(-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT")
    git clone --depth=1 https://github.com/certnanny/sscep.git /tmp/sscep 2>/dev/null \
        || (cd /tmp/sscep && git pull --ff-only)
    (cd /tmp/sscep && cmake . "${CMAKE_ARGS[@]}" -DCMAKE_BUILD_TYPE=Release -Wno-dev >/dev/null && make -j4 >/dev/null)
    SSCEP="/tmp/sscep/sscep"
    echo "    built: $SSCEP"
fi

echo ""

# ── Fetch SCEP CA bundle ───────────────────────────────────────────────────────
# sscep getca writes each cert in the degenerate PKCS7 as a separate DER file:
# ca-0 = RA cert (used for envelope encryption and signature verification),
# ca-1 = WiFi CA, ca-2 = Root CA.

echo "==> Fetching SCEP CA bundle from $PINT_URL/scep ..."
"$SSCEP" getca -u "$PINT_URL/scep" -c "$D/ca" 2>/dev/null
[ -f "$D/ca-0" ] && [ -f "$D/ca-1" ] \
    || { echo "Error: expected at least 2 certs from getca" >&2; exit 1; }
# sscep writes PEM files (despite the lack of extension).
echo "    RA cert : $(openssl x509 -in "$D/ca-0" -noout -subject)"
echo "    WiFi CA : $(openssl x509 -in "$D/ca-1" -noout -subject)"
[ -f "$D/ca-2" ] && \
    echo "    Root CA : $(openssl x509 -in "$D/ca-2" -noout -subject)"
echo ""

# ── Initial enrollment (PKCSReq) ───────────────────────────────────────────────

echo "==> Getting SCEP challenge (device_name='SCEP Smoketest', os=linux) ..."
CHALLENGE=$(curl -sf "$PINT_URL/profile/scep-challenge?device_name=SCEP+Smoketest&os=linux" \
    | jq -r .challenge)
[ -n "$CHALLENGE" ] || { echo "Error: empty challenge — is pint running?" >&2; exit 1; }
echo "    token: ${CHALLENGE:0:8}…"
echo ""

echo "==> Generating RSA key ..."
openssl genrsa -out "$D/wifi.key" 2048 2>/dev/null

# sscep reads the challenge password from the CSR's challengePassword attribute.
cat > "$D/enroll.conf" <<EOF
[ req ]
prompt = no
distinguished_name = dn
attributes = req_attrs

[ dn ]
CN = devuser
O = CSH.RIT.EDU

[ req_attrs ]
challengePassword = $CHALLENGE
EOF
openssl req -new -key "$D/wifi.key" -config "$D/enroll.conf" -out "$D/wifi.csr" 2>/dev/null

echo "==> Enrolling — PKCSReq ..."
"$SSCEP" enroll \
    -u "$PINT_URL/scep" \
    -c "$D/ca" \
    -e "$D/ca-0" \
    -k "$D/wifi.key" \
    -r "$D/wifi.csr" \
    -l "$D/wifi.crt" \
    -E aes \
    -S sha256 \
    2>/dev/null

SERIAL1=$(openssl x509 -in "$D/wifi.crt" -noout -serial | cut -d= -f2)
EXPIRY1=$(openssl x509 -in "$D/wifi.crt" -noout -enddate | cut -d= -f2)
echo "    serial  : $SERIAL1"
echo "    expires : $EXPIRY1"
echo ""

# ── Renewal (PKCSReq signed with existing cert) ────────────────────────────────
# sscep sends PKCSReq signed with the existing cert (-K/-O) rather than a
# self-signed temp cert. pint detects this and treats it as a renewal, skipping
# the challenge password check and carrying forward the device map entry.

echo "==> Generating new RSA key for renewal ..."
openssl genrsa -out "$D/wifi-new.key" 2048 2>/dev/null

cat > "$D/renew.conf" <<EOF
[ req ]
prompt = no
distinguished_name = dn

[ dn ]
CN = devuser
O = CSH.RIT.EDU
EOF
openssl req -new -key "$D/wifi-new.key" -config "$D/renew.conf" -out "$D/wifi-renew.csr" 2>/dev/null

echo "==> Renewing — PKCSReq signed with existing cert ..."
"$SSCEP" enroll \
    -u "$PINT_URL/scep" \
    -c "$D/ca" \
    -e "$D/ca-0" \
    -k "$D/wifi-new.key" \
    -r "$D/wifi-renew.csr" \
    -K "$D/wifi.key" \
    -O "$D/wifi.crt" \
    -l "$D/wifi-renewed.crt" \
    -E aes \
    -S sha256 \
    2>/dev/null

SERIAL2=$(openssl x509 -in "$D/wifi-renewed.crt" -noout -serial | cut -d= -f2)
EXPIRY2=$(openssl x509 -in "$D/wifi-renewed.crt" -noout -enddate | cut -d= -f2)
echo "    serial  : $SERIAL2"
echo "    expires : $EXPIRY2"
echo ""

# ── Assertions ─────────────────────────────────────────────────────────────────

PASS=true

if [ "$SERIAL1" = "$SERIAL2" ]; then
    echo "FAIL: renewal returned the same serial as the initial cert" >&2
    PASS=false
fi

# Both certs should be valid for ~1 year; flag anything longer than 400 days.
check_validity() {
    local label=$1 certfile=$2
    local end_epoch now days_remaining
    end_epoch=$(openssl x509 -in "$certfile" -noout -enddate \
        | cut -d= -f2 \
        | xargs -I{} bash -c 'date -j -f "%b %e %T %Y %Z" "{}" "+%s" 2>/dev/null \
            || date -d "{}" "+%s"')
    now=$(date +%s)
    days_remaining=$(( (end_epoch - now) / 86400 ))
    if [ "$days_remaining" -gt 400 ]; then
        echo "FAIL [$label]: cert valid for $days_remaining days (expected ≤ 400)" >&2
        PASS=false
    else
        echo "OK   [$label]: $days_remaining days remaining"
    fi
}

check_validity "initial" "$D/wifi.crt"
check_validity "renewed" "$D/wifi-renewed.crt"

echo ""
if [ "$PASS" = "true" ]; then
    echo "PASS  initial=$SERIAL1  renewed=$SERIAL2"
else
    exit 1
fi
