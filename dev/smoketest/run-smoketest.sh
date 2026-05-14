#!/usr/bin/env bash
set -euo pipefail

SMOKETEST_IMAGE=${SMOKETEST_IMAGE:-pint-smoketest:dev}
SMOKETEST_POD=${SMOKETEST_POD:-pint-radsec-smoketest}
NAMESPACE=${NAMESPACE:-pint}
D=$(mktemp -d)
trap 'rm -rf "$D"; kubectl delete pod "$SMOKETEST_POD" -n "$NAMESPACE" --ignore-not-found 2>/dev/null; kubectl delete secret "$SMOKETEST_POD-certs" -n "$NAMESPACE" --ignore-not-found 2>/dev/null' EXIT

for cmd in openssl curl jq kubectl; do
    which "$cmd" > /dev/null 2>&1 || { echo "Error: $cmd not installed"; exit 1; }
done

# Source dev env for stub URL and CA names
set -a && . .env.dev && set +a

issue_cert() {
    local out=$1 ca=$2 subj=$3 profile=${4:-""}
    openssl genrsa -out "${out}.key" 2048 2>/dev/null
    openssl req -new -key "${out}.key" -subj "$subj" -out "${out}.csr" 2>/dev/null
    local resp
    resp=$(curl -sk -X POST "https://$PINT_IPA_HOST/ipa/json" \
        -H 'Content-Type: application/json' \
        -d "$(jq -n --rawfile csr "${out}.csr" \
            --arg ca "$ca" \
            --arg profile "$profile" \
            '{method:"cert_request",params:[[$csr],{cacn:$ca,"profile_id":$profile}],id:0}')")
    local b64
    b64=$(echo "$resp" | jq -r '.result.result.certificate // empty')
    if [ -z "$b64" ]; then
        echo "Error: stub returned no certificate for CA '$ca'. Response: $resp" >&2
        exit 1
    fi
    echo "$b64" | base64 -d | openssl x509 -inform DER -out "${out}.crt"
}

echo "==> Fetching RadSec CA from cluster..."
kubectl get secret pint-radsec-server-certificates -n "$NAMESPACE" \
    -o jsonpath='{.data.ca\.pem}' | base64 -d > "$D/radsec-ca.pem"

echo "==> Verifying organization controller is registered..."
ROOT=$(kubectl get secret pint-config -n "$NAMESPACE" \
    -o jsonpath='{.data.clients\.json}' 2>/dev/null | base64 -d \
    | jq -r '.[] | select(.username == "root") | .username' 2>/dev/null)
if [ -z "$ROOT" ]; then
    echo "Error: organization controller (root) not registered — provision it via PINT admin first" >&2
    exit 1
fi

echo "==> Issuing organization controller cert (RadSec CA)..."
issue_cert "$D/router" "${PINT_IPA_RADSEC_CA_NAME:-radsec}" "/CN=root"

echo "==> Issuing user WiFi cert (WiFi CA)..."
issue_cert "$D/user" "${PINT_IPA_WIRELESS_CA_NAME:-wireless}" "/CN=smoketest"

echo "==> Creating certs secret in cluster..."
kubectl create secret generic "$SMOKETEST_POD-certs" -n "$NAMESPACE" \
    --from-file=radsec-ca.pem="$D/radsec-ca.pem" \
    --from-file=router.crt="$D/router.crt" \
    --from-file=router.key="$D/router.key" \
    --from-file=user.crt="$D/user.crt" \
    --from-file=user.key="$D/user.key" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "==> Running smoketest pod..."
kubectl delete pod "$SMOKETEST_POD" -n "$NAMESPACE" --ignore-not-found 2>/dev/null
kubectl run "$SMOKETEST_POD" -n "$NAMESPACE" \
    --image="$SMOKETEST_IMAGE" \
    --image-pull-policy=Never \
    --restart=Never \
    --overrides="{\"spec\":{\"volumes\":[{\"name\":\"certs\",\"secret\":{\"secretName\":\"$SMOKETEST_POD-certs\"}}],\"containers\":[{\"name\":\"smoketest\",\"image\":\"$SMOKETEST_IMAGE\",\"imagePullPolicy\":\"Never\",\"volumeMounts\":[{\"name\":\"certs\",\"mountPath\":\"/certs\",\"readOnly\":true}]}]}}"

echo "==> Waiting for smoketest pod to complete..."
kubectl wait pod/"$SMOKETEST_POD" -n "$NAMESPACE" \
    --for=jsonpath='{.status.phase}'=Succeeded \
    --timeout=60s 2>/dev/null || \
kubectl wait pod/"$SMOKETEST_POD" -n "$NAMESPACE" \
    --for=jsonpath='{.status.phase}'=Failed \
    --timeout=60s 2>/dev/null || true
kubectl logs "pod/$SMOKETEST_POD" -n "$NAMESPACE" 2>/dev/null || true

phase=$(kubectl get pod "$SMOKETEST_POD" -n "$NAMESPACE" -o jsonpath='{.status.phase}')
if [ "$phase" != "Succeeded" ]; then
    echo "FAIL (pod phase: $phase)"
    kubectl describe pod "$SMOKETEST_POD" -n "$NAMESPACE" 2>/dev/null | tail -30
    exit 1
fi
echo "PASS"
