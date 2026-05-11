# FreeIPA Configuration

This directory contains FreeIPA resources that must be applied to the CSH IPA server before PINT can issue certificates with the correct properties.

## Certificate Profiles

PINT issues three types of certificates from FreeIPA, each requiring a dedicated Dogtag certificate profile to control validity period, key usage, and extended key usage. Without these profiles, PINT falls back to the CA default (2-year validity, generic extensions).

| Profile | Used For | Validity | EKU |
|---|---|---|---|
| `pint_wifi` | EAP-TLS client certs for user devices | 5 years | clientAuth |
| `pint_radsec_client` | mTLS client certs for home routers connecting to RadSec | 5 years | clientAuth |
| `pint_radsec_server` | mTLS server cert for the FreeRADIUS RadSec listener | 90 days | serverAuth |

The RadSec server cert is intentionally short-lived. PINT checks it every 24 hours and automatically renews it and reloads FreeRADIUS when fewer than 30 days remain, so there is no operational burden to the short validity.

### Why custom profiles?

FreeIPA's default certificate profile issues 2-year certs with a broad set of extensions. For WiFi and RadSec:

- **Validity**: User WiFi certs and router RadSec certs should last 5 years to avoid forcing users to re-enroll their devices frequently.
- **EKU scoping**: Each profile enforces the minimum EKU required for its purpose. A WiFi client cert cannot be used as a RadSec server cert and vice versa.
- **Subject enforcement**: All profiles force `O=CSH.RIT.EDU` in the subject regardless of what the CSR contains, ensuring a consistent and verifiable identity namespace.

### Importing

Profiles are imported once via the FreeIPA JSON-RPC API. You will need an account with the **Certificate Manager Agents** role or admin privileges.

```bash
# Authenticate (session cookie saved to /tmp/ipa.cookies)
echo -n "IPA Password: "; read -s IPA_PASS; echo
curl -c /tmp/ipa.cookies -s -o /dev/null \
  -X POST https://ipa10-nrh.csh.rit.edu/ipa/session/login_password \
  -H "Referer: https://ipa10-nrh.csh.rit.edu/ipa" \
  --data-urlencode "user=$USER" \
  --data-urlencode "password=$IPA_PASS"

# Import all three profiles
for profile in pint_wifi pint_radsec_client pint_radsec_server; do
  echo "Importing $profile..."
  python3 -c "
import json
p = open('profiles/${profile}.cfg').read()
print(json.dumps({
  'method': 'certprofile_import',
  'params': [['${profile}'], {'file': p, 'ipacertprofilestoreissued': True}],
  'id': 0
}))
" | curl -s -b /tmp/ipa.cookies \
    -X POST https://ipa10-nrh.csh.rit.edu/ipa/json \
    -H "Content-Type: application/json" \
    -H "Referer: https://ipa10-nrh.csh.rit.edu/ipa" \
    -d @- | python3 -c "import json,sys; r=json.load(sys.stdin); print(r['result']['summary'] if r['error'] is None else r['error'])"
done
```

Run this from the `ipa/` directory.

### Updating an existing profile

If a profile already exists and you need to update it (e.g. after changing a `.cfg` file), use `certprofile_mod` with the `file` parameter instead of `certprofile_import`:

```bash
python3 -c "
import json
p = open('profiles/pint_wifi.cfg').read()
print(json.dumps({'method':'certprofile_mod','params':[['pint_wifi'],{'file':p}],'id':0}))
" | curl -s -b /tmp/ipa.cookies \
  -X POST https://ipa10-nrh.csh.rit.edu/ipa/json \
  -H "Content-Type: application/json" \
  -H "Referer: https://ipa10-nrh.csh.rit.edu/ipa" \
  -d @-
```

### Wiring up in PINT

Once imported, set these environment variables so PINT uses the profiles when requesting certificates:

```
PINT_IPA_CERT_PROFILE=pint_wifi
PINT_IPA_RADSEC_CLIENT_CERT_PROFILE=pint_radsec_client
PINT_IPA_RADSEC_SERVER_CERT_PROFILE=pint_radsec_server
```

All three are optional; omitting them causes PINT to request certificates without specifying a profile, which uses the CA's default.
