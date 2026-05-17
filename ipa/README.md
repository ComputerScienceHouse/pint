# FreeIPA Configuration

This directory contains FreeIPA resources that must be applied to the CSH IPA server before PINT can issue certificates with the correct properties.

## Certificate Profiles

PINT issues four types of certificates from FreeIPA, each requiring a dedicated Dogtag certificate profile to control validity period, key usage, and extended key usage. Without these profiles, PINT falls back to the CA default (2-year validity, generic extensions).

| Profile | Used For | Validity | EKU |
|---|---|---|---|
| `pint_wifi` | EAP-TLS client certs for user devices | 1 year | clientAuth |
| `pint_radsec_client` | mTLS client certs for home routers connecting to RadSec | 5 years | clientAuth |
| `pint_radsec_server` | Server cert for FreeRADIUS; used for both the outer RadSec TLS listener and the inner EAP-TLS authentication (two separate certs, same profile) | 90 days | serverAuth |
| `pint_profile_signing` | CMS signing cert for iOS mobileconfig profiles | 1 year | codeSigning |

The RadSec server cert is intentionally short-lived. PINT checks it every 24 hours and automatically renews it and reloads FreeRADIUS when fewer than 30 days remain, so there is no operational burden to the short validity.

### Why custom profiles?

FreeIPA's default certificate profile issues 2-year certs with a broad set of extensions. For WiFi and RadSec:

- **Validity**: User WiFi certs last 1 year; iOS/macOS renew automatically via SCEP. Router RadSec certs last 5 years to avoid frequent manual re-enrollment.
- **EKU scoping**: Each profile enforces the minimum EKU required for its purpose. A WiFi client cert cannot be used as a RadSec server cert and vice versa.
- **Subject enforcement**: All profiles force `O=CSH.RIT.EDU` in the subject regardless of what the CSR contains, ensuring a consistent and verifiable identity namespace.

### Importing and Updating

Use `update_profile.py` to manage profiles. It handles importing new profiles and updating existing ones via the FreeIPA JSON-RPC API. You will need an account with the **Certificate Manager Agents** role or admin privileges.

```bash
cd ipa
python3 update_profile.py
```

The script supports three actions:

| Action | FreeIPA call | When to use |
|---|---|---|
| `update` | `certprofile_mod` | Profile already exists; push changes to `.cfg` file |
| `show` | `certprofile_show` | Inspect what is currently deployed in FreeIPA |
| `reimport` | `certprofile_del` + `certprofile_import` | First import, or after making structural Dogtag changes that `certprofile_mod` cannot apply |

### Wiring up in PINT

Once imported, set these environment variables so PINT uses the profiles when requesting certificates:

```
PINT_IPA_CERT_PROFILE=pint_wifi
PINT_IPA_RADSEC_CLIENT_CERT_PROFILE=pint_radsec_client
PINT_IPA_RADSEC_SERVER_CERT_PROFILE=pint_radsec_server
PINT_IPA_EAP_CERT_PROFILE=pint_radsec_server
PINT_IPA_CODE_SIGNING_CERT_PROFILE=pint_profile_signing
```

All are optional with the defaults shown above. `PINT_IPA_EAP_CERT_PROFILE` controls the profile used for the EAP-TLS inner auth cert (separate from the RadSec outer TLS cert, but issued from the same profile by default). `PINT_IPA_CODE_SIGNING_CERT_PROFILE` only takes effect when `PINT_IPA_CODE_SIGNING_CA_NAME` is set.
