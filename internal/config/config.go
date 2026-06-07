package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	// OIDC
	ClientID     string
	ClientSecret string
	ServerURL    string
	LoginURL     string
	CallbackURL  string

	// FreeIPA
	IPAHost                 string
	IPAServiceAccount       string
	IPAPassword             string
	IPAWirelessCAName       string
	RadSecCAName            string // PINT_IPA_RADSEC_CA_NAME:FreeIPA intermediate CA for RadSec certs
	RootCAName              string // PINT_IPA_ROOT_CA_NAME:signing root CA; defaults to "ipa"
	EAPClientCertProfile          string // PINT_IPA_EAP_CLIENT_CERT_PROFILE:FreeIPA profile for WiFi client certs (default: pint_eap_client)
	RadSecClientCertProfile string // PINT_IPA_RADSEC_CLIENT_CERT_PROFILE:FreeIPA profile for RadSec router client certs (default: pint_radsec_client)
	RadSecServerCertProfile string // PINT_IPA_RADSEC_SERVER_CERT_PROFILE:FreeIPA profile for FreeRADIUS outer RadSec TLS cert (default: pint_radsec_server)
	EAPCertProfile          string // PINT_IPA_EAP_CERT_PROFILE:FreeIPA profile for FreeRADIUS EAP-TLS server cert, issued by the wireless CA (default: pint_radsec_server)
	IPAPrincipal            string // derived: full principal, e.g. pint/host@REALM
	IPAServiceHostname      string // derived: hostname portion of principal, e.g. host
	IPASkipTLSVerify        bool

	// WiFi
	WiFiSSID string

	// Kubernetes
	Namespace            string
	ConfigSecret         string // PINT_CONFIG_SECRET:K8s Secret holding clients.json, clients.conf, status-secret, and status config
	RadSecCertSecret     string // PINT_RADSEC_CERT_SECRET:K8s Secret storing FreeRADIUS outer RadSec TLS cert+key (tls.crt, tls.key, ca.pem, wifi-ca.pem)
	EAPCertSecret        string // PINT_EAP_CERT_SECRET:K8s Secret storing FreeRADIUS EAP-TLS server cert+key (eap.crt, eap.key); wireless CA-issued
	FreeRADIUSDeployment string

	// FreeRADIUS status virtual server
	RADIUSStatusPort   string // PINT_RADIUS_STATUS_PORT: port for the FreeRADIUS status virtual server
	RADIUSStatusAddr   string // PINT_RADIUS_STATUS_ADDR: override address (host:port) for status queries; replaces per-pod IP (useful when pod IPs are unreachable, e.g. local dev against kind)
	RadSecCheckCRL      bool     // PINT_RADIUS_RADSEC_CHECK_CRL: enable CRL checking in the RadSec TLS listener (default true; set false for local dev)
	RadSecProxyProtocol bool     // PINT_RADIUS_RADSEC_PROXY_PROTOCOL: expect HAProxy PROXY protocol header on RadSec connections (default false)
	RadSecProxyHosts    []string // PINT_RADIUS_RADSEC_PROXY_HOSTS: comma-separated IPs/CIDRs of trusted proxy hosts (e.g. HAProxy); added as clients so FreeRADIUS accepts their connections before reading the PROXY header


	// Apple profile signing
	CodeSigningCAName        string // PINT_IPA_CODE_SIGNING_CA_NAME: FreeIPA intermediate CA for profile signing certs
	CodeSigningCertProfile   string // PINT_IPA_CODE_SIGNING_CERT_PROFILE: FreeIPA profile for profile signing certs (default: pint_profile_signing)
	ProfileSigningCertSecret string // PINT_PROFILE_SIGNING_CERT_SECRET: K8s Secret storing the profile signing cert+key

	// SCEP
	SCEPURL          string // derived: ServerURL + /scep
	SCEPRACertSecret string // PINT_SCEP_RA_CERT_SECRET: K8s Secret storing the self-signed SCEP RA cert+key (default: pint-scep-ra-cert)
	DeviceMapSecret  string // PINT_DEVICE_MAP_SECRET: K8s Secret storing the cert serial → device info map (default: pint-device-map)

	// UI
	RadiusServer string

	// Session
	SessionSecret string // PINT_SESSION_SECRET: secret key for cookie-backed sessions (required in prod; defaults to "dev-secret" when PINT_DISABLE_OIDC=true)

	// Dev
	DisableOIDC bool // PINT_DISABLE_OIDC: skip OIDC and inject a static dev user

	// Migration
	// EAPMigrateLegacyLeaf: when true, the EAP cert watcher appends the WiFi CA chain to
	// leaf-only existing certs without reissuing (one-shot migration for legacy deployments).
	// Set PINT_EAP_MIGRATE_LEGACY_LEAF=true, run once, then unset. TODO: remove after 2026-12-01.
	EAPMigrateLegacyLeaf bool
}

func Load() (*Config, error) {
	cfg := &Config{}
	var missing []string

	require := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			missing = append(missing, key)
		}
		return v
	}

	optional := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}

	cfg.ClientID = require("PINT_CLIENT_ID")
	cfg.ClientSecret = require("PINT_CLIENT_SECRET")
	cfg.ServerURL = require("PINT_SERVER_URL")
	cfg.IPAHost = require("PINT_IPA_HOST")
	cfg.IPAServiceAccount = require("PINT_IPA_SERVICE_ACCOUNT")
	cfg.IPAPassword = require("PINT_IPA_PASSWORD")
	cfg.IPAWirelessCAName = optional("PINT_IPA_WIRELESS_CA_NAME", "wireless")
	cfg.RadSecCAName = optional("PINT_IPA_RADSEC_CA_NAME", "radsec")
	cfg.WiFiSSID = require("PINT_WIFI_SSID")

	cfg.Namespace = optional("PINT_NAMESPACE", "pint")
	cfg.ConfigSecret = optional("PINT_CONFIG_SECRET", "pint-config")
	cfg.RadSecCertSecret = optional("PINT_RADSEC_CERT_SECRET", "pint-radsec-server-certificates")
	cfg.EAPCertSecret = optional("PINT_EAP_CERT_SECRET", "pint-eap-server-cert")
	cfg.FreeRADIUSDeployment = optional("PINT_FREERADIUS_DEPLOYMENT", "pint-freeradius")
	cfg.RadiusServer = require("PINT_RADIUS_SERVER")
	cfg.RADIUSStatusPort = optional("PINT_RADIUS_STATUS_PORT", "18121")
	cfg.RADIUSStatusAddr = optional("PINT_RADIUS_STATUS_ADDR", "")


	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	cfg.DisableOIDC = os.Getenv("PINT_DISABLE_OIDC") == "true"
	if s := os.Getenv("PINT_SESSION_SECRET"); s != "" {
		cfg.SessionSecret = s
	} else if cfg.DisableOIDC {
		cfg.SessionSecret = "dev-secret-do-not-use-in-production"
	} else {
		return nil, fmt.Errorf("missing required environment variable: PINT_SESSION_SECRET")
	}
	cfg.EAPMigrateLegacyLeaf = os.Getenv("PINT_EAP_MIGRATE_LEGACY_LEAF") == "true"
	cfg.IPASkipTLSVerify = os.Getenv("PINT_IPA_SKIP_TLS_VERIFY") == "true"
	cfg.RadSecCheckCRL = os.Getenv("PINT_RADIUS_RADSEC_CHECK_CRL") != "false"
	cfg.RadSecProxyProtocol = os.Getenv("PINT_RADIUS_RADSEC_PROXY_PROTOCOL") == "true"
	if v := os.Getenv("PINT_RADIUS_RADSEC_PROXY_HOSTS"); v != "" {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				cfg.RadSecProxyHosts = append(cfg.RadSecProxyHosts, h)
			}
		}
	}
	cfg.RootCAName = os.Getenv("PINT_IPA_ROOT_CA_NAME")
	if cfg.RootCAName == "" {
		cfg.RootCAName = "ipa"
	}
	cfg.EAPClientCertProfile = optional("PINT_IPA_EAP_CLIENT_CERT_PROFILE", "pint_eap_client")
	cfg.RadSecClientCertProfile = optional("PINT_IPA_RADSEC_CLIENT_CERT_PROFILE", "pint_radsec_client")
	cfg.RadSecServerCertProfile = optional("PINT_IPA_RADSEC_SERVER_CERT_PROFILE", "pint_radsec_server")
	cfg.EAPCertProfile = optional("PINT_IPA_EAP_CERT_PROFILE", "pint_eap_server")
	cfg.CodeSigningCAName = require("PINT_IPA_CODE_SIGNING_CA_NAME")
	cfg.CodeSigningCertProfile = optional("PINT_IPA_CODE_SIGNING_CERT_PROFILE", "pint_profile_signing")
	cfg.ProfileSigningCertSecret = optional("PINT_PROFILE_SIGNING_CERT_SECRET", "pint-profile-signing-cert")
	cfg.SCEPRACertSecret = optional("PINT_SCEP_RA_CERT_SECRET", "pint-scep-ra-cert")
	cfg.DeviceMapSecret = optional("PINT_DEVICE_MAP_SECRET", "pint-device-map")

	cfg.LoginURL = cfg.ServerURL + "/auth/login"
	cfg.SCEPURL = cfg.ServerURL + "/scep"
	cfg.CallbackURL = cfg.ServerURL + "/auth/callback"
	cfg.IPAPrincipal = principalFromDN(cfg.IPAServiceAccount)
	cfg.IPAServiceHostname = hostnameFromPrincipal(cfg.IPAPrincipal)

	return cfg, nil
}

// principalFromDN parses krbprincipalname=pint/host@REALM,cn=services,...
// and returns the principal value (e.g. "pint/host@REALM").
func principalFromDN(dn string) string {
	first := strings.SplitN(dn, ",", 2)[0]
	parts := strings.SplitN(first, "=", 2)
	if len(parts) != 2 {
		return dn
	}
	return parts[1]
}

func hostnameFromPrincipal(principal string) string {
	if i := strings.LastIndex(principal, "@"); i != -1 {
		principal = principal[:i]
	}
	if i := strings.Index(principal, "/"); i != -1 {
		return principal[i+1:]
	}
	return principal
}
