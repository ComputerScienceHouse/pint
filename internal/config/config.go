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
	IPACAName               string
	RadSecCAName            string // PINT_IPA_RADSEC_CA_NAME — FreeIPA intermediate CA for RadSec certs
	RootCAName              string // PINT_IPA_ROOT_CA_NAME — signing root CA; defaults to "ipa"
	IPACertProfile          string // PINT_IPA_CERT_PROFILE — FreeIPA profile for WiFi client certs (optional)
	RadSecClientCertProfile string // PINT_IPA_RADSEC_CLIENT_CERT_PROFILE — FreeIPA profile for RadSec router client certs (optional)
	RadSecServerCertProfile string // PINT_IPA_RADSEC_SERVER_CERT_PROFILE — FreeIPA profile for FreeRADIUS server cert (optional)
	IPAPrincipal            string // derived: full principal, e.g. pint/host@REALM
	IPAServiceHostname      string // derived: hostname portion of principal, e.g. host
	IPASkipTLSVerify        bool

	// WiFi
	WiFiSSID string

	// Kubernetes
	Namespace             string
	RadiusClientsSecret   string
	RadiusConfigSecret    string
	RadSecCertSecret      string // PINT_RADSEC_CERT_SECRET — K8s Secret storing FreeRADIUS TLS cert+key
	FreeRADIUSPodSelector string

	// UI
	RadiusServer string
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

	cfg.ClientID = require("PINT_CLIENT_ID")
	cfg.ClientSecret = require("PINT_CLIENT_SECRET")
	cfg.ServerURL = require("PINT_SERVER_URL")
	cfg.LoginURL = require("PINT_LOGIN_URL")
	cfg.CallbackURL = require("PINT_CALLBACK_URL")
	cfg.IPAHost = require("PINT_IPA_HOST")
	cfg.IPAServiceAccount = require("PINT_IPA_SERVICE_ACCOUNT")
	cfg.IPAPassword = require("PINT_IPA_PASSWORD")
	cfg.IPACAName = require("PINT_IPA_CA_NAME")
	cfg.RadSecCAName = require("PINT_IPA_RADSEC_CA_NAME")
	cfg.WiFiSSID = require("PINT_WIFI_SSID")

	cfg.Namespace = require("PINT_NAMESPACE")
	cfg.RadiusClientsSecret = require("PINT_RADIUS_CLIENTS_SECRET")
	cfg.RadiusConfigSecret = require("PINT_RADIUS_CONFIG_SECRET")
	cfg.RadSecCertSecret = require("PINT_RADSEC_CERT_SECRET")
	cfg.FreeRADIUSPodSelector = require("PINT_FREERADIUS_POD_SELECTOR")
	cfg.RadiusServer = require("PINT_RADIUS_SERVER")

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	cfg.IPASkipTLSVerify = os.Getenv("PINT_IPA_SKIP_TLS_VERIFY") == "true"
	cfg.RootCAName = os.Getenv("PINT_IPA_ROOT_CA_NAME")
	if cfg.RootCAName == "" {
		cfg.RootCAName = "ipa"
	}
	cfg.IPACertProfile = os.Getenv("PINT_IPA_CERT_PROFILE")
	cfg.RadSecClientCertProfile = os.Getenv("PINT_IPA_RADSEC_CLIENT_CERT_PROFILE")
	cfg.RadSecServerCertProfile = os.Getenv("PINT_IPA_RADSEC_SERVER_CERT_PROFILE")
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
