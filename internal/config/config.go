package config

import (
	"fmt"
	"os"
)

type Config struct {
	// OIDC
	ClientID     string
	ClientSecret string
	ServerURL    string
	LoginURL     string
	CallbackURL  string

	// FreeIPA
	IPAHost              string
	IPAServiceAccount    string
	IPAPassword          string
	IPACAName            string
	IPARealm             string
	RadSecCAName         string // PINT_IPA_RADSEC_CA_NAME — FreeIPA intermediate CA for RadSec certs
	RadiusPrincipal      string // PINT_RADIUS_PRINCIPAL — FreeRADIUS Kerberos service principal
	IPASkipTLSVerify     bool

	// WiFi
	WiFiSSID string

	// Kubernetes
	Namespace              string
	RadiusClientsSecret    string
	RadiusConfigSecret     string
	RadSecCertSecret       string // PINT_RADSEC_CERT_SECRET — K8s Secret storing FreeRADIUS TLS cert+key
	FreeRADIUSPodSelector  string

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
	cfg.IPARealm = require("PINT_IPA_REALM")
	cfg.RadSecCAName = require("PINT_IPA_RADSEC_CA_NAME")
	cfg.RadiusPrincipal = require("PINT_RADIUS_PRINCIPAL")
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

	return cfg, nil
}
