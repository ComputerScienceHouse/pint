package config_test

import (
	"strings"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/config"
)

func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func fullEnv() map[string]string {
	return map[string]string{
		"PINT_CLIENT_ID":               "test-client",
		"PINT_CLIENT_SECRET":           "test-secret",
		"PINT_SERVER_URL":              "http://localhost:8080",
		"PINT_LOGIN_URL":               "http://localhost:8080/auth/login",
		"PINT_CALLBACK_URL":            "http://localhost:8080/auth/callback",
		"PINT_IPA_HOST":                "ipa.example.com",
		"PINT_IPA_SERVICE_ACCOUNT":     "pint",
		"PINT_IPA_PASSWORD":            "hunter2",
		"PINT_IPA_CA_NAME":             "ipa",
		"PINT_IPA_REALM":               "EXAMPLE.COM",
		"PINT_IPA_RADSEC_CA_NAME":      "radsec",
		"PINT_RADIUS_PRINCIPAL":        "radius/radius.example.com",
		"PINT_IPA_SKIP_TLS_VERIFY":     "false",
		"PINT_WIFI_SSID":               "TestNet",
		"PINT_NAMESPACE":               "pint",
		"PINT_RADIUS_CLIENTS_SECRET":   "pint-radius-clients",
		"PINT_RADIUS_CONFIG_SECRET":    "pint-radius-config",
		"PINT_RADSEC_CERT_SECRET":      "pint-radsec-server",
		"PINT_FREERADIUS_POD_SELECTOR": "app=freeradius",
		"PINT_RADIUS_SERVER":           "radius.example.com:1812",
	}
}

func TestLoad_AllVarsPresent(t *testing.T) {
	setEnv(t, fullEnv())
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientID != "test-client" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "test-client")
	}
	if cfg.IPAHost != "ipa.example.com" {
		t.Errorf("IPAHost = %q, want %q", cfg.IPAHost, "ipa.example.com")
	}
	if cfg.WiFiSSID != "TestNet" {
		t.Errorf("WiFiSSID = %q, want %q", cfg.WiFiSSID, "TestNet")
	}
	if cfg.IPASkipTLSVerify != false {
		t.Errorf("IPASkipTLSVerify = %v, want false", cfg.IPASkipTLSVerify)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	vars := fullEnv()
	delete(vars, "PINT_CLIENT_ID")
	setEnv(t, vars)
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for missing PINT_CLIENT_ID, got nil")
	}
	if !strings.Contains(err.Error(), "PINT_CLIENT_ID") {
		t.Errorf("error should mention PINT_CLIENT_ID, got: %v", err)
	}
}

func TestLoad_MultipleMissing(t *testing.T) {
	vars := fullEnv()
	delete(vars, "PINT_CLIENT_ID")
	delete(vars, "PINT_IPA_HOST")
	delete(vars, "PINT_WIFI_SSID")
	setEnv(t, vars)
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for missing vars, got nil")
	}
	for _, key := range []string{"PINT_CLIENT_ID", "PINT_IPA_HOST", "PINT_WIFI_SSID"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error should mention %s, got: %v", key, err)
		}
	}
}

func TestLoad_SkipTLSVerifyTrue(t *testing.T) {
	vars := fullEnv()
	vars["PINT_IPA_SKIP_TLS_VERIFY"] = "true"
	setEnv(t, vars)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IPASkipTLSVerify {
		t.Error("IPASkipTLSVerify should be true")
	}
}
