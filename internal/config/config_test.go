package config_test

import (
	"os"
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
		"PINT_IPA_SKIP_TLS_VERIFY":     "false",
		"PINT_WIFI_SSID":               "TestNet",
		"PINT_NAMESPACE":               "pint",
		"PINT_RADIUS_CLIENTS_SECRET":   "pint-radius-clients",
		"PINT_RADIUS_CONFIG_SECRET":    "pint-radius-config",
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
	os.Unsetenv("PINT_CLIENT_ID")
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for missing PINT_CLIENT_ID, got nil")
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
