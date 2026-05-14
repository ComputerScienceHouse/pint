// internal/profile/mobileconfig_test.go
package profile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/profile"
)

func TestBuildMobileconfig_ContainsSSID(t *testing.T) {
	key, _, err := profile.GenerateKeyAndCSR("mbillow")
	if err != nil {
		t.Fatal(err)
	}
	certDER, caDER := StubCertAndCA(t, key)
	p12, err := profile.BuildPKCS12(key, certDER, caDER)
	if err != nil {
		t.Fatal(err)
	}

	params := profile.MobileconfigParams{
		SSID:        "TestSSID",
		RadiusHost:  "radius.example.com",
		PKCS12Bytes: p12,
		CACertDER:   caDER,
		Username:    "mbillow",
	}

	data, err := profile.BuildMobileconfig(params)
	if err != nil {
		t.Fatalf("BuildMobileconfig() error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("mobileconfig is empty")
	}
	if !strings.Contains(string(data), "TestSSID") {
		t.Error("mobileconfig does not contain SSID")
	}
	if !strings.Contains(string(data), "<?xml") && !strings.Contains(string(data), "bplist") {
		t.Error("output does not look like a plist")
	}
}

func TestBuildMobileconfig_ContainsPayloadTypes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, caDER := StubCertAndCA(t, key)
	p12, err := profile.BuildPKCS12(key, certDER, caDER)
	if err != nil {
		t.Fatal(err)
	}

	params := profile.MobileconfigParams{
		SSID:        "CSH",
		RadiusHost:  "radius.csh.rit.edu",
		PKCS12Bytes: p12,
		CACertDER:   caDER,
		Username:    "mbillow",
	}

	data, err := profile.BuildMobileconfig(params)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"com.apple.wifi.managed",
		"com.apple.security.pkcs12",
		"com.apple.security.root",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("mobileconfig missing payload type %q", want)
		}
	}
}
