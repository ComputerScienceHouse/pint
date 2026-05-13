// internal/profile/wlanprofile_test.go
package profile_test

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/profile"
)

func TestBuildWLANProfile_ContainsSSID(t *testing.T) {
	_, caDER := StubCertAndCA(t, mustGenerateKey(t))

	data, err := profile.BuildWLANProfile(profile.WLANProfileParams{
		SSID:       "TestSSID",
		RadiusHost: "radius.example.com",
		CACertDER:  caDER,
	})
	if err != nil {
		t.Fatalf("BuildWLANProfile() error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "TestSSID") {
		t.Error("WLAN profile does not contain SSID")
	}
	if !strings.Contains(s, "radius.example.com") {
		t.Error("WLAN profile does not contain RadiusHost")
	}
	if !strings.Contains(s, `<?xml`) {
		t.Error("WLAN profile does not start with XML declaration")
	}
}

func TestBuildWLANProfile_ContainsExpectedElements(t *testing.T) {
	_, caDER := StubCertAndCA(t, mustGenerateKey(t))

	data, err := profile.BuildWLANProfile(profile.WLANProfileParams{
		SSID:       "CSH",
		RadiusHost: "radius.csh.rit.edu",
		CACertDER:  caDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"WPA2",
		"useOneX",
		">13<", // EAP-TLS type
		"TrustedRootCA",
		"SimpleCertSelection",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("WLAN profile missing expected element/value %q", want)
		}
	}
}

func mustGenerateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
