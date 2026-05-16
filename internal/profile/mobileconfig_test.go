// internal/profile/mobileconfig_test.go
package profile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/profile"
)

// stubRACertDER generates a minimal self-signed RSA cert for use as a fake SCEP RA cert in tests.
func stubRACertDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test SCEP RA"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestBuildMobileconfig_ContainsSSID(t *testing.T) {
	key, _, err := profile.GenerateKeyAndCSR("mbillow")
	if err != nil {
		t.Fatal(err)
	}
	_, caDER := StubCertAndCA(t, key)
	raDER := stubRACertDER(t)

	params := profile.MobileconfigParams{
		SSID:          "TestSSID",
		RadiusHost:    "radius.example.com",
		CACertDER:     caDER,
		Username:      "mbillow",
		SCEPURL:       "https://pint.example.com/scep",
		SCEPChallenge: "testchallenge",
		SCEPRACertDER: raDER,
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
	_, caDER := StubCertAndCA(t, key)
	raDER := stubRACertDER(t)

	params := profile.MobileconfigParams{
		SSID:          "CSH",
		RadiusHost:    "radius.csh.rit.edu",
		CACertDER:     caDER,
		Username:      "mbillow",
		SCEPURL:       "https://pint.csh.rit.edu/scep",
		SCEPChallenge: "abc123",
		SCEPRACertDER: raDER,
	}

	data, err := profile.BuildMobileconfig(params)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"com.apple.wifi.managed",
		"com.apple.security.scep",
		"com.apple.security.root",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("mobileconfig missing payload type %q", want)
		}
	}
}
