// internal/profile/cert_test.go
package profile_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/profile"
)

func TestGenerateKeyAndCSR(t *testing.T) {
	key, csrPEM, err := profile.GenerateKeyAndCSR("mbillow")
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR() error: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("csrPEM is not a valid CERTIFICATE REQUEST PEM, got block: %v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "mbillow" {
		t.Errorf("CSR CN = %q, want %q", csr.Subject.CommonName, "mbillow")
	}
}

func TestBuildPKCS12(t *testing.T) {
	// Generate a key and self-signed cert to simulate what FreeIPA returns
	key, csrPEM, err := profile.GenerateKeyAndCSR("mbillow")
	if err != nil {
		t.Fatal(err)
	}
	_ = csrPEM

	// Build a stub leaf cert DER signed with our key
	certDER, caDER := StubCertAndCA(t, key)

	p12, err := profile.BuildPKCS12(key, certDER, caDER, "")
	if err != nil {
		t.Fatalf("BuildPKCS12() error: %v", err)
	}
	if len(p12) == 0 {
		t.Fatal("PKCS12 bytes are empty")
	}
}
