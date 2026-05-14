// internal/profile/stub_test.go
package profile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// StubCertAndCA is a test helper that generates a self-signed CA and a leaf cert
// signed by it, using the provided leaf key. Returns (leafDER, caDER).
func StubCertAndCA(t *testing.T, leafKey *ecdsa.PrivateKey) (leafDER, caDER []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Stub CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDERBytes, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDERBytes)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mbillow"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
	}
	leafDERBytes, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	return leafDERBytes, caDERBytes
}
