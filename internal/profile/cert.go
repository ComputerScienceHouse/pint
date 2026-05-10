// internal/profile/cert.go
package profile

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// GenerateKeyAndCSR creates an RSA-2048 private key and a PEM-encoded CSR with the given CN.
func GenerateKeyAndCSR(commonName string) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return key, csrPEM, nil
}

// BuildPKCS12 bundles the private key, leaf certificate DER, and CA certificate DER
// into a PKCS#12 archive with no passphrase.
func BuildPKCS12(key *rsa.PrivateKey, certDER, caDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	p12, err := pkcs12.Legacy.Encode(key, cert, []*x509.Certificate{ca}, "")
	if err != nil {
		return nil, fmt.Errorf("encode PKCS12: %w", err)
	}
	return p12, nil
}
