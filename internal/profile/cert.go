// internal/profile/cert.go
package profile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// GenerateKeyAndCSR creates a secp384r1 ECDSA private key and a PEM-encoded CSR with the given CN.
func GenerateKeyAndCSR(commonName string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

// RandomPassword generates a 32-character hex password for PKCS#12 archives.
func RandomPassword() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// BuildPKCS12 bundles the private key, leaf certificate DER, and CA certificate DER
// into a PKCS#12 archive protected by password.
func BuildPKCS12(key crypto.Signer, certDER, caDER []byte, password string) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	p12, err := pkcs12.Legacy.Encode(key, cert, []*x509.Certificate{ca}, password)
	if err != nil {
		return nil, fmt.Errorf("encode PKCS12: %w", err)
	}
	return p12, nil
}
