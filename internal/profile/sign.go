// internal/profile/sign.go
package profile

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"go.mozilla.org/pkcs7"
)

// Signer holds the certificate and private key used to sign mobileconfig profiles.
type Signer struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// SignMobileconfig wraps the plist data in a CMS SignedData envelope.
// Apple requires an attached (non-detached) signature for mobileconfig files.
func SignMobileconfig(data []byte, s *Signer) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(data)
	if err != nil {
		return nil, fmt.Errorf("pkcs7 new signed data: %w", err)
	}
	if err := sd.AddSigner(s.Cert, s.Key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("pkcs7 add signer: %w", err)
	}
	signed, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("pkcs7 finish: %w", err)
	}
	return signed, nil
}
