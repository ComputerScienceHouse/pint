// internal/profile/mobileconfig.go
package profile

import (
	"crypto/sha1" //nolint:gosec
	"fmt"

	"github.com/google/uuid"
	"howett.net/plist"
)

// MobileconfigParams holds the data needed to build an Apple Configuration Profile.
type MobileconfigParams struct {
	SSID                 string
	RadiusHost           string // hostname only, no port
	CACertDER            []byte // wireless intermediate CA — anchors EAP-TLS server verification.
	// FreeRADIUS presents a cert signed by the wireless CA for EAP-TLS (eap.crt in the
	// radsec secret), so this CA is the correct anchor. The outer RadSec TLS cert (tls.crt)
	// is signed by the RadSec CA and is verified by routers, not end devices.
	// See: dev/freeradius/eap — certificate_file = /etc/pint/radsec/eap.crt.
	RootCACertDER        []byte // root CA — always embed for full chain trust
	CodeSigningCACertDER []byte // code-signing intermediate CA — embed when profile signing is enabled
	Username             string

	// SCEP enrollment fields
	SCEPURL       string // full URL of the SCEP endpoint, e.g. https://pint.csh.rit.edu/scep
	SCEPChallenge string // one-time challenge password from the ChallengeStore
	SCEPRACertDER []byte // RA cert — SHA-1 fingerprint embedded as CAFingerprint for iOS verification
}

// BuildMobileconfig returns a plist-encoded Apple Configuration Profile containing
// a WiFi (EAP-TLS) payload and a SCEP payload for on-device key generation and enrollment.
func BuildMobileconfig(p MobileconfigParams) ([]byte, error) {
	caUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.ca."+p.Username)).String()
	rootCAUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.rootca."+p.Username)).String()
	scepUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.scep."+p.Username)).String()
	profileUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.profile."+p.Username)).String()
	wifiUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.wifi."+p.Username)).String()

	//nolint:gosec
	raFingerprint := sha1.Sum(p.SCEPRACertDER)

	scepContent := map[string]interface{}{
		"URL":           p.SCEPURL,
		"Name":          "CSH WiFi",
		"Subject":       [][][]string{{{"CN", p.Username}}},
		"Challenge":     p.SCEPChallenge,
		"Key Type":      "RSA",
		"Keysize":       2048,
		"Key Usage":     1, // digitalSignature (bitmask: 1=signing, 4=encryption)
		"CAFingerprint": raFingerprint[:],
	}

	scepPayload := map[string]interface{}{
		"PayloadType":        "com.apple.security.scep",
		"PayloadUUID":        scepUUID,
		"PayloadIdentifier":  fmt.Sprintf("com.csh.pint.scep.%s", p.Username),
		"PayloadVersion":     1,
		"PayloadDisplayName": "CSH WiFi Client Certificate",
		"PayloadContent":     scepContent,
	}

	wifiPayload := map[string]interface{}{
		"PayloadType":        "com.apple.wifi.managed",
		"PayloadUUID":        wifiUUID,
		"PayloadIdentifier":  fmt.Sprintf("com.csh.pint.wifi.%s", p.Username),
		"PayloadVersion":     1,
		"PayloadDisplayName": "CSH WiFi",
		"SSID_STR":           p.SSID,
		"EncryptionType":     "WPA2",
		"EAPClientConfiguration": map[string]interface{}{
			"AcceptEAPTypes":               []int{13},
			"PayloadCertificateAnchorUUID": []string{caUUID, rootCAUUID},
			"TLSTrustedServerNames":        []string{p.RadiusHost},
		},
		"PayloadCertificateUUID": scepUUID,
	}

	// Wireless intermediate CA — anchors EAP-TLS server verification and embedded for chain reference.
	caPayload := map[string]interface{}{
		"PayloadType":        "com.apple.security.root",
		"PayloadUUID":        caUUID,
		"PayloadIdentifier":  fmt.Sprintf("com.csh.pint.ca.%s", p.Username),
		"PayloadVersion":     1,
		"PayloadDisplayName": "CSH Wireless CA",
		"PayloadContent":     p.CACertDER,
	}

	// Root CA — establishes trust for the full chain.
	rootCAPayload := map[string]interface{}{
		"PayloadType":        "com.apple.security.root",
		"PayloadUUID":        rootCAUUID,
		"PayloadIdentifier":  fmt.Sprintf("com.csh.pint.rootca.%s", p.Username),
		"PayloadVersion":     1,
		"PayloadDisplayName": "CSH Root CA",
		"PayloadContent":     p.RootCACertDER,
	}

	payloads := []interface{}{scepPayload, wifiPayload, caPayload, rootCAPayload}

	// Code-signing CA — embed when profile signing is enabled so the signing chain
	// is trusted after the profile is installed.
	if len(p.CodeSigningCACertDER) > 0 {
		codeSigningCAUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.codesigningca."+p.Username)).String()
		payloads = append(payloads, map[string]interface{}{
			"PayloadType":        "com.apple.security.root",
			"PayloadUUID":        codeSigningCAUUID,
			"PayloadIdentifier":  fmt.Sprintf("com.csh.pint.codesigningca.%s", p.Username),
			"PayloadVersion":     1,
			"PayloadDisplayName": "CSH Code Signing CA",
			"PayloadContent":     p.CodeSigningCACertDER,
		})
	}

	profile := map[string]interface{}{
		"PayloadContent":     payloads,
		"PayloadDisplayName": "CSH WiFi",
		"PayloadIdentifier":  fmt.Sprintf("com.csh.pint.profile.%s", p.Username),
		"PayloadType":        "Configuration",
		"PayloadUUID":        profileUUID,
		"PayloadVersion":     1,
	}

	data, err := plist.Marshal(profile, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("marshal mobileconfig: %w", err)
	}
	return data, nil
}
