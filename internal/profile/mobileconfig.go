// internal/profile/mobileconfig.go
package profile

import (
	"fmt"

	"github.com/google/uuid"
	"howett.net/plist"
)

// MobileconfigParams holds the data needed to build an Apple Configuration Profile.
type MobileconfigParams struct {
	SSID                 string
	RadiusHost           string // hostname only, no port
	PKCS12Bytes          []byte
	PKCS12Password       string
	CACertDER            []byte // wireless intermediate CA
	RootCACertDER        []byte // root CA — always embed for full chain trust
	CodeSigningCACertDER []byte // code-signing intermediate CA — embed when profile signing is enabled
	Username             string
}

// BuildMobileconfig returns a plist-encoded Apple Configuration Profile
// containing a WiFi (EAP-TLS), PKCS#12 identity, and CA certificate payloads.
func BuildMobileconfig(p MobileconfigParams) ([]byte, error) {
	caUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.ca."+p.Username)).String()
	rootCAUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.rootca."+p.Username)).String()
	clientUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.client."+p.Username)).String()
	profileUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.profile."+p.Username)).String()
	wifiUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("com.csh.pint.wifi."+p.Username)).String()

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
			"PayloadCertificateAnchorUUID": []string{caUUID},
			"TLSTrustedServerNames":        []string{p.RadiusHost},
		},
		"PayloadCertificateUUID": clientUUID,
	}

	pkcs12Payload := map[string]interface{}{
		"PayloadType":        "com.apple.security.pkcs12",
		"PayloadUUID":        clientUUID,
		"PayloadIdentifier":  fmt.Sprintf("com.csh.pint.pkcs12.%s", p.Username),
		"PayloadVersion":     1,
		"PayloadDisplayName": "CSH WiFi Client Certificate",
		"PayloadContent":     p.PKCS12Bytes,
		"Password":           p.PKCS12Password,
	}

	// Wireless intermediate CA — anchors EAP-TLS server verification.
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

	payloads := []interface{}{wifiPayload, pkcs12Payload, caPayload, rootCAPayload}

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
