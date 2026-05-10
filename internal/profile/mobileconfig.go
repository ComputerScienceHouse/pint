// internal/profile/mobileconfig.go
package profile

import (
	"fmt"

	"howett.net/plist"
)

// MobileconfigParams holds the data needed to build an Apple Configuration Profile.
type MobileconfigParams struct {
	SSID        string
	RadiusHost  string // hostname only, no port
	PKCS12Bytes []byte
	CACertDER   []byte
	Username    string
}

// BuildMobileconfig returns a plist-encoded Apple Configuration Profile
// containing a WiFi (EAP-TLS), PKCS#12 identity, and CA certificate payload.
func BuildMobileconfig(p MobileconfigParams) ([]byte, error) {
	caUUID := fmt.Sprintf("CA-%s-0001", p.Username)
	clientUUID := fmt.Sprintf("CLIENT-%s-0001", p.Username)
	profileUUID := fmt.Sprintf("PROFILE-%s-0001", p.Username)

	wifiPayload := map[string]interface{}{
		"PayloadType":        "com.apple.wifi.managed",
		"PayloadUUID":        fmt.Sprintf("WIFI-%s-0001", p.Username),
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
		"Password":           "",
	}

	caPayload := map[string]interface{}{
		"PayloadType":        "com.apple.security.root",
		"PayloadUUID":        caUUID,
		"PayloadIdentifier":  fmt.Sprintf("com.csh.pint.ca.%s", p.Username),
		"PayloadVersion":     1,
		"PayloadDisplayName": "CSH FreeIPA CA",
		"PayloadContent":     p.CACertDER,
	}

	profile := map[string]interface{}{
		"PayloadContent":     []interface{}{wifiPayload, pkcs12Payload, caPayload},
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
