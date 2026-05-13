// internal/profile/wlanprofile.go
package profile

import (
	"crypto/sha1"
	"fmt"
	"strings"
)

// WLANProfileParams holds the data needed to build a Windows WLAN profile.
type WLANProfileParams struct {
	SSID       string
	RadiusHost string // hostname only, no port
	CACertDER  []byte
}

// BuildWLANProfile returns a Windows WLAN profile XML for EAP-TLS / WPA2-Enterprise.
// The profile uses SimpleCertSelection so Windows picks the installed client cert
// automatically from the user's certificate store.
func BuildWLANProfile(p WLANProfileParams) ([]byte, error) {
	fingerprint := sha1.Sum(p.CACertDER)
	hexParts := make([]string, len(fingerprint))
	for i, b := range fingerprint {
		hexParts[i] = fmt.Sprintf("%02x", b)
	}
	thumbprint := strings.Join(hexParts, " ")

	xml := fmt.Sprintf(`<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>%s</name>
    <SSIDConfig>
        <SSID>
            <name>%s</name>
        </SSID>
        <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2</authentication>
                <encryption>AES</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                <authMode>user</authMode>
                <EAPConfig>
                    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <EapMethod>
                            <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
                            <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                            <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                            <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
                        </EapMethod>
                        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                            <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                <Type>13</Type>
                                <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
                                    <CredentialsSource>
                                        <CertificateStore>
                                            <SimpleCertSelection>true</SimpleCertSelection>
                                        </CertificateStore>
                                    </CredentialsSource>
                                    <ServerValidation>
                                        <DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
                                        <ServerNames>%s</ServerNames>
                                        <TrustedRootCA>%s</TrustedRootCA>
                                    </ServerValidation>
                                    <DifferentUsername>false</DifferentUsername>
                                    <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>
                                    <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName>
                                </EapType>
                            </Eap>
                        </Config>
                    </EapHostConfig>
                </EAPConfig>
            </OneX>
        </security>
    </MSM>
</WLANProfile>`, p.SSID, p.SSID, p.RadiusHost, thumbprint)

	return []byte(xml), nil
}
