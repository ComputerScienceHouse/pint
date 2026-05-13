// internal/handlers/profile.go
package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/gin-gonic/gin"
)

// ProfilePageHandler serves GET /profile.
func ProfilePageHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)
		data := nav.toMap()
		data["SSID"] = cfg.WiFiSSID
		data["CSRFToken"] = c.GetString(csrfContextKey)
		c.HTML(http.StatusOK, "profile.html", data)
	}
}

// GenerateProfileHandler serves POST /profile/generate?platform=ios|android|windows.
func GenerateProfileHandler(ipaClient *freeipa.Client, cfg *config.Config, caDER []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		platform := c.Query("platform")
		if platform != "ios" && platform != "android" && platform != "windows" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "platform must be ios, android, or windows"})
			return
		}

		username, ok := getUsername(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}

		if platform == "windows" {
			radiusHost := strings.Split(cfg.RadiusServer, ":")[0]
			wlan, err := profile.BuildWLANProfile(profile.WLANProfileParams{
				SSID:       cfg.WiFiSSID,
				RadiusHost: radiusHost,
				CACertDER:  caDER,
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "WLAN profile build failed"})
				return
			}
			c.Header("Content-Disposition", `attachment; filename="csh-wifi.xml"`)
			c.Data(http.StatusOK, "application/xml", wlan)
			return
		}

		privKey, csrPEM, err := profile.GenerateKeyAndCSR(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "key generation failed"})
			return
		}

		certDER, err := ipaClient.CertRequest(username, string(csrPEM), cfg.IPAWirelessCAName, cfg.IPACertProfile)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("cert request failed: %v", err)})
			return
		}

		p12, err := profile.BuildPKCS12(privKey, certDER, caDER)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS12 build failed"})
			return
		}

		switch platform {
		case "ios":
			radiusHost := strings.Split(cfg.RadiusServer, ":")[0]
			mc, err := profile.BuildMobileconfig(profile.MobileconfigParams{
				SSID:        cfg.WiFiSSID,
				RadiusHost:  radiusHost,
				PKCS12Bytes: p12,
				CACertDER:   caDER,
				Username:    username,
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "mobileconfig build failed"})
				return
			}
			c.Header("Content-Disposition", `attachment; filename="csh-wifi.mobileconfig"`)
			c.Data(http.StatusOK, "application/x-apple-aspen-config", mc)

		case "android":
			c.Header("Content-Disposition", `attachment; filename="csh-wifi.p12"`)
			c.Data(http.StatusOK, "application/x-pkcs12", p12)
		}
	}
}

// CAHandler serves GET /profile/ca, returns the FreeIPA CA certificate as DER.
func CAHandler(caDER []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Disposition", `attachment; filename="csh-ca.cer"`)
		c.Data(http.StatusOK, "application/x-x509-ca-cert", caDER)
	}
}
