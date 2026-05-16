// internal/handlers/profile.go
package handlers

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/scep"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
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
// signer is optional; when non-nil, iOS mobileconfig profiles are CMS-signed.
// challenges issues one-time SCEP enrollment passwords for iOS profiles.
// scepRACertDER is the DER-encoded SCEP RA certificate embedded as CAFingerprint.
func GenerateProfileHandler(log *zap.Logger, ipaClient *freeipa.Client, cfg *config.Config, caDER, rootCACertDER, codeSigningCACertDER, scepRACertDER []byte, challenges *scep.ChallengeStore, signer *profile.Signer) gin.HandlerFunc {
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

		radiusHost := strings.Split(cfg.RadiusServer, ":")[0]
		switch platform {
		case "windows":
			wlan, err := profile.BuildWLANProfile(profile.WLANProfileParams{
				SSID:       cfg.WiFiSSID,
				RadiusHost: radiusHost,
				CACertDER:  caDER,
			})
			if err != nil {
				log.Error("WLAN profile build failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "WLAN profile build failed"})
				return
			}
			log.Info("wifi profile generated", zap.String("platform", platform))
			c.Header("Content-Disposition", `attachment; filename="csh-wifi.xml"`)
			c.Data(http.StatusOK, "application/xml", wlan)

		case "ios":
			challenge, err := challenges.Issue(username)
			if err != nil {
				log.Error("challenge generation failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "challenge generation failed"})
				return
			}
			mc, err := profile.BuildMobileconfig(profile.MobileconfigParams{
				SSID:                 cfg.WiFiSSID,
				RadiusHost:           radiusHost,
				CACertDER:            caDER,
				RootCACertDER:        rootCACertDER,
				CodeSigningCACertDER: codeSigningCACertDER,
				Username:             username,
				SCEPURL:              cfg.SCEPURL,
				SCEPChallenge:        challenge,
				SCEPRACertDER:        scepRACertDER,
			})
			if err != nil {
				log.Error("mobileconfig build failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "mobileconfig build failed"})
				return
			}
			if signer != nil {
				mc, err = profile.SignMobileconfig(mc, signer)
				if err != nil {
					log.Error("mobileconfig signing failed", zap.Error(err))
					c.JSON(http.StatusInternalServerError, gin.H{"error": "mobileconfig signing failed"})
					return
				}
			}
			log.Info("wifi profile generated", zap.String("platform", platform), zap.Bool("signed", signer != nil))
			c.Header("Content-Disposition", `attachment; filename="csh-wifi.mobileconfig"`)
			c.Data(http.StatusOK, "application/x-apple-aspen-config", mc)

		case "android":
			privKey, csrPEM, err := profile.GenerateKeyAndCSR(username)
			if err != nil {
				log.Error("key generation failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "key generation failed"})
				return
			}
			certDER, err := ipaClient.CertRequest(username, string(csrPEM), cfg.IPAWirelessCAName, cfg.IPACertProfile)
			if err != nil {
				log.Error("cert request failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("cert request failed: %v", err)})
				return
			}
			p12, err := profile.BuildPKCS12(privKey, certDER, caDER, "")
			if err != nil {
				log.Error("PKCS12 build failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS12 build failed"})
				return
			}
			log.Info("wifi profile generated", zap.String("platform", platform))
			c.Header("Content-Disposition", `attachment; filename="csh-wifi.p12"`)
			c.Data(http.StatusOK, "application/x-pkcs12", p12)
		}
	}
}

// CAHandler serves GET /profile/ca, returns the FreeIPA CA certificate as PEM.
func CAHandler(caDER []byte) gin.HandlerFunc {
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return func(c *gin.Context) {
		c.Header("Content-Disposition", `attachment; filename="csh-ca.pem"`)
		c.Data(http.StatusOK, "application/x-x509-ca-cert", caPEM)
	}
}
