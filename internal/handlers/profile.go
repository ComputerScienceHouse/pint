// internal/handlers/profile.go
package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/devicemap"
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

// GenerateProfileHandler serves POST /profile/generate?platform=ios|manual|windows.
// signer is optional; when non-nil, iOS mobileconfig profiles are CMS-signed.
// challenges issues one-time SCEP enrollment passwords for iOS profiles.
// scepRACertDER is the DER-encoded SCEP RA certificate embedded as CAFingerprint.
// dm is optional; when non-nil, cert serial → device info is recorded on issuance.
func GenerateProfileHandler(log *zap.Logger, ipaClient *freeipa.Client, cfg *config.Config, caDER, rootCACertDER, codeSigningCACertDER, scepRACertDER []byte, challenges *scep.ChallengeStore, signer *profile.Signer, dm *devicemap.DeviceMap) gin.HandlerFunc {
	return func(c *gin.Context) {
		platform := c.Query("platform")
		if platform != "ios" && platform != "manual" && platform != "windows" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "platform must be ios, manual, or windows"})
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
			challenge, err := challenges.Issue(username, c.Query("device_name"))
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

		case "manual":
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
			if dm != nil {
				deviceName := c.Query("device_name")
				if len(deviceName) > 256 {
					deviceName = deviceName[:256]
				}
				if cert, parseErr := x509.ParseCertificate(certDER); parseErr != nil {
					log.Error("failed to parse issued cert for device map", zap.Error(parseErr))
				} else {
					info := devicemap.DeviceInfo{
						DeviceName: deviceName,
						Platform:   c.Query("os"),
						EnrolledAt: time.Now(),
					}
					if err := dm.Set(c.Request.Context(), cert.SerialNumber.String(), info); err != nil {
						log.Error("failed to record device info", zap.Error(err))
					}
				}
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

// SCEPChallengeHandler serves GET /profile/scep-challenge.
// Issues a one-time challenge token that can be used with any SCEP client
// (e.g. Get-SCEPCertificate on Windows, sscep or strongswan pki on Linux).
func SCEPChallengeHandler(log *zap.Logger, challenges *scep.ChallengeStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, ok := getUsername(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}
		token, err := challenges.Issue(username, "")
		if err != nil {
			log.Error("challenge generation failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "challenge generation failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"challenge": token})
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
