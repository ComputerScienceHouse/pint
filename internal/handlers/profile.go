// internal/handlers/profile.go
package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/devicemap"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ProfilePage serves GET /profile.
func (s *Server) ProfilePage(c *gin.Context) {
	nav, _ := getNavInfo(c)
	data := nav.toMap()
	data["SSID"] = s.Cfg.WiFiSSID
	data["CSRFToken"] = c.GetString(csrfContextKey)
	c.HTML(http.StatusOK, "profile.html", data)
}

// GenerateProfile serves POST /profile/generate?platform=ios|manual|windows.
// Signer is optional; when non-nil, iOS mobileconfig profiles are CMS-signed.
func (s *Server) GenerateProfile(c *gin.Context) {
	platform := c.Query("platform")
	if platform != "ios" && platform != "manual" && platform != "windows" {
		s.fail(c, http.StatusBadRequest, "platform must be ios, manual, or windows", nil)
		return
	}

	username, ok := getUsername(c)
	if !ok {
		s.fail(c, http.StatusUnauthorized, "not authenticated", nil)
		return
	}

	radiusHost, _, _ := net.SplitHostPort(s.Cfg.RadiusServer)
	switch platform {
	case "windows":
		wlan, err := profile.BuildWLANProfile(profile.WLANProfileParams{
			SSID:       s.Cfg.WiFiSSID,
			RadiusHost: radiusHost,
			CACertDER:  s.CA.WiFiCACertDER,
		})
		if err != nil {
			s.fail(c, http.StatusInternalServerError, "WLAN profile build failed", err)
			return
		}
		s.log().Info("wifi profile generated", zap.String("platform", platform))
		c.Header("Content-Disposition", `attachment; filename="csh-wifi.xml"`)
		c.Data(http.StatusOK, "application/xml", wlan)

	case "ios":
		challenge, err := s.Challenges.Issue(username, c.Query("device_name"), "ios")
		if err != nil {
			s.fail(c, http.StatusInternalServerError, "challenge generation failed", err)
			return
		}
		mc, err := profile.BuildMobileconfig(profile.MobileconfigParams{
			SSID:                 s.Cfg.WiFiSSID,
			RadiusHost:           s.Cfg.IPAServiceHostname,
			CACertDER:            s.CA.WiFiCACertDER,
			RootCACertDER:        s.CA.RootCACertDER,
			CodeSigningCACertDER: s.CA.CodeSigningCACertDER,
			Username:             username,
			SCEPURL:              s.Cfg.SCEPURL,
			SCEPChallenge:        challenge,
			SCEPRACertDER:        s.CA.SCEPRACertDER,
		})
		if err != nil {
			s.fail(c, http.StatusInternalServerError, "mobileconfig build failed", err)
			return
		}
		signer := s.Signer.Load()
		if signer != nil {
			mc, err = profile.SignMobileconfig(mc, signer)
			if err != nil {
				s.fail(c, http.StatusInternalServerError, "mobileconfig signing failed", err)
				return
			}
		}
		s.log().Info("wifi profile generated", zap.String("platform", platform), zap.Bool("signed", signer != nil))
		c.Header("Content-Disposition", `attachment; filename="csh-wifi.mobileconfig"`)
		c.Data(http.StatusOK, "application/x-apple-aspen-config", mc)

	case "manual":
		privKey, csrPEM, err := profile.GenerateKeyAndCSR(username)
		if err != nil {
			s.fail(c, http.StatusInternalServerError, "key generation failed", err)
			return
		}
		certDER, err := s.IPA.CertRequest(username, string(csrPEM), s.Cfg.IPAWirelessCAName, s.Cfg.EAPClientCertProfile)
		if err != nil {
			s.fail(c, http.StatusInternalServerError, fmt.Sprintf("cert request failed: %v", err), err)
			return
		}
		if s.DM != nil {
			deviceName := c.Query("device_name")
			if len(deviceName) > 256 {
				deviceName = deviceName[:256]
			}
			if cert, parseErr := x509.ParseCertificate(certDER); parseErr != nil {
				s.log().Error("failed to parse issued cert for device map", zap.Error(parseErr))
			} else {
				info := devicemap.DeviceInfo{
					Username:   username,
					DeviceName: deviceName,
					Platform:   c.Query("os"),
					EnrolledAt: time.Now(),
				}
				if err := s.DM.Set(c.Request.Context(), cert.SerialNumber.String(), info); err != nil {
					s.log().Error("failed to record device info", zap.Error(err))
				}
			}
		}
		p12, err := profile.BuildPKCS12(privKey, certDER, s.CA.WiFiCACertDER, "")
		if err != nil {
			s.fail(c, http.StatusInternalServerError, "PKCS12 build failed", err)
			return
		}
		s.log().Info("wifi profile generated", zap.String("platform", platform))
		c.Header("Content-Disposition", `attachment; filename="csh-wifi.p12"`)
		c.Data(http.StatusOK, "application/x-pkcs12", p12)
	}
}

// SCEPChallenge serves GET /profile/scep-challenge.
// Issues a one-time challenge token for use with any SCEP client.
func (s *Server) SCEPChallenge(c *gin.Context) {
	username, ok := getUsername(c)
	if !ok {
		s.fail(c, http.StatusUnauthorized, "not authenticated", nil)
		return
	}
	token, err := s.Challenges.Issue(username, c.Query("device_name"), c.Query("os"))
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "challenge generation failed", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"challenge": token})
}

// CADownload serves GET /profile/ca, returns the FreeIPA WiFi CA certificate as PEM.
func (s *Server) CADownload(c *gin.Context) {
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.CA.WiFiCACertDER})
	c.Header("Content-Disposition", `attachment; filename="csh-ca.pem"`)
	c.Data(http.StatusOK, "application/x-x509-ca-cert", caPEM)
}
