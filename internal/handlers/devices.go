// internal/handlers/devices.go
package handlers

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/devicemap"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type deviceView struct {
	Serial        string
	DeviceName    string
	Platform      string
	IsSCEP        bool
	IsExpired     bool
	EnrolledAt    time.Time
	LastRenewedAt time.Time
	ExpiresAt     time.Time
	HasMapInfo    bool // false if cert predates device tracking
}

// ExpiresIn returns a human-readable relative expiry string, e.g. "11 months" or "25 days".
func (d deviceView) ExpiresIn() string {
	if d.ExpiresAt.IsZero() || d.IsExpired {
		return ""
	}
	until := time.Until(d.ExpiresAt)
	if until <= 0 {
		return ""
	}
	days := int(until.Hours() / 24)
	if days < 60 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	months := int(math.Round(until.Hours() / (24 * 30.44)))
	if months == 1 {
		return "1 month"
	}
	return fmt.Sprintf("%d months", months)
}

// IsExpiringSoon returns true when the cert expires within 30 days.
func (d deviceView) IsExpiringSoon() bool {
	if d.ExpiresAt.IsZero() || d.IsExpired {
		return false
	}
	return time.Until(d.ExpiresAt) < 30*24*time.Hour
}

type adminDeviceView struct {
	Username   string
	Serial     string
	DeviceName string
	Platform   string
	EnrolledAt time.Time
}

// certTimeFormats are tried in order when parsing valid_not_after from FreeIPA.
var certTimeFormats = []string{time.RFC3339, "20060102150405Z", "20060102150405-0700"}

func parseCertTime(s string) (time.Time, error) {
	for _, layout := range certTimeFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable cert time %q", s)
}


func (s *Server) revokeWiFiCert(ctx context.Context, serial int64, serialStr string) error {
	if err := s.IPA.CertRevoke(serial, s.Cfg.IPAWirelessCAName, freeipa.RevocationReasonCessationOfOperation); err != nil {
		s.log().Error("devices: cert_revoke failed", zap.Int64("serial", serial), zap.Error(err))
		return err
	}
	if err := s.DM.Delete(ctx, serialStr); err != nil {
		s.log().Error("devices: device map delete failed", zap.String("serial", serialStr), zap.Error(err))
	}
	return nil
}

// DevicesPage serves GET /devices — the self-service device list.
func (s *Server) DevicesPage(c *gin.Context) {
	username, ok := getUsername(c)
	if !ok {
		s.fail(c, http.StatusUnauthorized, "not authenticated", nil)
		return
	}

	var (
		certList   []freeipa.CertInfo
		allEntries map[string]devicemap.DeviceInfo
		certErr    error
		mapErr     error
		wg         sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		certList, certErr = s.IPA.CertFind(username, s.Cfg.IPAWirelessCAName)
	}()
	go func() {
		defer wg.Done()
		allEntries, mapErr = s.DM.All(c.Request.Context())
	}()
	wg.Wait()

	if certErr != nil {
		s.fail(c, http.StatusInternalServerError, "failed to list certificates", certErr)
		return
	}
	if mapErr != nil {
		s.log().Warn("devices: device map unavailable", zap.Error(mapErr))
		allEntries = map[string]devicemap.DeviceInfo{}
	}

	var active, expired []deviceView
	for _, cert := range certList {
		if cert.Revoked {
			continue
		}
		serialStr := strconv.FormatInt(cert.SerialNumber, 10)
		v := deviceView{Serial: serialStr}
		if info, ok := allEntries[serialStr]; ok {
			v.DeviceName = info.DeviceName
			v.Platform = info.Platform
			v.IsSCEP = info.IsSCEP
			v.EnrolledAt = info.EnrolledAt
			v.LastRenewedAt = info.LastRenewedAt
			v.ExpiresAt = info.ExpiresAt
			v.HasMapInfo = true
			if v.ExpiresAt.IsZero() {
				// Device map entry predates expiry tracking; fall back to the cert itself.
				v.ExpiresAt, _ = parseCertTime(cert.ValidNotAfter)
			}
		} else {
			notAfter, timeErr := parseCertTime(cert.ValidNotAfter)
			if timeErr != nil {
				s.log().Warn("devices: unparseable cert time", zap.String("value", cert.ValidNotAfter), zap.Error(timeErr))
			}
			v.DeviceName = "Unknown device"
			v.ExpiresAt = notAfter
		}
		if !v.ExpiresAt.IsZero() && v.ExpiresAt.Before(time.Now()) {
			v.IsExpired = true
			expired = append(expired, v)
		} else {
			active = append(active, v)
		}
	}

	byEnrolled := func(views []deviceView) {
		sort.Slice(views, func(i, j int) bool {
			return views[i].EnrolledAt.After(views[j].EnrolledAt)
		})
	}
	byEnrolled(active)
	byEnrolled(expired)

	nav, _ := getNavInfo(c)
	data := nav.toMap()
	data["Devices"] = active
	data["ExpiredDevices"] = expired
	data["CSRFToken"] = c.GetString(csrfContextKey)
	data["FlashSuccess"] = getFlash(c, flashSuccess)
	data["FlashError"] = getFlash(c, flashError)
	c.HTML(http.StatusOK, "devices.html", data)
}

// RevokeDevice serves POST /devices/revoke — self-service cert revocation.
func (s *Server) RevokeDevice(c *gin.Context) {
	username, ok := getUsername(c)
	if !ok {
		s.fail(c, http.StatusUnauthorized, "not authenticated", nil)
		return
	}

	serialStr := c.PostForm("serial")
	serial, err := strconv.ParseInt(serialStr, 10, 64)
	if err != nil || serialStr == "" {
		setFlash(c, flashError, "Invalid serial number.")
		c.Redirect(http.StatusFound, "/devices")
		return
	}

	certList, err := s.IPA.CertFind(username, s.Cfg.IPAWirelessCAName)
	if err != nil {
		s.log().Error("devices: cert_find failed during revoke", zap.String("username", username), zap.Error(err))
		setFlash(c, flashError, "Could not verify certificate ownership.")
		c.Redirect(http.StatusFound, "/devices")
		return
	}
	owned := false
	for _, cert := range certList {
		if cert.SerialNumber == serial {
			owned = true
			break
		}
	}
	if !owned {
		s.log().Warn("devices: revoke attempt for unowned cert", zap.String("username", username), zap.Int64("serial", serial))
		setFlash(c, flashError, "Certificate not found.")
		c.Redirect(http.StatusFound, "/devices")
		return
	}

	if err := s.revokeWiFiCert(c.Request.Context(), serial, serialStr); err != nil {
		setFlash(c, flashError, "Revocation failed. Please try again or contact support.")
		c.Redirect(http.StatusFound, "/devices")
		return
	}

	s.log().Info("devices: cert revoked", zap.String("username", username), zap.Int64("serial", serial))
	setFlash(c, flashSuccess, "Certificate revoked successfully.")
	c.Redirect(http.StatusFound, "/devices")
}

// AdminDevicesPage serves GET /admin/devices — RTP view of all enrolled devices.
func (s *Server) AdminDevicesPage(c *gin.Context) {
	allEntries, err := s.DM.All(c.Request.Context())
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load device map", err)
		return
	}

	views := make([]adminDeviceView, 0, len(allEntries))
	for serial, info := range allEntries {
		views = append(views, adminDeviceView{
			Username:   info.Username,
			Serial:     serial,
			DeviceName: info.DeviceName,
			Platform:   info.Platform,
			EnrolledAt: info.EnrolledAt,
		})
	}

	sort.Slice(views, func(i, j int) bool {
		if views[i].Username != views[j].Username {
			return views[i].Username < views[j].Username
		}
		return views[i].EnrolledAt.After(views[j].EnrolledAt)
	})

	nav, _ := getNavInfo(c)
	data := nav.toMap()
	data["Devices"] = views
	data["CSRFToken"] = c.GetString(csrfContextKey)
	data["FlashSuccess"] = getFlash(c, flashSuccess)
	data["FlashError"] = getFlash(c, flashError)
	c.HTML(http.StatusOK, "admin_devices.html", data)
}

// AdminRevokeDevice serves POST /admin/devices/revoke — RTP cert revocation for any user.
func (s *Server) AdminRevokeDevice(c *gin.Context) {
	serialStr := c.PostForm("serial")
	serial, err := strconv.ParseInt(serialStr, 10, 64)
	if err != nil || serialStr == "" {
		setFlash(c, flashError, "Invalid serial number.")
		c.Redirect(http.StatusFound, "/admin/devices")
		return
	}

	revoker, _ := getUsername(c)

	if entry, ok, _ := s.DM.Get(c.Request.Context(), serialStr); ok && entry.Username != "" {
		s.log().Info("admin/devices: revoking cert",
			zap.String("owner", entry.Username),
			zap.String("revoker", revoker),
			zap.Int64("serial", serial))
	}

	if err := s.revokeWiFiCert(c.Request.Context(), serial, serialStr); err != nil {
		setFlash(c, flashError, "Revocation failed. Please try again or contact support.")
		c.Redirect(http.StatusFound, "/admin/devices")
		return
	}

	s.log().Info("admin/devices: cert revoked", zap.String("revoker", revoker), zap.Int64("serial", serial))
	setFlash(c, flashSuccess, "Certificate "+serialStr+" revoked.")
	c.Redirect(http.StatusFound, "/admin/devices")
}
