// internal/handlers/status.go
package handlers

import (
	"net/http"

	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// StatusPage serves GET /status — FreeRADIUS health for all authenticated users.
func (s *Server) StatusPage(c *gin.Context) {
	nav, _ := getNavInfo(c)
	data := nav.toMap()
	data["CSRFToken"] = c.GetString(csrfContextKey)
	data["FlashSuccess"] = getFlash(c, flashSuccess)
	data["FlashWarn"] = getFlash(c, flashWarn)

	ctx := c.Request.Context()

	statusSecret, err := radius.EnsureStatusConfig(ctx, s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err != nil {
		statusSecret = ""
	}

	status, err := radius.GetStatus(ctx, s.K8s, s.Metrics, s.Cfg.Namespace, s.Cfg.FreeRADIUSDeployment, s.Cfg.RADIUSStatusPort, statusSecret, s.Cfg.RADIUSStatusAddr)
	if err != nil {
		data["StatusError"] = err.Error()
	} else {
		data["Status"] = status
	}

	certInfo, err := radius.GetCertInfo(ctx, s.K8s, s.Cfg.Namespace, s.Cfg.RadSecCertSecret, "tls.crt")
	if err != nil {
		data["CertError"] = err.Error()
	} else {
		data["Cert"] = certInfo
	}

	eapCertInfo, err := radius.GetCertInfo(ctx, s.K8s, s.Cfg.Namespace, s.Cfg.EAPCertSecret, "eap.crt")
	if err != nil {
		data["EAPCertError"] = err.Error()
	} else {
		data["EAPCert"] = eapCertInfo
	}

	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(ctx); err == nil {
		clients := store.All()
		noIP := 0
		for _, cl := range clients {
			if cl.IPCIDR == nil {
				noIP++
			}
		}
		data["ClientCount"] = len(clients)
		data["ClientNoIPCount"] = noIP
	}

	c.HTML(http.StatusOK, "status.html", data)
}

// Reload serves POST /status/reload — triggers a FreeRADIUS rollout restart.
// Only RTPs may trigger this; non-RTPs receive 403.
func (s *Server) Reload(c *gin.Context) {
	if !isRTP(c) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	actor, _ := getUsername(c)
	if err := radius.Reload(c.Request.Context(), s.K8s, s.Cfg.Namespace, s.Cfg.FreeRADIUSDeployment); err != nil {
		s.log().Error("manual freeradius reload failed", zap.String("actor", actor), zap.Error(err))
		setFlash(c, flashWarn, "Rollout restart failed: "+err.Error())
		c.Redirect(http.StatusFound, "/status")
		return
	}
	s.log().Info("manual freeradius reload triggered", zap.String("actor", actor))
	setFlash(c, flashSuccess, "FreeRADIUS rollout restart triggered")
	c.Redirect(http.StatusFound, "/status")
}
