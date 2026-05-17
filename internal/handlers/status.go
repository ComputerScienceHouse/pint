// internal/handlers/status.go
package handlers

import (
	"net/http"
	"net/url"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
)

// StatusPageHandler serves GET /status — FreeRADIUS health for all authenticated users.
func StatusPageHandler(cfg *config.Config, k8s kubernetes.Interface, metricsClient metricsv.Interface) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)
		data := nav.toMap()
		data["CSRFToken"] = c.GetString(csrfContextKey)
		data["FlashSuccess"] = c.Query("success")
		data["FlashWarn"] = c.Query("warn")

		ctx := c.Request.Context()

		statusSecret, err := radius.EnsureStatusConfig(ctx, k8s, cfg.Namespace, cfg.ConfigSecret)
		if err != nil {
			statusSecret = ""
		}

		status, err := radius.GetStatus(ctx, k8s, metricsClient, cfg.Namespace, cfg.FreeRADIUSDeployment, cfg.RADIUSStatusPort, statusSecret, cfg.RADIUSStatusAddr)
		if err != nil {
			data["StatusError"] = err.Error()
		} else {
			data["Status"] = status
		}

		certInfo, err := radius.GetCertInfo(ctx, k8s, cfg.Namespace, cfg.RadSecCertSecret, "tls.crt")
		if err != nil {
			data["CertError"] = err.Error()
		} else {
			data["Cert"] = certInfo
		}

		eapCertInfo, err := radius.GetCertInfo(ctx, k8s, cfg.Namespace, cfg.EAPCertSecret, "eap.crt")
		if err != nil {
			data["EAPCertError"] = err.Error()
		} else {
			data["EAPCert"] = eapCertInfo
		}

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.ConfigSecret)
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
}

// ReloadHandler serves POST /status/reload — triggers a FreeRADIUS rollout restart.
// Only RTPs may trigger this; non-RTPs receive 403.
func ReloadHandler(log *zap.Logger, cfg *config.Config, k8s kubernetes.Interface) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isRTP(c) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		actor, _ := getUsername(c)
		if err := radius.Reload(c.Request.Context(), k8s, cfg.Namespace, cfg.FreeRADIUSDeployment); err != nil {
			log.Error("manual freeradius reload failed", zap.String("actor", actor), zap.Error(err))
			dest := "/status?warn=" + url.QueryEscape("Rollout restart failed: "+err.Error())
			c.Redirect(http.StatusFound, dest)
			return
		}
		log.Info("manual freeradius reload triggered", zap.String("actor", actor))
		c.Redirect(http.StatusFound, "/status?success=FreeRADIUS+rollout+restart+triggered")
	}
}
