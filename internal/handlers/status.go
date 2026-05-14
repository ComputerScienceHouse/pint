// internal/handlers/status.go
package handlers

import (
	"net/http"
	"net/url"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
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

		statusSecret, err := radius.EnsureStatusConfig(ctx, k8s, cfg.Namespace)
		if err != nil {
			statusSecret = ""
		}

		status, err := radius.GetStatus(ctx, k8s, metricsClient, cfg.Namespace, cfg.FreeRADIUSDeployment, cfg.RADIUSStatusPort, statusSecret, cfg.RADIUSStatusAddr)
		if err != nil {
			data["StatusError"] = err.Error()
		} else {
			data["Status"] = status
		}

		certInfo, err := radius.GetRadSecCertInfo(ctx, k8s, cfg.Namespace, cfg.RadSecCertSecret)
		if err != nil {
			data["CertError"] = err.Error()
		} else {
			data["Cert"] = certInfo
		}

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
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
func ReloadHandler(cfg *config.Config, k8s kubernetes.Interface) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isRTP(c) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if err := radius.Reload(c.Request.Context(), k8s, cfg.Namespace, cfg.FreeRADIUSDeployment); err != nil {
			dest := "/status?warn=" + url.QueryEscape("Rollout restart failed: "+err.Error())
			c.Redirect(http.StatusFound, dest)
			return
		}
		c.Redirect(http.StatusFound, "/status?success=FreeRADIUS+rollout+restart+triggered")
	}
}
