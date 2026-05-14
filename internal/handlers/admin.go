// internal/handlers/admin.go
package handlers

import (
	"net/http"
	"net/url"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
	"k8s.io/client-go/kubernetes"
)

const rootUsername = "root"

// AdminRadiusPageHandler serves GET /admin/radius — all enrolled clients, RTP-gated.
func AdminRadiusPageHandler(cfg *config.Config, k8s kubernetes.Interface, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		data := nav.toMap()
		data["CSRFToken"] = c.GetString(csrfContextKey)
		data["CACertPEM"] = caChainPEM
		data["RootClient"] = store.FindByUsername(rootUsername)
		data["Clients"] = memberClients(store.All())
		data["FlashSuccess"] = c.Query("success")
		data["FlashWarn"] = c.Query("warn")
		c.HTML(http.StatusOK, "admin_radius.html", data)
	}
}

// AdminDeleteHandler serves POST /admin/radius/delete — revokes cert and removes a user's client entry.
func AdminDeleteHandler(cfg *config.Config, k8s kubernetes.Interface, ipaClient *freeipa.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.PostForm("username")
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
			return
		}
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		revokeExistingCert(ipaClient, store.FindByUsername(username), cfg.RadSecCAName, freeipa.RevocationReasonCessationOfOperation)
		store.Delete(username)
		reloadWarn, err := commitStore(c, store, k8s, cfg)
		if err != nil {
			return
		}
		c.Redirect(http.StatusFound, adminRadiusRedirect(username+" removed", reloadWarn))
	}
}

// AdminRegenerateHandler serves POST /admin/radius/regenerate — reissues credentials for any user.
func AdminRegenerateHandler(ipaClient *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.PostForm("username")
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
			return
		}
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		existing := store.FindByUsername(username)
		revokeExistingCert(ipaClient, existing, cfg.RadSecCAName, freeipa.RevocationReasonSuperseded)
		entry, _, _, err := issueClientCredentials(ipaClient, cfg, username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if existing != nil {
			entry.IPCIDR = existing.IPCIDR
		}
		store.Upsert(*entry)
		reloadWarn, err := commitStore(c, store, k8s, cfg)
		if err != nil {
			return
		}
		c.Redirect(http.StatusFound, adminRadiusRedirect("Credentials regenerated for "+username, reloadWarn))
	}
}

// AdminRootProvisionHandler serves POST /admin/radius/root/provision.
func AdminRootProvisionHandler(ipaClient *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if store.FindByUsername(rootUsername) != nil {
			c.Redirect(http.StatusFound, "/admin/radius?warn="+url.QueryEscape("Root client already provisioned — use Regenerate to reissue credentials"))
			return
		}
		entry, keyPEM, certPEM, err := issueClientCredentials(ipaClient, cfg, rootUsername)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		store.Upsert(*entry)
		reloadWarn, err := commitStore(c, store, k8s, cfg)
		if err != nil {
			return
		}
		renderRootCredsPage(c, nav, store, entry, keyPEM, certPEM, caChainPEM,
			"Organization controller provisioned — save credentials now, they will not be shown again",
			reloadWarn)
	}
}

// AdminRootRegenerateHandler serves POST /admin/radius/root/regenerate.
func AdminRootRegenerateHandler(ipaClient *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		existing := store.FindByUsername(rootUsername)
		revokeExistingCert(ipaClient, existing, cfg.RadSecCAName, freeipa.RevocationReasonSuperseded)
		entry, keyPEM, certPEM, err := issueClientCredentials(ipaClient, cfg, rootUsername)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if existing != nil {
			entry.IPCIDR = existing.IPCIDR
		}
		store.Upsert(*entry)
		reloadWarn, err := commitStore(c, store, k8s, cfg)
		if err != nil {
			return
		}
		renderRootCredsPage(c, nav, store, entry, keyPEM, certPEM, caChainPEM,
			"Organization controller credentials regenerated — save the new key and cert now",
			reloadWarn)
	}
}

// AdminRootUpdateIPHandler serves POST /admin/radius/root/update-ip.
func AdminRootUpdateIPHandler(cfg *config.Config, k8s kubernetes.Interface) gin.HandlerFunc {
	return func(c *gin.Context) {
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		existing := store.FindByUsername(rootUsername)
		if existing == nil {
			c.Redirect(http.StatusFound, "/admin/radius?warn="+url.QueryEscape("Root client is not provisioned"))
			return
		}
		ipCIDR, ok := parseIPCIDR(c)
		if !ok {
			return
		}
		updated := *existing
		if ipCIDR != "" {
			updated.IPCIDR = &ipCIDR
		} else {
			updated.IPCIDR = nil
		}
		store.Upsert(updated)
		reloadWarn, err := commitStore(c, store, k8s, cfg)
		if err != nil {
			return
		}
		c.Redirect(http.StatusFound, adminRadiusRedirect("Source IP updated for organization controller", reloadWarn))
	}
}

// renderRootCredsPage builds and renders the admin_radius.html page with one-time root credentials.
func renderRootCredsPage(c *gin.Context, nav navInfo, store *radius.ClientStore, entry *radius.RadiusClient, keyPEM, certPEM, caChainPEM, successMsg, reloadWarn string) {
	data := nav.toMap()
	data["CSRFToken"] = c.GetString(csrfContextKey)
	data["CACertPEM"] = caChainPEM
	data["RootClient"] = entry
	data["RootKeyPEM"] = keyPEM
	data["RootCertPEM"] = certPEM
	data["Clients"] = memberClients(store.All())
	data["FlashSuccess"] = successMsg
	if reloadWarn != "" {
		data["FlashWarn"] = "FreeRADIUS reload failed: " + reloadWarn
	}
	c.HTML(http.StatusOK, "admin_radius.html", data)
}

// adminRadiusRedirect builds a redirect URL to /admin/radius with success and optional reload warning.
func adminRadiusRedirect(success, reloadWarn string) string {
	dest := "/admin/radius?success=" + url.QueryEscape(success)
	if reloadWarn != "" {
		dest += "&warn=" + url.QueryEscape("FreeRADIUS reload failed: " + reloadWarn)
	}
	return dest
}

// memberClients filters out the reserved root username, returning only member-owned clients.
func memberClients(all []radius.RadiusClient) []radius.RadiusClient {
	out := make([]radius.RadiusClient, 0, len(all))
	for _, c := range all {
		if c.Username != rootUsername {
			out = append(out, c)
		}
	}
	return out
}
