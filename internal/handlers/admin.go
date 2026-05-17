// internal/handlers/admin.go
package handlers

import (
	"net/http"
	"net/url"

	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AdminRadiusPage serves GET /admin/radius — all enrolled clients, RTP-gated.
func (s *Server) AdminRadiusPage(c *gin.Context) {
	nav, _ := getNavInfo(c)
	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	data := nav.toMap()
	data["CSRFToken"] = c.GetString(csrfContextKey)
	data["CACertPEM"] = s.CA.RadSecCAChainPEM
	data["RootClient"] = store.FindByUsername(rootUsername)
	data["Clients"] = memberClients(store.All())
	data["FlashSuccess"] = c.Query("success")
	data["FlashWarn"] = c.Query("warn")
	c.HTML(http.StatusOK, "admin_radius.html", data)
}

// AdminDelete serves POST /admin/radius/delete — revokes cert and removes a user's client entry.
func (s *Server) AdminDelete(c *gin.Context) {
	username := c.PostForm("username")
	if username == "" {
		s.fail(c, http.StatusBadRequest, "username required", nil)
		return
	}
	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	s.revokeExistingCert(store.FindByUsername(username), s.Cfg.RadSecCAName, freeipa.RevocationReasonCessationOfOperation)
	store.Delete(username)
	if err := s.commitStore(c, store); err != nil {
		return
	}
	s.log().Info("admin: radius credentials deleted", zap.String("target", username))
	c.Redirect(http.StatusFound, adminRadiusRedirect(username+" removed", ""))
}

// AdminRegenerate serves POST /admin/radius/regenerate — reissues credentials for any user.
func (s *Server) AdminRegenerate(c *gin.Context) {
	username := c.PostForm("username")
	if username == "" {
		s.fail(c, http.StatusBadRequest, "username required", nil)
		return
	}
	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	existing := store.FindByUsername(username)
	s.revokeExistingCert(existing, s.Cfg.RadSecCAName, freeipa.RevocationReasonSuperseded)
	entry, _, _, err := s.issueClientCredentials(username, username)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "admin: credential regeneration failed", err)
		return
	}
	if existing != nil {
		entry.IPCIDR = existing.IPCIDR
	}
	store.Upsert(*entry)
	if err := s.commitStore(c, store); err != nil {
		return
	}
	s.log().Info("admin: radius credentials regenerated", zap.String("target", username), zap.String("serial", entry.CertSerial))
	c.Redirect(http.StatusFound, adminRadiusRedirect("Credentials regenerated for "+username, ""))
}

// AdminRootProvision serves POST /admin/radius/root/provision.
func (s *Server) AdminRootProvision(c *gin.Context) {
	nav, _ := getNavInfo(c)
	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	if store.FindByUsername(rootUsername) != nil {
		c.Redirect(http.StatusFound, "/admin/radius?warn="+url.QueryEscape("Root client already provisioned — use Regenerate to reissue credentials"))
		return
	}
	entry, keyPEM, certPEM, err := s.issueClientCredentials(rootUsername, s.Cfg.IPAPrincipal)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "admin: root client provisioning failed", err)
		return
	}
	store.Upsert(*entry)
	if err := s.commitStore(c, store); err != nil {
		return
	}
	s.log().Info("admin: root radius client provisioned", zap.String("serial", entry.CertSerial))
	s.renderRootCredsPage(c, nav, store, entry, keyPEM, certPEM,
		"Organization controller provisioned — save credentials now, they will not be shown again")
}

// AdminRootRegenerate serves POST /admin/radius/root/regenerate.
func (s *Server) AdminRootRegenerate(c *gin.Context) {
	nav, _ := getNavInfo(c)
	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	existing := store.FindByUsername(rootUsername)
	s.revokeExistingCert(existing, s.Cfg.RadSecCAName, freeipa.RevocationReasonSuperseded)
	entry, keyPEM, certPEM, err := s.issueClientCredentials(rootUsername, s.Cfg.IPAPrincipal)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "admin: root credential regeneration failed", err)
		return
	}
	if existing != nil {
		entry.IPCIDR = existing.IPCIDR
	}
	store.Upsert(*entry)
	if err := s.commitStore(c, store); err != nil {
		return
	}
	s.log().Info("admin: root radius credentials regenerated", zap.String("serial", entry.CertSerial))
	s.renderRootCredsPage(c, nav, store, entry, keyPEM, certPEM,
		"Organization controller credentials regenerated — save the new key and cert now")
}

// AdminRootUpdateIP serves POST /admin/radius/root/update-ip.
func (s *Server) AdminRootUpdateIP(c *gin.Context) {
	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
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
	if err := s.commitStore(c, store); err != nil {
		return
	}
	s.log().Info("admin: root radius source IP updated", zap.String("ip_cidr", ipCIDR))
	c.Redirect(http.StatusFound, adminRadiusRedirect("Source IP updated for organization controller", ""))
}

func (s *Server) renderRootCredsPage(c *gin.Context, nav navInfo, store *radius.ClientStore, entry *radius.RadiusClient, keyPEM, certPEM, successMsg string) {
	data := nav.toMap()
	data["CSRFToken"] = c.GetString(csrfContextKey)
	data["CACertPEM"] = s.CA.RadSecCAChainPEM
	data["RootClient"] = entry
	data["RootKeyPEM"] = keyPEM
	data["RootCertPEM"] = certPEM
	data["Clients"] = memberClients(store.All())
	data["FlashSuccess"] = successMsg
	c.HTML(http.StatusOK, "admin_radius.html", data)
}

func adminRadiusRedirect(success, warn string) string {
	dest := "/admin/radius?success=" + url.QueryEscape(success)
	if warn != "" {
		dest += "&warn=" + url.QueryEscape(warn)
	}
	return dest
}

func memberClients(all []radius.RadiusClient) []radius.RadiusClient {
	out := make([]radius.RadiusClient, 0, len(all))
	for _, c := range all {
		if c.Username != rootUsername {
			out = append(out, c)
		}
	}
	return out
}
