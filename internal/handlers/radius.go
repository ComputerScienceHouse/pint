// internal/handlers/radius.go
package handlers

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageClientAuth:      "TLS Web Client Authentication",
	x509.ExtKeyUsageServerAuth:      "TLS Web Server Authentication",
	x509.ExtKeyUsageEmailProtection: "Email Protection",
}

// RadiusPage serves GET /radius.
func (s *Server) RadiusPage(c *gin.Context) {
	nav, _ := getNavInfo(c)
	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	c.HTML(http.StatusOK, "radius.html", s.radiusPageData(c, nav, store.FindByUsername(nav.Username), "", ""))
}

// SaveSecret serves POST /radius/secret (initial enrollment).
// Renders the page directly with the one-time key and cert PEM.
func (s *Server) SaveSecret(c *gin.Context) {
	nav, _ := getNavInfo(c)

	if nav.Username == rootUsername {
		s.fail(c, http.StatusForbidden, "reserved username", nil)
		return
	}

	ipCIDR, ok := parseMemberIP(c)
	if !ok {
		return
	}
	entry, keyPEM, certPEM, err := s.issueClientCredentials(nav.Username, nav.Username)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "radius enrollment failed", err)
		return
	}
	s.log().Info("radius credentials issued", zap.String("serial", entry.CertSerial))
	if ipCIDR != "" {
		entry.IPCIDR = &ipCIDR
	}

	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	store.Upsert(*entry)

	if err := s.commitStore(c, store); err != nil {
		return
	}

	c.HTML(http.StatusOK, "radius.html", s.radiusPageData(c, nav, entry, keyPEM, certPEM))
}

// Regenerate serves POST /radius/regenerate.
// Revokes the existing cert, issues new credentials, and renders once with the new key/cert PEM.
func (s *Server) Regenerate(c *gin.Context) {
	nav, _ := getNavInfo(c)

	if nav.Username == rootUsername {
		s.fail(c, http.StatusForbidden, "reserved username", nil)
		return
	}

	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	existing := store.FindByUsername(nav.Username)
	s.revokeExistingCert(existing, s.Cfg.RadSecCAName, freeipa.RevocationReasonSuperseded)

	entry, keyPEM, certPEM, err := s.issueClientCredentials(nav.Username, nav.Username)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "radius credential regeneration failed", err)
		return
	}
	s.log().Info("radius credentials regenerated", zap.String("serial", entry.CertSerial))
	if existing != nil {
		entry.IPCIDR = existing.IPCIDR
	}
	store.Upsert(*entry)

	if err := s.commitStore(c, store); err != nil {
		return
	}

	c.HTML(http.StatusOK, "radius.html", s.radiusPageData(c, nav, entry, keyPEM, certPEM))
}

// UpdateIP serves POST /radius/update-ip, changes source IP only.
func (s *Server) UpdateIP(c *gin.Context) {
	username, _ := getUsername(c)

	store := radius.NewClientStore(s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret)
	if err := store.Load(c.Request.Context()); err != nil {
		s.fail(c, http.StatusInternalServerError, "failed to load RADIUS config", err)
		return
	}
	existing := store.FindByUsername(username)
	if existing == nil {
		c.Redirect(http.StatusFound, "/radius")
		return
	}

	ipCIDR, ok := parseMemberIP(c)
	if !ok {
		return
	}
	updated := *existing
	updated.IPCIDR = &ipCIDR
	store.Upsert(updated)

	if err := s.commitStore(c, store); err != nil {
		return
	}

	s.log().Info("radius source IP updated", zap.String("ip_cidr", ipCIDR))
	c.Redirect(http.StatusFound, "/radius")
}

// DeleteSecret serves POST /radius/delete, revokes cert and removes config.
func (s *Server) DeleteSecret(c *gin.Context) {
	username, _ := getUsername(c)

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

	s.log().Info("radius credentials deleted")
	c.Redirect(http.StatusFound, "/radius")
}

// RadSecCA serves GET /radius/ca, streams the full RadSec CA chain as PEM.
func (s *Server) RadSecCA(c *gin.Context) {
	c.Header("Content-Disposition", `attachment; filename="csh-radsec-ca-chain.pem"`)
	c.Data(http.StatusOK, "application/x-pem-file", []byte(s.CA.RadSecCAChainPEM))
}

// radiusPageData builds the template context for the radius page.
// keyPEM and certPEM are non-empty only immediately after credential generation.
func (s *Server) radiusPageData(c *gin.Context, nav navInfo, client *radius.RadiusClient, keyPEM, certPEM string) gin.H {
	data := nav.toMap()
	data["CSRFToken"] = c.GetString(csrfContextKey)
	host, port, _ := net.SplitHostPort(s.Cfg.RadiusServer)
	if host == "" {
		host = s.Cfg.RadiusServer
	}
	data["RadiusServer"] = host
	data["RadiusPort"] = port
	data["Client"] = client
	data["CACertPEM"] = s.CA.RadSecCAChainPEM
	data["KeyPEM"] = keyPEM
	data["CertPEM"] = certPEM
	if client != nil && client.IPCIDR != nil {
		data["IPCIDR"] = *client.IPCIDR
	}
	return data
}

// On any error it writes a JSON error response and returns non-nil so callers can return immediately.
func (s *Server) commitStore(c *gin.Context, store *radius.ClientStore) error {
	ctx := c.Request.Context()
	if err := store.Save(ctx); err != nil {
		s.fail(c, http.StatusInternalServerError, "radius store save failed", err)
		return err
	}
	if err := radius.WriteRadiusConfig(ctx, s.K8s, s.Cfg.Namespace, s.Cfg.ConfigSecret, s.Cfg.FreeRADIUSDeployment, store.All(), s.Cfg.RadSecProxyHosts); err != nil {
		s.fail(c, http.StatusInternalServerError, "radius config write failed", err)
		return err
	}
	s.log().Debug("freeradius reloaded")
	return nil
}

// issueClientCredentials generates an EC key and RadSec client cert.
// username is the store key; principal is the FreeIPA principal and CSR CN.
func (s *Server) issueClientCredentials(username, principal string) (*radius.RadiusClient, string, string, error) {
	privKey, csrPEM, err := profile.GenerateKeyAndCSR(principal)
	if err != nil {
		return nil, "", "", err
	}

	certDER, err := s.IPA.CertRequest(principal, string(csrPEM), s.Cfg.RadSecCAName, s.Cfg.RadSecClientCertProfile)
	if err != nil {
		return nil, "", "", err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, "", "", err
	}

	var ekus []string
	for _, eku := range cert.ExtKeyUsage {
		if name, ok := ekuNames[eku]; ok {
			ekus = append(ekus, name)
		}
	}

	keyBits := 0
	if ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		keyBits = ecKey.Curve.Params().BitSize
	}

	entry := &radius.RadiusClient{
		Username:      username,
		CertSerial:    cert.SerialNumber.String(),
		CertSubject:   cert.Subject.CommonName,
		CertIssuer:    cert.Issuer.CommonName,
		CertNotBefore: cert.NotBefore.UTC().Format(time.RFC1123),
		CertNotAfter:  cert.NotAfter.UTC().Format(time.RFC1123),
		CertKeyBits:   keyBits,
		CertEKUs:      ekus,
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := profile.MarshalECKeyPEM(privKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal ec key: %w", err)
	}

	return entry, string(keyPEM), string(certPEM), nil
}

// revokeExistingCert revokes the cert identified by client.CertSerial.
// Errors are logged but not returned; revocation failure should not block deletion.
func (s *Server) revokeExistingCert(client *radius.RadiusClient, caName string, reason int) {
	if client == nil || client.CertSerial == "" {
		return
	}
	serial, err := strconv.ParseInt(client.CertSerial, 10, 64)
	if err != nil {
		s.log().Warn("revokeExistingCert: invalid serial", zap.String("serial", client.CertSerial), zap.Error(err))
		return
	}
	if err := s.IPA.CertRevoke(serial, caName, reason); err != nil {
		s.log().Warn("cert revocation failed, continuing", zap.Int64("serial", serial), zap.Error(err))
		return
	}
	s.log().Info("cert revoked", zap.Int64("serial", serial), zap.Int("reason", reason))
}

// parseMemberIP reads ip_cidr from POST form and requires a single bare IP address.
func parseMemberIP(c *gin.Context) (string, bool) {
	raw := c.PostForm("ip_cidr")
	if raw == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a source IP address is required"})
		return "", false
	}
	if _, err := netip.ParseAddr(raw); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source IP must be a single IP address (not a CIDR range)"})
		return "", false
	}
	return raw, true
}

// parseIPCIDR reads ip_cidr from the POST form, validates it, and returns it.
// An empty value is allowed (means "any IP"). Accepts a bare IP or CIDR prefix.
func parseIPCIDR(c *gin.Context) (string, bool) {
	raw := c.PostForm("ip_cidr")
	if raw == "" {
		return "", true
	}
	_, prefixErr := netip.ParsePrefix(raw)
	_, addrErr := netip.ParseAddr(raw)
	if prefixErr != nil && addrErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip_cidr must be a valid IP address or CIDR prefix"})
		return "", false
	}
	return raw, true
}
