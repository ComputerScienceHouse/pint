// internal/handlers/radius.go
package handlers

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
	"k8s.io/client-go/kubernetes"
)

var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageClientAuth:      "TLS Web Client Authentication",
	x509.ExtKeyUsageServerAuth:      "TLS Web Server Authentication",
	x509.ExtKeyUsageEmailProtection: "Email Protection",
}

// RadiusPageHandler serves GET /radius.
func RadiusPageHandler(cfg *config.Config, k8s kubernetes.Interface, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.ConfigSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.HTML(http.StatusOK, "radius.html", radiusPageData(c, nav, cfg.RadiusServer, store.FindByUsername(nav.Username), caChainPEM, "", ""))
	}
}

// SaveSecretHandler serves POST /radius/secret (initial enrollment).
// Renders the page directly with the one-time key and cert PEM.
func SaveSecretHandler(ipaClient *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)

		ipCIDR, ok := parseMemberIP(c)
		if !ok {
			return
		}
		entry, keyPEM, certPEM, err := issueClientCredentials(ipaClient, cfg, nav.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if ipCIDR != "" {
			entry.IPCIDR = &ipCIDR
		}

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.ConfigSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		store.Upsert(*entry)

		if _, err := commitStore(c, store, k8s, cfg); err != nil {
			return
		}

		c.HTML(http.StatusOK, "radius.html", radiusPageData(c, nav, cfg.RadiusServer, entry, caChainPEM, keyPEM, certPEM))
	}
}

// RegenerateHandler serves POST /radius/regenerate.
// Revokes the existing cert, issues new credentials, and renders once with the new key/cert PEM.
func RegenerateHandler(ipaClient *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.ConfigSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		existing := store.FindByUsername(nav.Username)
		revokeExistingCert(ipaClient, existing, cfg.RadSecCAName, freeipa.RevocationReasonSuperseded)

		entry, keyPEM, certPEM, err := issueClientCredentials(ipaClient, cfg, nav.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if existing != nil {
			entry.IPCIDR = existing.IPCIDR
		}
		store.Upsert(*entry)

		if _, err := commitStore(c, store, k8s, cfg); err != nil {
			return
		}

		c.HTML(http.StatusOK, "radius.html", radiusPageData(c, nav, cfg.RadiusServer, entry, caChainPEM, keyPEM, certPEM))
	}
}

// UpdateIPHandler serves POST /radius/update-ip, changes source IP only.
func UpdateIPHandler(cfg *config.Config, k8s kubernetes.Interface) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, _ := getUsername(c)

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.ConfigSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

		if _, err := commitStore(c, store, k8s, cfg); err != nil {
			return
		}

		c.Redirect(http.StatusFound, "/radius")
	}
}

// DeleteSecretHandler serves POST /radius/delete, revokes cert and removes config.
func DeleteSecretHandler(cfg *config.Config, k8s kubernetes.Interface, ipaClient *freeipa.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, _ := getUsername(c)

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.ConfigSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		revokeExistingCert(ipaClient, store.FindByUsername(username), cfg.RadSecCAName, freeipa.RevocationReasonCessationOfOperation)
		store.Delete(username)

		if _, err := commitStore(c, store, k8s, cfg); err != nil {
			return
		}

		c.Redirect(http.StatusFound, "/radius")
	}
}

// RadSecCAHandler serves GET /radius/ca, streams the full RadSec CA chain as PEM.
func RadSecCAHandler(caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Disposition", `attachment; filename="csh-radsec-ca-chain.pem"`)
		c.Data(http.StatusOK, "application/x-pem-file", []byte(caChainPEM))
	}
}

// radiusPageData builds the template context for the radius page.
// keyPEM and certPEM are non-empty only immediately after credential generation.
func radiusPageData(c *gin.Context, nav navInfo, radiusServer string, client *radius.RadiusClient, caPEM, keyPEM, certPEM string) gin.H {
	data := nav.toMap()
	data["CSRFToken"] = c.GetString(csrfContextKey)
	data["RadiusServer"] = radiusServer
	data["Client"] = client
	data["CACertPEM"] = caPEM
	data["KeyPEM"] = keyPEM
	data["CertPEM"] = certPEM
	if client != nil && client.IPCIDR != nil {
		data["IPCIDR"] = *client.IPCIDR
	}
	return data
}

// commitStore saves the store, writes the RADIUS config, and reloads FreeRADIUS.
// Returns (reloadWarning, fatalErr). reloadWarning is non-empty when reload fails but
// the store was saved successfully; fatalErr aborts the response and should cause the
// caller to return immediately.
// Member-facing callers discard the reload warning intentionally — only admin handlers surface it.
func commitStore(c *gin.Context, store *radius.ClientStore, k8s kubernetes.Interface, cfg *config.Config) (string, error) {
	ctx := c.Request.Context()
	if err := store.Save(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return "", err
	}
	if err := radius.WriteRadiusConfig(ctx, k8s, cfg.Namespace, cfg.ConfigSecret, store.All()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return "", err
	}
	if err := radius.Reload(ctx, k8s, cfg.Namespace, cfg.FreeRADIUSDeployment); err != nil {
		return err.Error(), nil
	}
	return "", nil
}

// issueClientCredentials generates an EC key and RadSec client cert for username.
// Returns the RadiusClient to store (no PEM fields), plus the one-time keyPEM and certPEM.
// The RADIUS shared secret is always "radsec" and is not stored on the client.
func issueClientCredentials(ipaClient *freeipa.Client, cfg *config.Config, username string) (*radius.RadiusClient, string, string, error) {
	privKey, csrPEM, err := profile.GenerateKeyAndCSR(username)
	if err != nil {
		return nil, "", "", err
	}

	certDER, err := ipaClient.CertRequest(username, string(csrPEM), cfg.RadSecCAName, cfg.RadSecClientCertProfile)
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
	ecKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal ec key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKeyBytes})

	return entry, string(keyPEM), string(certPEM), nil
}

// revokeExistingCert revokes the cert identified by client.CertSerial.
// Errors are logged but not returned; revocation failure should not block deletion or reissuance.
func revokeExistingCert(ipaClient *freeipa.Client, client *radius.RadiusClient, caName string, reason int) {
	if client == nil || client.CertSerial == "" {
		return
	}
	serial, err := strconv.ParseInt(client.CertSerial, 10, 64)
	if err != nil {
		log.Printf("revokeExistingCert: invalid serial %q: %v", client.CertSerial, err)
		return
	}
	if err := ipaClient.CertRevoke(serial, caName, reason); err != nil {
		log.Printf("revokeExistingCert: cert_revoke serial=%d: %v (continuing)", serial, err)
	}
}

// parseMemberIP reads ip_cidr from POST form and requires a single bare IP address.
// CIDR ranges are rejected — member clients must restrict to one specific IP.
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
	if _, err := netip.ParsePrefix(raw); err != nil {
		if _, err2 := netip.ParseAddr(raw); err2 != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ip_cidr must be a valid IP address or CIDR prefix"})
			return "", false
		}
	}
	return raw, true
}
