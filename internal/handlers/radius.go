// internal/handlers/radius.go
package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageClientAuth: "TLS Web Client Authentication",
	x509.ExtKeyUsageServerAuth: "TLS Web Server Authentication",
	x509.ExtKeyUsageEmailProtection: "Email Protection",
}

// RadiusPageHandler serves GET /radius.
func RadiusPageHandler(cfg *config.Config, k8s kubernetes.Interface, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		client := store.FindByUsername(nav.Username)
		c.HTML(http.StatusOK, "radius.html", radiusPageData(nav, cfg.RadiusServer, client, caChainPEM, "", ""))
	}
}

// SaveSecretHandler serves POST /radius/secret — initial enrollment.
// Renders the page directly with the one-time key and cert PEM.
func SaveSecretHandler(ipaClient *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, restCfg *rest.Config, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, ok := getNavInfo(c)
		if !ok {
			c.Redirect(http.StatusFound, "/auth/login")
			return
		}

		ipCIDR := c.PostForm("ip_cidr")
		entry, keyPEM, certPEM, err := issueClientCredentials(ipaClient, cfg, nav.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if ipCIDR != "" {
			entry.IPCIDR = &ipCIDR
		}

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		store.Upsert(*entry)

		if err := store.Save(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := radius.WriteRadiusConfig(c.Request.Context(), k8s, cfg.Namespace, cfg.RadiusConfigSecret, store.All()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := radius.Reload(c.Request.Context(), k8s, restCfg, cfg.Namespace, cfg.FreeRADIUSPodSelector); err != nil {
			c.Header("X-Reload-Warning", err.Error())
		}

		c.HTML(http.StatusOK, "radius.html", radiusPageData(nav, cfg.RadiusServer, entry, caChainPEM, keyPEM, certPEM))
	}
}

// RegenerateHandler serves POST /radius/regenerate.
// Revokes the existing cert, issues new credentials, and renders once with the new key/cert PEM.
func RegenerateHandler(ipaClient *freeipa.Client, cfg *config.Config, k8s kubernetes.Interface, restCfg *rest.Config, caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, ok := getNavInfo(c)
		if !ok {
			c.Redirect(http.StatusFound, "/auth/login")
			return
		}

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		existing := store.FindByUsername(nav.Username)
		revokeExistingCert(ipaClient, existing, cfg.RadSecCAName, 4) // 4 = superseded

		entry, keyPEM, certPEM, err := issueClientCredentials(ipaClient, cfg, nav.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if existing != nil {
			entry.IPCIDR = existing.IPCIDR
		}
		store.Upsert(*entry)

		if err := store.Save(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := radius.WriteRadiusConfig(c.Request.Context(), k8s, cfg.Namespace, cfg.RadiusConfigSecret, store.All()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := radius.Reload(c.Request.Context(), k8s, restCfg, cfg.Namespace, cfg.FreeRADIUSPodSelector); err != nil {
			c.Header("X-Reload-Warning", err.Error())
		}

		c.HTML(http.StatusOK, "radius.html", radiusPageData(nav, cfg.RadiusServer, entry, caChainPEM, keyPEM, certPEM))
	}
}

// UpdateIPHandler serves POST /radius/update-ip — changes source IP/CIDR only.
func UpdateIPHandler(cfg *config.Config, k8s kubernetes.Interface, restCfg *rest.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, ok := getUsername(c)
		if !ok {
			c.Redirect(http.StatusFound, "/auth/login")
			return
		}

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		existing := store.FindByUsername(username)
		if existing == nil {
			c.Redirect(http.StatusFound, "/radius")
			return
		}

		ipCIDR := c.PostForm("ip_cidr")
		updated := *existing
		if ipCIDR != "" {
			updated.IPCIDR = &ipCIDR
		} else {
			updated.IPCIDR = nil
		}
		store.Upsert(updated)

		if err := store.Save(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := radius.WriteRadiusConfig(c.Request.Context(), k8s, cfg.Namespace, cfg.RadiusConfigSecret, store.All()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := radius.Reload(c.Request.Context(), k8s, restCfg, cfg.Namespace, cfg.FreeRADIUSPodSelector); err != nil {
			c.Header("X-Reload-Warning", err.Error())
		}

		c.Redirect(http.StatusFound, "/radius")
	}
}

// DeleteSecretHandler serves POST /radius/delete — revokes cert and removes config.
func DeleteSecretHandler(cfg *config.Config, k8s kubernetes.Interface, restCfg *rest.Config, ipaClient *freeipa.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, ok := getUsername(c)
		if !ok {
			c.Redirect(http.StatusFound, "/auth/login")
			return
		}

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		existing := store.FindByUsername(username)
		revokeExistingCert(ipaClient, existing, cfg.RadSecCAName, 5) // 5 = cessationOfOperation
		store.Delete(username)

		if err := store.Save(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := radius.WriteRadiusConfig(c.Request.Context(), k8s, cfg.Namespace, cfg.RadiusConfigSecret, store.All()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := radius.Reload(c.Request.Context(), k8s, restCfg, cfg.Namespace, cfg.FreeRADIUSPodSelector); err != nil {
			c.Header("X-Reload-Warning", err.Error())
		}

		c.Redirect(http.StatusFound, "/radius")
	}
}

// RadSecCAHandler serves GET /radius/ca — streams the full RadSec CA chain as PEM.
func RadSecCAHandler(caChainPEM string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Disposition", `attachment; filename="csh-radsec-ca-chain.pem"`)
		c.Data(http.StatusOK, "application/x-pem-file", []byte(caChainPEM))
	}
}

// radiusPageData builds the template context for the radius page.
// keyPEM and certPEM are non-empty only immediately after credential generation.
func radiusPageData(nav navInfo, radiusServer string, client *radius.RadiusClient, caPEM, keyPEM, certPEM string) gin.H {
	data := gin.H{
		"Username":     nav.Username,
		"FullName":     nav.FullName,
		"AvatarURL":    nav.AvatarURL,
		"RadiusServer": radiusServer,
		"Client":       client,
		"CACertPEM":    caPEM,
		"KeyPEM":       keyPEM,
		"CertPEM":      certPEM,
	}
	if client != nil && client.IPCIDR != nil {
		data["IPCIDR"] = *client.IPCIDR
	}
	return data
}

// issueClientCredentials generates a new shared secret, RSA key, and RadSec client cert.
// Returns the RadiusClient to store (no PEM fields), plus the one-time keyPEM and certPEM.
func issueClientCredentials(ipaClient *freeipa.Client, cfg *config.Config, username string) (*radius.RadiusClient, string, string, error) {
	secret, err := generateSecret()
	if err != nil {
		return nil, "", "", err
	}

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
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keyBits = rsaKey.N.BitLen()
	}

	entry := &radius.RadiusClient{
		Username:      username,
		Secret:        secret,
		CertSerial:    cert.SerialNumber.String(),
		CertSubject:   cert.Subject.CommonName,
		CertIssuer:    cert.Issuer.CommonName,
		CertNotBefore: cert.NotBefore.UTC().Format(time.RFC1123),
		CertNotAfter:  cert.NotAfter.UTC().Format(time.RFC1123),
		CertKeyBits:   keyBits,
		CertEKUs:      ekus,
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return entry, string(keyPEM), string(certPEM), nil
}

// revokeExistingCert revokes the cert identified by client.CertSerial.
// Errors are logged but not returned — revocation failure should not block deletion or reissuance.
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

// generateSecret returns a cryptographically random 32-hex-character secret.
func generateSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
