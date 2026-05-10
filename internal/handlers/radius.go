// internal/handlers/radius.go
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-gonic/gin"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// RadiusPageHandler serves GET /radius.
func RadiusPageHandler(cfg *config.Config, k8s kubernetes.Interface) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, _ := getUsername(c)
		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		client := store.FindByUsername(username)

		var ipcidr string
		var hasIPCIDR bool
		if client != nil && client.IPCIDR != nil {
			ipcidr = *client.IPCIDR
			hasIPCIDR = true
		}

		c.HTML(http.StatusOK, "radius.html", gin.H{
			"Username":     username,
			"RadiusServer": cfg.RadiusServer,
			"Client":       client,
			"IPCIDR":       ipcidr,
			"HasIPCIDR":    hasIPCIDR,
		})
	}
}

// SaveSecretHandler serves POST /radius/secret.
func SaveSecretHandler(cfg *config.Config, k8s kubernetes.Interface, restCfg *rest.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, ok := getUsername(c)
		if !ok {
			c.Redirect(http.StatusFound, "/auth/login")
			return
		}

		ipCIDR := c.PostForm("ip_cidr")

		secret, err := generateSecret()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate secret"})
			return
		}

		store := radius.NewClientStore(k8s, cfg.Namespace, cfg.RadiusClientsSecret)
		if err := store.Load(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		entry := radius.RadiusClient{Username: username, Secret: secret}
		if ipCIDR != "" {
			entry.IPCIDR = &ipCIDR
		}
		store.Upsert(entry)

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

// DeleteSecretHandler serves POST /radius/delete.
func DeleteSecretHandler(cfg *config.Config, k8s kubernetes.Interface, restCfg *rest.Config) gin.HandlerFunc {
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

// RouterClientCertHandler serves GET /radius/client-cert.
// Generates a fresh RSA keypair, requests a RadSec client cert from FreeIPA for the user,
// and streams it as a PKCS#12 file.
func RouterClientCertHandler(ipaClient *freeipa.Client, cfg *config.Config, radSecCACertDER []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, ok := getUsername(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}

		privKey, csrPEM, err := profile.GenerateKeyAndCSR(username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "key generation failed"})
			return
		}

		certDER, err := ipaClient.CertRequest(username, cfg.IPARealm, string(csrPEM), "pint_radsec", cfg.RadSecCAName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "cert request failed"})
			return
		}

		p12, err := profile.BuildPKCS12(privKey, certDER, radSecCACertDER)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "PKCS12 build failed"})
			return
		}

		c.Header("Content-Disposition", `attachment; filename="csh-router.p12"`)
		c.Data(http.StatusOK, "application/x-pkcs12", p12)
	}
}

// RadSecCAHandler serves GET /radius/ca.
// Streams the RadSec CA certificate DER as a .cer file.
func RadSecCAHandler(radSecCACertDER []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Disposition", `attachment; filename="csh-radsec-ca.cer"`)
		c.Data(http.StatusOK, "application/x-x509-ca-cert", radSecCACertDER)
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
