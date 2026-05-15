// cmd/pint/main.go
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/handlers"
	"github.com/ComputerScienceHouse/pint/internal/logger"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
	"software.sslmate.com/src/go-pkcs12"
)

const radSecRenewBefore = 30 * 24 * time.Hour

func main() {
	log, err := logger.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger init: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("config load failed", zap.Error(err))
	}

	// FreeIPA client: authenticate at startup
	ipaClient := freeipa.New(cfg.IPAHost, cfg.IPAPrincipal, cfg.IPAPassword, cfg.IPASkipTLSVerify)
	if err := ipaClient.Login(); err != nil {
		log.Fatal("freeipa login failed", zap.Error(err))
	}
	log.Info("freeipa authenticated", zap.String("host", cfg.IPAHost), zap.String("principal", cfg.IPAPrincipal))

	// Kubernetes client: try in-cluster first, fall back to kubeconfig
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		restCfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			log.Fatal("kubernetes config failed", zap.Error(err))
		}
		log.Info("kubernetes: using kubeconfig (local dev mode)")
	}
	k8sClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Fatal("kubernetes client init failed", zap.Error(err))
	}

	// Metrics client is optional; absent if metrics-server is not installed.
	metricsClient, err := metricsv.NewForConfig(restCfg)
	if err != nil {
		log.Warn("metrics client unavailable, continuing without pod metrics", zap.Error(err))
		metricsClient = nil
	}

	// Initialize RADIUS secrets with empty content if they don't exist yet.
	if err := radius.EnsureConfigSecret(context.Background(), k8sClient, cfg.Namespace, cfg.ConfigSecret); err != nil {
		log.Fatal("init radius secrets failed", zap.Error(err))
	}

	// Ensure FreeRADIUS status server is configured.
	statusSecret, err := radius.EnsureStatusConfig(context.Background(), k8sClient, cfg.Namespace, cfg.ConfigSecret)
	if err != nil {
		log.Fatal("ensure status secret failed", zap.Error(err))
	}
	statusConf := radius.RenderStatusConfig(statusSecret, "0.0.0.0/0")
	updated, err := radius.WriteStatusConfig(context.Background(), k8sClient, cfg.Namespace, cfg.ConfigSecret, statusConf)
	if err != nil {
		log.Fatal("write status config failed", zap.Error(err))
	}
	if updated {
		log.Info("updated FreeRADIUS status config, triggering rollout restart")
		if err := radius.Reload(context.Background(), k8sClient, cfg.Namespace, cfg.FreeRADIUSDeployment); err != nil {
			log.Warn("status config reload failed", zap.Error(err))
		}
	}

	tlsUpdated, err := radius.WriteRadSecTLS(context.Background(), k8sClient, cfg.Namespace, cfg.ConfigSecret, cfg.RadSecCheckCRL)
	if err != nil {
		log.Fatal("write radsec-tls.conf failed", zap.Error(err))
	}
	if tlsUpdated {
		log.Info("updated radsec-tls.conf, triggering rollout restart", zap.Bool("check_crl", cfg.RadSecCheckCRL))
		if err := radius.Reload(context.Background(), k8sClient, cfg.Namespace, cfg.FreeRADIUSDeployment); err != nil {
			log.Warn("radsec tls config reload failed", zap.Error(err))
		}
	}

	// Fetch all three CA certs in parallel.
	var (
		caDER           []byte
		radSecCACertDER []byte
		rootCACertDER   []byte
		certErr         [3]error
	)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); caDER, certErr[0] = ipaClient.CAShow(cfg.IPAWirelessCAName) }()
	go func() { defer wg.Done(); radSecCACertDER, certErr[1] = ipaClient.CAShow(cfg.RadSecCAName) }()
	go func() { defer wg.Done(); rootCACertDER, certErr[2] = ipaClient.CAShow(cfg.RootCAName) }()
	wg.Wait()
	for i, e := range certErr {
		if e != nil {
			log.Fatal("freeipa ca_show failed", zap.Int("index", i), zap.Error(e))
		}
	}

	logCACert := func(name string, der []byte) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			log.Warn("CA cert parse failed", zap.String("ca", name), zap.Int("bytes", len(der)), zap.Error(err))
			return
		}
		remaining := time.Until(cert.NotAfter).Truncate(time.Hour)
		log.Info("CA cert loaded",
			zap.String("ca", name),
			zap.String("valid_until", cert.NotAfter.Format("2006-01-02")),
			zap.String("remaining", formatDuration(remaining)),
		)
	}
	logCACert("WiFi CA", caDER)
	logCACert("RadSec CA", radSecCACertDER)
	logCACert("Root CA", rootCACertDER)

	radSecCAChainPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: radSecCACertDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCACertDER}))
	wifiCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Load or renew FreeRADIUS server TLS cert
	if _, _, _, err := loadOrRenewRadSecServerCert(context.Background(), log, k8sClient, ipaClient, cfg, []byte(radSecCAChainPEM), wifiCAPEM); err != nil {
		log.Fatal("radsec server cert failed", zap.Error(err))
	}

	// Background watcher: renew cert before expiry and reload FreeRADIUS
	go watchRadSecServerCert(log, k8sClient, ipaClient, cfg, []byte(radSecCAChainPEM), wifiCAPEM)

	// Load Apple profile signing identity if configured.
	var appleSigner *profile.Signer
	if cfg.AppleSigningCertPath != "" {
		p12Data, readErr := os.ReadFile(cfg.AppleSigningCertPath)
		if readErr != nil {
			log.Fatal("apple signing cert read failed", zap.String("path", cfg.AppleSigningCertPath), zap.Error(readErr))
		}
		privKey, cert, _, p12Err := pkcs12.DecodeChain(p12Data, cfg.AppleSigningCertPassword)
		if p12Err != nil {
			log.Fatal("apple signing cert decode failed", zap.Error(p12Err))
		}
		signer, ok := privKey.(crypto.Signer)
		if !ok {
			log.Fatal("apple signing cert: private key does not implement crypto.Signer")
		}
		appleSigner = &profile.Signer{Cert: cert, Key: signer}
		log.Info("apple profile signing enabled", zap.String("subject", cert.Subject.CommonName))
	}

	if cfg.DisableOIDC {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(handlers.ZapLogger(log), gin.Recovery())
	r.HTMLRender = buildTemplates()

	var authMiddleware gin.HandlerFunc
	if cfg.DisableOIDC {
		log.Warn("OIDC disabled — injecting static dev user")
		authMiddleware = handlers.DevAuthMiddleware()
		r.GET("/auth/login", func(c *gin.Context) { c.Redirect(http.StatusFound, "/dashboard") })
		r.GET("/auth/callback", func(c *gin.Context) { c.Redirect(http.StatusFound, "/dashboard") })
		r.GET("/auth/logout", func(c *gin.Context) { c.Redirect(http.StatusFound, "/") })
	} else {
		auth, err := cshauth.Init(
			cfg.ClientID,
			cfg.ClientSecret,
			cfg.ServerURL,
			cfg.LoginURL,
			cfg.CallbackURL,
			[]string{"openid", "profile", "groups"},
		)
		if err != nil {
			log.Fatal("csh-auth init failed", zap.Error(err))
		}
		authMiddleware = auth.CookieMiddleware()
		r.GET("/auth/login", auth.HandleLogin)
		r.GET("/auth/callback", auth.HandleCallback)
		r.GET("/auth/logout", auth.HandleLogout)
	}

	// Public routes
	r.GET("/", handlers.IndexHandler(cfg.LoginURL))

	// Protected routes
	protected := r.Group("/")
	protected.Use(authMiddleware)
	protected.Use(handlers.RequireAuth(cfg.LoginURL))
	protected.Use(handlers.CSRFMiddleware())
	{
		protected.GET("/dashboard", handlers.DashboardHandler())
		protected.GET("/profile", handlers.ProfilePageHandler(cfg))
		protected.POST("/profile/generate", handlers.GenerateProfileHandler(log, ipaClient, cfg, caDER, appleSigner))
		protected.GET("/profile/ca", handlers.CAHandler(caDER))
		protected.GET("/radius", handlers.RadiusPageHandler(cfg, k8sClient, radSecCAChainPEM))
		protected.POST("/radius/secret", handlers.SaveSecretHandler(log, ipaClient, cfg, k8sClient, radSecCAChainPEM))
		protected.POST("/radius/regenerate", handlers.RegenerateHandler(log, ipaClient, cfg, k8sClient, radSecCAChainPEM))
		protected.POST("/radius/update-ip", handlers.UpdateIPHandler(log, cfg, k8sClient))
		protected.POST("/radius/delete", handlers.DeleteSecretHandler(log, cfg, k8sClient, ipaClient))
		protected.GET("/radius/ca", handlers.RadSecCAHandler(radSecCAChainPEM))

		protected.GET("/status", handlers.StatusPageHandler(cfg, k8sClient, metricsClient))
		protected.POST("/status/reload", handlers.ReloadHandler(log, cfg, k8sClient))

		admin := protected.Group("/admin")
		admin.Use(handlers.RequireRTP)
		{
			admin.GET("/radius", handlers.AdminRadiusPageHandler(cfg, k8sClient, radSecCAChainPEM))
			admin.POST("/radius/delete", handlers.AdminDeleteHandler(log, cfg, k8sClient, ipaClient))
			admin.POST("/radius/regenerate", handlers.AdminRegenerateHandler(log, ipaClient, cfg, k8sClient))
			admin.POST("/radius/root/provision", handlers.AdminRootProvisionHandler(log, ipaClient, cfg, k8sClient, radSecCAChainPEM))
			admin.POST("/radius/root/regenerate", handlers.AdminRootRegenerateHandler(log, ipaClient, cfg, k8sClient, radSecCAChainPEM))
			admin.POST("/radius/root/update-ip", handlers.AdminRootUpdateIPHandler(log, cfg, k8sClient))
		}
	}

	log.Info("starting PINT", zap.String("addr", ":8080"))
	if err := r.Run(":8080"); err != nil {
		log.Fatal("server exited", zap.Error(err))
	}
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		return "EXPIRED"
	}
	days := int(d.Hours()) / 24
	if days >= 365 {
		return fmt.Sprintf("%dy %dd", days/365, days%365)
	}
	return fmt.Sprintf("%dd", days)
}

func buildTemplates() multitemplate.Render {
	r := multitemplate.New()
	layout := "templates/layout.html"
	for _, page := range []string{"index", "dashboard", "profile", "radius", "status", "admin_radius"} {
		r.AddFromFiles(page+".html", layout, "templates/"+page+".html")
	}
	return r
}

// loadOrRenewRadSecServerCert reads the existing FreeRADIUS TLS cert from the K8s Secret.
// If it exists and has more than radSecRenewBefore of validity remaining, it is used as-is
// and renewed is false. Otherwise a new cert is issued and renewed is true.
func loadOrRenewRadSecServerCert(ctx context.Context, log *zap.Logger, k8sClient kubernetes.Interface, ipaClient *freeipa.Client, cfg *config.Config, caPEM, wifiCAPEM []byte) (certPEM, keyPEM []byte, renewed bool, err error) {
	secret, err := k8sClient.CoreV1().Secrets(cfg.Namespace).Get(ctx, cfg.RadSecCertSecret, metav1.GetOptions{})
	if err == nil {
		existing := secret.Data["tls.crt"]
		key := secret.Data["tls.key"]
		if len(existing) > 0 && len(key) > 0 {
			block, _ := pem.Decode(existing)
			if block != nil {
				cert, parseErr := x509.ParseCertificate(block.Bytes)
				if parseErr == nil && time.Until(cert.NotAfter) > radSecRenewBefore {
					log.Info("reusing existing RadSec server cert", zap.String("expires", cert.NotAfter.Format(time.RFC3339)))
					return existing, key, false, nil
				}
			}
		}
	}

	// Generate new cert via FreeIPA
	privKey, csrPEM, genErr := profile.GenerateKeyAndCSR(cfg.IPAServiceHostname)
	if genErr != nil {
		return nil, nil, false, fmt.Errorf("generate radsec key/csr: %w", genErr)
	}

	certDER, certErr := ipaClient.CertRequest(cfg.IPAPrincipal, string(csrPEM), cfg.RadSecCAName, cfg.RadSecServerCertProfile)
	if certErr != nil {
		return nil, nil, false, fmt.Errorf("cert_request radsec: %w", certErr)
	}

	newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	ecKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, false, fmt.Errorf("marshal radsec ec key: %w", err)
	}
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKeyBytes})

	if writeErr := radius.WriteRadSecServerCert(ctx, k8sClient, cfg.Namespace, cfg.RadSecCertSecret, newCertPEM, newKeyPEM, caPEM, wifiCAPEM); writeErr != nil {
		return nil, nil, false, fmt.Errorf("write radsec cert: %w", writeErr)
	}
	log.Info("issued and stored new RadSec server cert")
	return newCertPEM, newKeyPEM, true, nil
}

// watchRadSecServerCert runs forever, checking every 24 hours whether the RadSec server
// cert needs renewal. On renewal it reloads FreeRADIUS so the new cert is picked up
// without a full restart.
func watchRadSecServerCert(log *zap.Logger, k8sClient kubernetes.Interface, ipaClient *freeipa.Client, cfg *config.Config, caPEM, wifiCAPEM []byte) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		ctx := context.Background()
		_, _, renewed, err := loadOrRenewRadSecServerCert(ctx, log, k8sClient, ipaClient, cfg, caPEM, wifiCAPEM)
		if err != nil {
			log.Error("radsec cert renewal failed", zap.Error(err))
			continue
		}
		if renewed {
			if err := radius.Reload(ctx, k8sClient, cfg.Namespace, cfg.FreeRADIUSDeployment); err != nil {
				log.Error("radsec cert watcher: freeradius reload failed", zap.Error(err))
			} else {
				log.Info("radsec cert watcher: renewed cert and reloaded freeradius")
			}
		}
	}
}
