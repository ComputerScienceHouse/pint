// cmd/pint/main.go
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/handlers"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
)

const radSecRenewBefore = 30 * 24 * time.Hour

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// FreeIPA client: authenticate at startup
	ipaClient := freeipa.New(cfg.IPAHost, cfg.IPAPrincipal, cfg.IPAPassword, cfg.IPASkipTLSVerify)
	if err := ipaClient.Login(); err != nil {
		log.Fatalf("freeipa login: %v", err)
	}

	// Kubernetes client: try in-cluster first, fall back to kubeconfig
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		restCfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			log.Fatalf("kubernetes config: %v", err)
		}
		log.Println("using kubeconfig (local dev mode)")
	}
	k8sClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Fatalf("kubernetes client: %v", err)
	}

	// Metrics client is optional; absent if metrics-server is not installed.
	metricsClient, err := metricsv.NewForConfig(restCfg)
	if err != nil {
		log.Printf("metrics client unavailable (continuing without pod metrics): %v", err)
		metricsClient = nil
	}

	// Initialize RADIUS secrets with empty content if they don't exist yet.
	if err := radius.EnsureConfigSecrets(context.Background(), k8sClient, cfg.Namespace, cfg.RadiusClientsSecret, cfg.RadiusConfigSecret); err != nil {
		log.Fatalf("init radius secrets: %v", err)
	}

	// Ensure FreeRADIUS status server is configured.
	statusSecret, err := radius.EnsureStatusConfig(context.Background(), k8sClient, cfg.Namespace)
	if err != nil {
		log.Fatalf("ensure status secret: %v", err)
	}
	statusConf := radius.RenderStatusConfig("18121", statusSecret, "0.0.0.0/0")
	updated, err := radius.WriteStatusConfig(context.Background(), k8sClient, cfg.Namespace, "pint-freeradius-status-config", statusConf)
	if err != nil {
		log.Fatalf("write status config: %v", err)
	}
	if updated {
		log.Printf("updated FreeRADIUS status config, triggering rollout restart")
		if err := radius.Reload(context.Background(), k8sClient, cfg.Namespace, cfg.FreeRADIUSDeployment); err != nil {
			log.Printf("status config reload failed: %v", err)
		}
	}
	// Fetch all three CA certs and the RadSec server cert in parallel.
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
			log.Fatalf("freeipa ca_show[%d]: %v", i, e)
		}
	}
	log.Printf("fetched WiFi CA (%d bytes), RadSec CA (%d bytes), root CA (%d bytes)",
		len(caDER), len(radSecCACertDER), len(rootCACertDER))

	radSecCAChainPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: radSecCACertDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCACertDER}))
	wifiCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Load or renew FreeRADIUS server TLS cert
	if _, _, _, err := loadOrRenewRadSecServerCert(context.Background(), k8sClient, ipaClient, cfg, []byte(radSecCAChainPEM), wifiCAPEM); err != nil {
		log.Fatalf("radsec server cert: %v", err)
	}

	// Background watcher: renew cert before expiry and reload FreeRADIUS
	go watchRadSecServerCert(k8sClient, ipaClient, cfg, []byte(radSecCAChainPEM), wifiCAPEM)

	r := gin.Default()
	r.HTMLRender = buildTemplates()

	var authMiddleware gin.HandlerFunc
	if cfg.DisableOIDC {
		log.Printf("WARNING: OIDC disabled — injecting static dev user")
		authMiddleware = handlers.DevAuthMiddleware()
		r.GET("/auth/login", func(c *gin.Context) { c.Redirect(http.StatusFound, "/dashboard") })
		r.GET("/auth/callback", func(c *gin.Context) { c.Redirect(http.StatusFound, "/dashboard") })
		r.GET("/auth/logout", func(c *gin.Context) { c.Redirect(http.StatusFound, "/") })
	} else {
		// csh-auth v2: package-level Init returns (Auth, error)
		auth, err := cshauth.Init(
			cfg.ClientID,
			cfg.ClientSecret,
			cfg.ServerURL,
			cfg.LoginURL,
			cfg.CallbackURL,
			[]string{"openid", "profile", "groups"},
		)
		if err != nil {
			log.Fatalf("csh-auth init: %v", err)
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
		protected.POST("/profile/generate", handlers.GenerateProfileHandler(ipaClient, cfg, caDER))
		protected.GET("/profile/ca", handlers.CAHandler(caDER))
		protected.GET("/radius", handlers.RadiusPageHandler(cfg, k8sClient, radSecCAChainPEM))
		protected.POST("/radius/secret", handlers.SaveSecretHandler(ipaClient, cfg, k8sClient, radSecCAChainPEM))
		protected.POST("/radius/regenerate", handlers.RegenerateHandler(ipaClient, cfg, k8sClient, radSecCAChainPEM))
		protected.POST("/radius/update-ip", handlers.UpdateIPHandler(cfg, k8sClient))
		protected.POST("/radius/delete", handlers.DeleteSecretHandler(cfg, k8sClient, ipaClient))
		protected.GET("/radius/ca", handlers.RadSecCAHandler(radSecCAChainPEM))

		protected.GET("/status", handlers.StatusPageHandler(cfg, k8sClient, metricsClient))
		protected.POST("/status/reload", handlers.ReloadHandler(cfg, k8sClient))

		admin := protected.Group("/admin")
		admin.Use(handlers.RequireRTP)
		{
			admin.GET("/radius", handlers.AdminRadiusPageHandler(cfg, k8sClient, radSecCAChainPEM))
			admin.POST("/radius/delete", handlers.AdminDeleteHandler(cfg, k8sClient, ipaClient))
			admin.POST("/radius/regenerate", handlers.AdminRegenerateHandler(ipaClient, cfg, k8sClient))
			admin.POST("/radius/root/provision", handlers.AdminRootProvisionHandler(ipaClient, cfg, k8sClient, radSecCAChainPEM))
			admin.POST("/radius/root/regenerate", handlers.AdminRootRegenerateHandler(ipaClient, cfg, k8sClient, radSecCAChainPEM))
			admin.POST("/radius/root/update-ip", handlers.AdminRootUpdateIPHandler(cfg, k8sClient))
		}
	}

	log.Printf("starting PINT on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("server: %v", err)
	}
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
func loadOrRenewRadSecServerCert(ctx context.Context, k8sClient kubernetes.Interface, ipaClient *freeipa.Client, cfg *config.Config, caPEM, wifiCAPEM []byte) (certPEM, keyPEM []byte, renewed bool, err error) {
	secret, err := k8sClient.CoreV1().Secrets(cfg.Namespace).Get(ctx, cfg.RadSecCertSecret, metav1.GetOptions{})
	if err == nil {
		existing := secret.Data["tls.crt"]
		key := secret.Data["tls.key"]
		if len(existing) > 0 && len(key) > 0 {
			block, _ := pem.Decode(existing)
			if block != nil {
				cert, parseErr := x509.ParseCertificate(block.Bytes)
				if parseErr == nil && time.Until(cert.NotAfter) > radSecRenewBefore {
					log.Printf("reusing existing RadSec server cert (expires %s)", cert.NotAfter.Format(time.RFC3339))
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
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	if writeErr := radius.WriteRadSecServerCert(ctx, k8sClient, cfg.Namespace, cfg.RadSecCertSecret, newCertPEM, newKeyPEM, caPEM, wifiCAPEM); writeErr != nil {
		return nil, nil, false, fmt.Errorf("write radsec cert: %w", writeErr)
	}
	log.Printf("issued and stored new RadSec server cert")
	return newCertPEM, newKeyPEM, true, nil
}

// watchRadSecServerCert runs forever, checking every 24 hours whether the RadSec server
// cert needs renewal. On renewal it reloads FreeRADIUS so the new cert is picked up
// without a full restart.
func watchRadSecServerCert(k8sClient kubernetes.Interface, ipaClient *freeipa.Client, cfg *config.Config, caPEM, wifiCAPEM []byte) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		ctx := context.Background()
		_, _, renewed, err := loadOrRenewRadSecServerCert(ctx, k8sClient, ipaClient, cfg, caPEM, wifiCAPEM)
		if err != nil {
			log.Printf("radsec cert watcher: renewal failed: %v", err)
			continue
		}
		if renewed {
			if err := radius.Reload(ctx, k8sClient, cfg.Namespace, cfg.FreeRADIUSDeployment); err != nil {
				log.Printf("radsec cert watcher: freeradius reload failed: %v", err)
			} else {
				log.Printf("radsec cert watcher: renewed cert and reloaded freeradius")
			}
		}
	}
}
