// cmd/pint/main.go
package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/ComputerScienceHouse/pint/internal/certmgr"
	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/devicemap"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/handlers"
	"github.com/ComputerScienceHouse/pint/internal/logger"
	"github.com/ComputerScienceHouse/pint/internal/radius"
	internscep "github.com/ComputerScienceHouse/pint/internal/scep"
	pintemplates "github.com/ComputerScienceHouse/pint/templates"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
)

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

	// Signal context for graceful shutdown — propagated to certmgr, http server, and challenge store.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// FreeIPA client: authenticate at startup.
	ipaClient := freeipa.New(cfg.IPAHost, cfg.IPAPrincipal, cfg.IPAPassword, cfg.IPASkipTLSVerify)
	if err := ipaClient.Login(); err != nil {
		log.Fatal("freeipa login failed", zap.Error(err))
	}
	log.Info("freeipa authenticated", zap.String("host", cfg.IPAHost), zap.String("principal", cfg.IPAPrincipal))

	// Kubernetes client: try in-cluster first, fall back to kubeconfig.
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

	// Initialize RADIUS secrets with safe defaults if they don't exist yet.
	if err := radius.EnsureConfigSecret(ctx, k8sClient, cfg.Namespace, cfg.ConfigSecret); err != nil {
		log.Fatal("init radius secrets failed", zap.Error(err))
	}

	statusSecret, err := radius.EnsureStatusConfig(ctx, k8sClient, cfg.Namespace, cfg.ConfigSecret)
	if err != nil {
		log.Fatal("ensure status secret failed", zap.Error(err))
	}
	statusConf := radius.RenderStatusConfig(statusSecret, "0.0.0.0/0")
	if err := radius.WriteStatusConfig(ctx, k8sClient, cfg.Namespace, cfg.ConfigSecret, cfg.FreeRADIUSDeployment, statusConf); err != nil {
		log.Fatal("write status config failed", zap.Error(err))
	}
	if err := radius.WriteRadSecTLS(ctx, k8sClient, cfg.Namespace, cfg.ConfigSecret, cfg.FreeRADIUSDeployment, cfg.RadSecCheckCRL, cfg.RadSecProxyProtocol); err != nil {
		log.Fatal("write radsec-tls.conf failed", zap.Error(err))
	}

	// Fetch CA certs in parallel.
	var (
		caDER                []byte
		radSecCACertDER      []byte
		rootCACertDER        []byte
		codeSigningCACertDER []byte
		caErr                [3]error
	)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); caDER, caErr[0] = ipaClient.CAShow(cfg.IPAWirelessCAName) }()
	go func() { defer wg.Done(); radSecCACertDER, caErr[1] = ipaClient.CAShow(cfg.RadSecCAName) }()
	go func() { defer wg.Done(); rootCACertDER, caErr[2] = ipaClient.CAShow(cfg.RootCAName) }()
	wg.Wait()
	for i, e := range caErr {
		if e != nil {
			log.Fatal("freeipa ca_show failed", zap.Int("index", i), zap.Error(e))
		}
	}
	if cfg.CodeSigningCAName != "" {
		var codeSigningErr error
		codeSigningCACertDER, codeSigningErr = ipaClient.CAShow(cfg.CodeSigningCAName)
		if codeSigningErr != nil {
			log.Fatal("freeipa ca_show (code signing CA) failed", zap.String("ca", cfg.CodeSigningCAName), zap.Error(codeSigningErr))
		}
	}

	logCACert(log, "WiFi CA", caDER)
	logCACert(log, "RadSec CA", radSecCACertDER)
	logCACert(log, "Root CA", rootCACertDER)
	if len(codeSigningCACertDER) > 0 {
		logCACert(log, "Code Signing CA", codeSigningCACertDER)
	}

	radSecCAChainPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: radSecCACertDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCACertDER}))
	wifiCAPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCACertDER})...,
	)

	// Load or generate the SCEP RA cert (self-signed RSA, no renewal watcher needed).
	scepRACert, scepRAKey, scepRACertDER, err := loadOrGenerateSCEPRACert(ctx, log, k8sClient, cfg)
	if err != nil {
		log.Fatal("scep RA cert init failed", zap.Error(err))
	}
	log.Info("scep RA cert loaded", zap.String("subject", scepRACert.Subject.CommonName), zap.String("expires", scepRACert.NotAfter.Format("2006-01-02")))

	// Build the application server.
	srv := &handlers.Server{
		Log:     log,
		Cfg:     cfg,
		IPA:     ipaClient,
		K8s:     k8sClient,
		Metrics: metricsClient,
		DM:      devicemap.New(k8sClient, cfg.Namespace, cfg.DeviceMapSecret),
		CA: handlers.CABundle{
			WiFiCACertDER:        caDER,
			RootCACertDER:        rootCACertDER,
			CodeSigningCACertDER: codeSigningCACertDER,
			SCEPRACertDER:        scepRACertDER,
			RadSecCAChainPEM:     radSecCAChainPEM,
		},
	}
	srv.Challenges = internscep.NewChallengeStore()

	// Cert manager: single goroutine handles all certs with jitter, context-aware shutdown.
	mgr := certmgr.New(log, k8sClient)
	mgr.Register(newRadSecServerCert(log, ipaClient, cfg, k8sClient, []byte(radSecCAChainPEM)))
	mgr.Register(newEAPServerCert(log, ipaClient, cfg, k8sClient, wifiCAPEM))
	if cfg.CodeSigningCAName != "" {
		mgr.Register(newProfileSigningCert(log, ipaClient, cfg, k8sClient, codeSigningCACertDER, srv))
	}
	if err := mgr.RunOnce(ctx); err != nil {
		log.Fatal("cert manager startup failed", zap.Error(err))
	}
	go mgr.Watch(ctx)

	// If profile signing is enabled, load the initial signer from the K8s secret.
	// The certmgr will hot-swap it on renewal via profileSigningCert.AfterRenew.
	if cfg.CodeSigningCAName != "" {
		if secret, err := k8sClient.CoreV1().Secrets(cfg.Namespace).Get(ctx, cfg.ProfileSigningCertSecret, metav1.GetOptions{}); err == nil {
			if signer, err := profileSignerFromPEM(secret.Data["tls.crt"], secret.Data["tls.key"], codeSigningCACertDER); err == nil {
				srv.Signer.Store(signer)
				log.Info("apple profile signing enabled", zap.String("subject", signer.Cert.Subject.CommonName))
			}
		}
	}

	// Router setup.
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

	// SCEP public routes — iOS calls these without a session cookie.
	scepHandler, err := internscep.NewHandler(log, srv.Challenges, ipaClient, srv.DM, cfg.IPAWirelessCAName, cfg.IPACertProfile, scepRACert, scepRAKey, caDER, rootCACertDER)
	if err != nil {
		log.Fatal("scep handler init failed", zap.Error(err))
	}
	scepHandler.Register(r)

	srv.Routes(r, authMiddleware)

	// HTTP server with explicit timeouts and graceful shutdown.
	httpSrv := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			log.Error("http server shutdown error", zap.Error(err))
		}
		srv.Challenges.Stop()
	}()

	log.Info("starting PINT", zap.String("addr", ":8080"))
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("server exited", zap.Error(err))
	}
	log.Info("server stopped gracefully")
}

// buildTemplates creates the multitemplate renderer from the embedded template FS.
// Pages are discovered by glob rather than a hardcoded list, so adding a new
// template file is sufficient — no code change required.
func buildTemplates() multitemplate.Render {
	r := multitemplate.New()
	entries, err := pintemplates.FS.ReadDir(".")
	if err != nil {
		panic("template dir read failed: " + err.Error())
	}
	for _, e := range entries {
		name := e.Name()
		if name == "layout.html" || !strings.HasSuffix(name, ".html") {
			continue
		}
		r.AddFromFS(name, pintemplates.FS, "layout.html", name)
	}
	return r
}
