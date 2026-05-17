// internal/handlers/server.go
package handlers

import (
	"net/http"
	"sync/atomic"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/devicemap"
	"github.com/ComputerScienceHouse/pint/internal/freeipa"
	"github.com/ComputerScienceHouse/pint/internal/profile"
	"github.com/ComputerScienceHouse/pint/internal/scep"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
)

// rootUsername is the reserved store key for the organization controller RADIUS entry.
// Regular member-facing handlers must reject this username to prevent shadowing.
const rootUsername = "root"

// FreeIPAClient is the subset of freeipa.Client used by handlers.
// Defining it here decouples the handlers package from freeipa's full surface.
type FreeIPAClient interface {
	CertRequest(principal, csrPEM, caName, profileID string) ([]byte, error)
	CertRevoke(serial int64, caName string, reason int) error
	CertFind(username, caName string) ([]freeipa.CertInfo, error)
}

// CABundle holds the CA certificates needed to build and sign profiles.
type CABundle struct {
	WiFiCACertDER        []byte // wireless intermediate CA DER
	RootCACertDER        []byte // root CA DER
	CodeSigningCACertDER []byte // code-signing intermediate CA DER; empty when signing is disabled
	SCEPRACertDER        []byte // self-signed SCEP RA cert DER
	RadSecCAChainPEM     string // RadSec CA chain PEM (intermediate + root)
}

// Server holds the shared dependencies for all HTTP handlers.
// Fields are exported so tests can create minimal instances without a constructor.
type Server struct {
	Log        *zap.Logger
	Cfg        *config.Config
	IPA        FreeIPAClient
	K8s        kubernetes.Interface
	Metrics    metricsv.Interface
	DM         *devicemap.DeviceMap
	Challenges *scep.ChallengeStore
	Signer     atomic.Pointer[profile.Signer] // hot-swappable; nil pointer means signing disabled
	CA         CABundle
}

// Routes registers all application routes on r.
// Auth routes (/auth/login, /auth/callback, /auth/logout) and SCEP routes are
// expected to be registered by the caller before this method is invoked.
func (s *Server) Routes(r *gin.Engine, authMiddleware gin.HandlerFunc) {
	// Health probes — always public, never logged (filtered in ZapLogger by kube-probe UA)
	r.GET("/healthz", s.Healthz)
	r.GET("/readyz", s.Readyz)

	r.GET("/", s.Index)

	protected := r.Group("/")
	protected.Use(authMiddleware)
	protected.Use(RequireAuth(s.Cfg.LoginURL))
	protected.Use(CSRFMiddleware())
	{
		protected.GET("/dashboard", s.Dashboard)
		protected.GET("/profile", s.ProfilePage)
		protected.POST("/profile/generate", s.GenerateProfile)
		protected.GET("/profile/ca", s.CADownload)
		protected.GET("/profile/scep-challenge", s.SCEPChallenge)
		protected.GET("/devices", s.DevicesPage)
		protected.POST("/devices/revoke", s.RevokeDevice)
		protected.GET("/radius", s.RadiusPage)
		protected.POST("/radius/secret", s.SaveSecret)
		protected.POST("/radius/regenerate", s.Regenerate)
		protected.POST("/radius/update-ip", s.UpdateIP)
		protected.POST("/radius/delete", s.DeleteSecret)
		protected.GET("/radius/ca", s.RadSecCA)
		protected.GET("/status", s.StatusPage)
		protected.POST("/status/reload", s.Reload)

		admin := protected.Group("/admin")
		admin.Use(RequireRTP)
		{
			admin.GET("/devices", s.AdminDevicesPage)
			admin.POST("/devices/revoke", s.AdminRevokeDevice)
			admin.GET("/radius", s.AdminRadiusPage)
			admin.POST("/radius/delete", s.AdminDelete)
			admin.POST("/radius/regenerate", s.AdminRegenerate)
			admin.POST("/radius/root/provision", s.AdminRootProvision)
			admin.POST("/radius/root/regenerate", s.AdminRootRegenerate)
			admin.POST("/radius/root/update-ip", s.AdminRootUpdateIP)
		}
	}
}

// Healthz serves GET /healthz — returns 200 when the process is alive.
func (s *Server) Healthz(c *gin.Context) {
	c.Status(http.StatusOK)
}

// Readyz serves GET /readyz — returns 200 when the k8s client is reachable.
// It's intentionally lightweight: a server-version check is cheap and doesn't
// require FreeIPA, which may be temporarily unavailable during a restart.
func (s *Server) Readyz(c *gin.Context) {
	if _, err := s.K8s.Discovery().ServerVersion(); err != nil {
		s.log().Error("readyz: k8s unreachable", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "k8s unreachable"})
		return
	}
	c.Status(http.StatusOK)
}

// log returns the server logger, falling back to a no-op so tests can omit it.
func (s *Server) log() *zap.Logger {
	if s.Log != nil {
		return s.Log
	}
	return zap.NewNop()
}

// fail logs err (if non-nil) and writes a JSON error response with a user-safe message.
// Callers should return immediately after fail.
func (s *Server) fail(c *gin.Context, status int, msg string, err error) {
	if err != nil {
		s.log().Error(msg, zap.Error(err))
	}
	c.JSON(status, gin.H{"error": msg})
}
