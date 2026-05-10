// internal/handlers/handlers_test.go
package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/ComputerScienceHouse/pint/internal/handlers"
	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// testAuth injects a mock csh-auth v2 Claims into the Gin context.
func testAuth(username string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(cshauth.ContextKey, &cshauth.Claims{
			UserInfo: cshauth.UserInfo{Username: username},
		})
		c.Next()
	}
}

func minimalConfig() *config.Config {
	return &config.Config{
		WiFiSSID:     "TestNet",
		RadiusServer: "radius.example.com:2083",
	}
}

func TestIndexHandler(t *testing.T) {
	r := gin.New()
	r.LoadHTMLGlob("../../templates/*.html")
	r.GET("/", handlers.IndexHandler(minimalConfig()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "PINT") {
		t.Error("index page missing PINT title")
	}
}

func TestDashboardHandler(t *testing.T) {
	r := gin.New()
	r.LoadHTMLGlob("../../templates/*.html")
	r.GET("/dashboard", testAuth("mbillow"), handlers.DashboardHandler(minimalConfig()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "mbillow") {
		t.Error("dashboard missing username")
	}
}
