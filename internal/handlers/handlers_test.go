// internal/handlers/handlers_test.go
package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ComputerScienceHouse/pint/internal/handlers"
	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func testTemplates() multitemplate.Render {
	r := multitemplate.New()
	layout := "../../templates/layout.html"
	for _, page := range []string{"index", "dashboard", "profile", "radius"} {
		r.AddFromFiles(page+".html", layout, "../../templates/"+page+".html")
	}
	return r
}

// testAuth injects a mock csh-auth v2 Claims into the Gin context.
func testAuth(username string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(cshauth.ContextKey, &cshauth.Claims{
			UserInfo: cshauth.UserInfo{Username: username},
		})
		c.Next()
	}
}


func TestIndexHandler(t *testing.T) {
	const loginURL = "http://localhost:8080/auth/login"
	r := gin.New()
	r.GET("/", handlers.IndexHandler(loginURL))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != loginURL {
		t.Errorf("Location = %q, want %q", loc, loginURL)
	}
}

func TestDashboardHandler(t *testing.T) {
	r := gin.New()
	r.HTMLRender = testTemplates()
	r.GET("/dashboard", testAuth("mbillow"), handlers.DashboardHandler())

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/dashboard", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "mbillow") {
		t.Error("dashboard missing username")
	}
}
