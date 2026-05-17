// internal/handlers/index.go
package handlers

import (
	"net/http"

	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/gin-gonic/gin"
)

// Index serves GET / — redirects authenticated users to /dashboard.
func (s *Server) Index(c *gin.Context) {
	if _, err := c.Cookie(cshauth.CookieName); err == nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	c.Redirect(http.StatusFound, s.Cfg.LoginURL+"?referer=/dashboard")
}
