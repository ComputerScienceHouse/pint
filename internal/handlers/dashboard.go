// internal/handlers/dashboard.go
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Dashboard serves GET /dashboard.
func (s *Server) Dashboard(c *gin.Context) {
	nav, _ := getNavInfo(c)
	c.HTML(http.StatusOK, "dashboard.html", nav.toMap())
}
