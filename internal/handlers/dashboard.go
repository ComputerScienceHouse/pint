// internal/handlers/dashboard.go
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func DashboardHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		nav, _ := getNavInfo(c)
		c.HTML(http.StatusOK, "dashboard.html", nav.toMap())
	}
}
