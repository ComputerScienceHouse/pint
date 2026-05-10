// internal/handlers/dashboard.go
package handlers

import (
	"net/http"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/gin-gonic/gin"
)

func DashboardHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, _ := getUsername(c)
		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"Username": username,
		})
	}
}
