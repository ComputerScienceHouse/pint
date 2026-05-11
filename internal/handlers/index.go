// internal/handlers/index.go
package handlers

import (
	"net/http"

	"github.com/ComputerScienceHouse/pint/internal/config"
	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/gin-gonic/gin"
)

func IndexHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, err := c.Cookie(cshauth.CookieName); err == nil {
			c.Redirect(http.StatusFound, "/dashboard")
			return
		}
		c.HTML(http.StatusOK, "index.html", gin.H{})
	}
}
