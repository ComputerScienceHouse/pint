// internal/handlers/index.go
package handlers

import (
	"net/http"

	"github.com/ComputerScienceHouse/pint/internal/config"
	"github.com/gin-gonic/gin"
)

func IndexHandler(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	}
}
