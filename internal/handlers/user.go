// internal/handlers/user.go
package handlers

import (
	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/gin-gonic/gin"
)

// getUsername extracts the CSH username from the csh-auth v2 middleware context.
// csh-auth v2 stores *cshauth.Claims at the "cshauth" key.
func getUsername(c *gin.Context) (string, bool) {
	raw, exists := c.Get(cshauth.ContextKey)
	if !exists {
		return "", false
	}
	claims, ok := raw.(*cshauth.Claims)
	if !ok {
		return "", false
	}
	return claims.Username, true
}
