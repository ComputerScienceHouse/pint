// internal/handlers/user.go
package handlers

import "github.com/gin-gonic/gin"

// getUsername extracts the CSH username from the csh-auth middleware context.
// csh-auth stores user claims at the "cshauth" key as a map[string]interface{}.
func getUsername(c *gin.Context) (string, bool) {
	raw, exists := c.Get("cshauth")
	if !exists {
		return "", false
	}
	claims, ok := raw.(map[string]interface{})
	if !ok {
		return "", false
	}
	username, ok := claims["preferred_username"].(string)
	return username, ok
}
