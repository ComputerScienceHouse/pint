// internal/handlers/user.go
package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/gin-gonic/gin"
)

// navInfo holds the fields injected into every authenticated page render.
type navInfo struct {
	Username  string
	FullName  string
	AvatarURL string
}

func (n navInfo) toMap() gin.H {
	return gin.H{
		"Username":  n.Username,
		"FullName":  n.FullName,
		"AvatarURL": n.AvatarURL,
	}
}

// getNavInfo extracts user identity from the csh-auth v2 middleware context.
func getNavInfo(c *gin.Context) (navInfo, bool) {
	raw, exists := c.Get(cshauth.ContextKey)
	if !exists {
		return navInfo{}, false
	}
	claims, ok := raw.(*cshauth.Claims)
	if !ok {
		return navInfo{}, false
	}
	return navInfo{
		Username:  claims.Username,
		FullName:  claims.FullName,
		AvatarURL: fmt.Sprintf("https://profiles.csh.rit.edu/image/%s", claims.Username),
	}, true
}

// getUsername is a convenience wrapper for handlers that only need the username.
func getUsername(c *gin.Context) (string, bool) {
	info, ok := getNavInfo(c)
	return info.Username, ok
}

// DevAuthMiddleware injects a static *cshauth.Claims for local development.
// Enabled via PINT_DISABLE_OIDC=true; never use in production.
func DevAuthMiddleware() gin.HandlerFunc {
	claims := &cshauth.Claims{}
	claims.Username = "devuser"
	claims.FullName = "Dev User"
	return func(c *gin.Context) {
		c.Set(cshauth.ContextKey, claims)
		c.Next()
	}
}

// RequireAuth aborts with a redirect to loginURL if csh-auth Claims are not in context.
// Use this after CookieMiddleware on any route group that must be authenticated.
func RequireAuth(loginURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, exists := c.Get(cshauth.ContextKey); !exists {
			target := loginURL + "?referer=" + url.QueryEscape(c.Request.URL.RequestURI())
			c.Redirect(http.StatusFound, target)
			c.Abort()
			return
		}
		c.Next()
	}
}
