// internal/handlers/user.go
package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	cshauth "github.com/computersciencehouse/csh-auth/v2"
	"github.com/ComputerScienceHouse/pint/internal/version"
	"github.com/gin-gonic/gin"
)

// navInfo holds the fields injected into every authenticated page render.
type navInfo struct {
	Username    string
	FullName    string
	AvatarURL   string
	IsRTP       bool
	CurrentPath string
}

func (n navInfo) toMap() gin.H {
	return gin.H{
		"Username":    n.Username,
		"FullName":    n.FullName,
		"AvatarURL":   n.AvatarURL,
		"IsRTP":       n.IsRTP,
		"CurrentPath": n.CurrentPath,
		"GitCommit":   version.GitCommit,
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
	rtpMember := false
	for _, g := range claims.Groups {
		if g == "rtp" {
			rtpMember = true
			break
		}
	}
	return navInfo{
		Username:    claims.Username,
		FullName:    claims.FullName,
		AvatarURL:   fmt.Sprintf("https://profiles.csh.rit.edu/image/%s", claims.Username),
		IsRTP:       rtpMember,
		CurrentPath: c.Request.URL.Path,
	}, true
}

// isRTP returns true if the current request's user is an RTP member.
func isRTP(c *gin.Context) bool {
	nav, ok := getNavInfo(c)
	return ok && nav.IsRTP
}

// RequireRTP aborts with 403 if the authenticated user is not in the rtp group.
func RequireRTP(c *gin.Context) {
	if !isRTP(c) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Next()
}

// getUsername is a convenience wrapper for handlers that only need the username.
func getUsername(c *gin.Context) (string, bool) {
	info, ok := getNavInfo(c)
	return info.Username, ok
}

// DevAuthMiddleware injects a static *cshauth.Claims for local development.
// Enabled via PINT_DISABLE_OIDC=true; never use in production.
// Set PINT_DEV_RTP=true to also inject the rtp group.
func DevAuthMiddleware() gin.HandlerFunc {
	claims := &cshauth.Claims{}
	claims.Username = "devuser"
	claims.FullName = "Dev User"
	if os.Getenv("PINT_DEV_RTP") == "true" {
		claims.Groups = []string{"rtp"}
	}
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
