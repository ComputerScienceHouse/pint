// internal/handlers/csrf.go
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	csrfCookieName = "_csrf"
	csrfFormField  = "csrf_token"
	csrfContextKey = "csrf_token"
)

// CSRFMiddleware implements the double-submit cookie pattern.
// On every request it ensures the _csrf cookie exists and injects the token
// value into the Gin context as "csrf_token" for template rendering.
// On POST requests it verifies that the form field matches the cookie.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(csrfCookieName)
		if err != nil || token == "" {
			token = newCSRFToken()
		}
		// Refresh cookie on every response (SameSite=Lax, not HttpOnly so JS
		// can read it if needed, but Secure is intentionally omitted here to
		// work in local dev over HTTP — set Secure=true behind TLS in prod).
		c.SetCookie(csrfCookieName, token, 0, "/", "", false, false)
		c.Set(csrfContextKey, token)

		if c.Request.Method == http.MethodPost {
			// Accept token from form field (HTML forms) or X-CSRF-Token header (fetch).
			submitted := c.PostForm(csrfFormField)
			if submitted == "" {
				submitted = c.GetHeader("X-CSRF-Token")
			}
			if submitted != token {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		c.Next()
	}
}

func newCSRFToken() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck — rand.Read never returns an error
	return hex.EncodeToString(b)
}
