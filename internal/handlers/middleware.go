// internal/handlers/middleware.go
package handlers

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ZapLogger returns a gin middleware that logs each request with zap.
// Query strings are redacted for /auth/callback to prevent OIDC codes from
// appearing in logs. The authenticated username is included when available.
func ZapLogger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.UserAgent(), "kube-probe/") {
			c.Next()
			return
		}

		start := time.Now()
		path := c.Request.URL.Path

		// OIDC callback carries a short-lived authorization code in the query
		// string; logging it would expose a credential, so strip it entirely.
		redacted := path == "/auth/callback"
		if !redacted {
			if q := c.Request.URL.RawQuery; q != "" {
				path += "?" + q
			}
		}

		c.Next()

		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		}
		if redacted {
			fields = append(fields, zap.Bool("query_redacted", true))
		}
		if username, ok := getUsername(c); ok {
			fields = append(fields, zap.String("user", username))
		}

		log.Info("request", fields...)
	}
}
