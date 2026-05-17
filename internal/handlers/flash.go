// internal/handlers/flash.go
package handlers

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	flashSuccess = "flash_success"
	flashError   = "flash_error"
	flashWarn    = "flash_warn"
)

func setFlash(c *gin.Context, key, msg string) {
	s := sessions.Default(c)
	s.AddFlash(msg, key)
	_ = s.Save()
}

// getFlash returns and clears the first flash message stored under key.
func getFlash(c *gin.Context, key string) string {
	s := sessions.Default(c)
	flashes := s.Flashes(key)
	_ = s.Save()
	if len(flashes) == 0 {
		return ""
	}
	if msg, ok := flashes[0].(string); ok {
		return msg
	}
	return ""
}
