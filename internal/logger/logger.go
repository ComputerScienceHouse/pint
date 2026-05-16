// internal/logger/logger.go
package logger

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New builds a zap logger.
//
// PINT_LOG_DEV=true selects the development preset (colored console output,
// lowercase level names, stack traces on warn+). Defaults to the production
// preset (JSON, no color).
//
// PINT_LOG_LEVEL controls verbosity for both presets.
// Valid values: debug, info, warn, error (case-insensitive). Defaults to info.
func New() (*zap.Logger, error) {
	level := zapcore.InfoLevel
	if raw := strings.ToLower(os.Getenv("PINT_LOG_LEVEL")); raw != "" {
		if err := level.UnmarshalText([]byte(raw)); err != nil {
			return nil, fmt.Errorf("invalid PINT_LOG_LEVEL %q: %w", raw, err)
		}
	}

	dev := strings.ToLower(os.Getenv("PINT_LOG_DEV")) == "true"

	var cfg zap.Config
	if dev {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006/01/02 15:04:05.000")
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		cfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	} else {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "ts"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}
	cfg.Level = zap.NewAtomicLevelAt(level)

	return cfg.Build()
}
