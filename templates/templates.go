// Package templates embeds the application HTML templates into the binary.
package templates

import "embed"

//go:embed *.html
var FS embed.FS
