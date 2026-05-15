package version

// GitCommit is the short git hash injected at build time via -ldflags.
// Falls back to "dev" when built without ldflags (local development).
var GitCommit = "dev"
