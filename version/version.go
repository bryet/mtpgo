package version

import (
	"fmt"
	"runtime"
)

// Set at build time via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func String() string {
	return fmt.Sprintf("mtpgo version %s\nCommit: %s\nBuild date: %s\nGo version: %s\nOS/Arch: %s/%s",
		Version, Commit, BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
