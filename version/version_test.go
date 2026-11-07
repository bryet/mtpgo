package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	s := String()
	for _, part := range []string{Version, Commit, BuildDate, runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(s, part) {
			t.Fatalf("missing %q in %q", part, s)
		}
	}
}
