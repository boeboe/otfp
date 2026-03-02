package core

import "fmt"

// BuildInfo holds version metadata injected at compile time via ldflags.
type BuildInfo struct {
	Version   string
	Branch    string
	Revision  string
	BuildUser string
	BuildDate string
}

// String returns a multi-line human-readable version summary.
func (b BuildInfo) String() string {
	return fmt.Sprintf("version %s\n  branch:     %s\n  revision:   %s\n  build user: %s\n  build date: %s",
		b.Version, b.Branch, b.Revision, b.BuildUser, b.BuildDate)
}

// Short returns a single-line version string suitable for log headers.
func (b BuildInfo) Short() string {
	return fmt.Sprintf("%s (%s/%s)", b.Version, b.Branch, b.Revision)
}
