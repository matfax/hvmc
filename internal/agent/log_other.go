//go:build !windows

package agent

import (
	"io"
	"log/slog"
	"os"
)

// platformHandler logs text records to stderr (journald on Linux).
func platformHandler(o LogOptions) (slog.Handler, func() error, error) {
	var w io.Writer = os.Stderr
	if o.Stderr != nil {
		w = o.Stderr
	}
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: o.Level}), func() error { return nil }, nil
}
