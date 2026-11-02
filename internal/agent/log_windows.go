//go:build windows

package agent

import (
	"errors"
	"log/slog"
	"path/filepath"

	slogmulti "github.com/samber/slog-multi"
	"golang.org/x/sys/windows/svc/eventlog"
)

// platformHandler fans out to the Event Log, a rotating JSON file in
// o.Dir and, when set, o.Stderr. A missing Event Log (source not
// registered yet, e.g. before install) is not fatal: the file and stderr
// still receive every record.
func platformHandler(o LogOptions) (slog.Handler, func() error, error) {
	var handlers []slog.Handler
	var closers []func() error
	opts := &slog.HandlerOptions{Level: o.Level}
	if o.Stderr != nil {
		handlers = append(handlers, slog.NewTextHandler(o.Stderr, opts))
	}
	if o.Dir != "" {
		f, err := OpenRotatingFile(filepath.Join(o.Dir, "agent.log"), DefaultRotateBytes, DefaultRotateKeep)
		if err != nil {
			return nil, nil, err
		}
		handlers = append(handlers, slog.NewJSONHandler(f, opts))
		closers = append(closers, f.Close)
	}
	if el, err := eventlog.Open(EventSource); err == nil {
		handlers = append(handlers, newEventLogHandler(el, o.Level))
		closers = append(closers, el.Close)
	}
	closeAll := func() error {
		var errs []error
		for _, c := range closers {
			errs = append(errs, c())
		}
		return errors.Join(errs...)
	}
	return slogmulti.Fanout(handlers...), closeAll, nil
}
