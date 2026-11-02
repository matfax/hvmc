package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Logging (DESIGN §2.1, §4.5)
//
// Linux: log/slog text records on stderr, which journald captures.
// Windows: the Windows Event Log (source [EventSource], registered by
// `hvmc agent install`) and a rotating JSON file in %ProgramData%\hvmc\logs,
// fanned out with slog-multi, plus stderr when one is given (foreground
// runs). The platform part is in log_windows.go and log_other.go.

// EventSource is the Windows Event Log source of the agent.
const EventSource = "hvmc-agent"

// Rotation defaults of the log and audit files.
const (
	DefaultRotateBytes int64 = 10 << 20
	DefaultRotateKeep        = 5
)

// LogOptions configure NewLogger.
type LogOptions struct {
	// Level is the minimum level; nil means Info.
	Level slog.Leveler
	// Stderr receives text records: always on Linux; on Windows only when
	// set (foreground runs), next to the Event Log and the file.
	Stderr io.Writer
	// Dir is the directory of the rotating log file (Windows only).
	Dir string
}

// NewLogger returns the agent's logger for this platform and a function
// that closes what it opened.
func NewLogger(o LogOptions) (*slog.Logger, func() error, error) {
	if o.Level == nil {
		o.Level = slog.LevelInfo
	}
	h, closeFn, err := platformHandler(o)
	if err != nil {
		return nil, nil, err
	}
	return slog.New(h), closeFn, nil
}

// RotatingFile is an io.Writer that appends to a file and rotates it by
// size: path → path.1 → … → path.<keep>, the oldest dropped. The file is
// closed before it is renamed, so rotation also works on Windows.
type RotatingFile struct {
	path string
	max  int64
	keep int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenRotatingFile opens (or creates, mode 0600) path for appending,
// creating its directory if needed.
func OpenRotatingFile(path string, maxBytes int64, keep int) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, max: maxBytes, keep: max(keep, 1)}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when p would take the file past its
// limit. A single write larger than the limit goes into a fresh file.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.size > 0 && r.size+int64(len(p)) > r.max {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	r.f = nil
	_ = os.Remove(r.rotated(r.keep))
	for i := r.keep - 1; i >= 1; i-- {
		_ = os.Rename(r.rotated(i), r.rotated(i+1))
	}
	if err := os.Rename(r.path, r.rotated(1)); err != nil {
		_ = r.open()
		return err
	}
	return r.open()
}

func (r *RotatingFile) rotated(i int) string { return fmt.Sprintf("%s.%d", r.path, i) }

// Close closes the file. Later writes fail with os.ErrClosed.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// eventWriter is the part of golang.org/x/sys/windows/svc/eventlog.Log the
// Event Log handler uses.
type eventWriter interface {
	Info(eid uint32, msg string) error
	Warning(eid uint32, msg string) error
	Error(eid uint32, msg string) error
}

// eventID is the event ID of every record; the level carries the meaning.
const eventID = 1

// eventLogHandler is a slog.Handler writing one Event Log entry per
// record, formatted as a text record without the time (the Event Log has
// its own). Debug and Info map to Information, Warn to Warning, Error to
// Error.
type eventLogHandler struct {
	w     eventWriter
	level slog.Leveler
	mu    *sync.Mutex
	buf   *bytes.Buffer
	inner slog.Handler
}

func newEventLogHandler(w eventWriter, level slog.Leveler) *eventLogHandler {
	buf := &bytes.Buffer{}
	inner := slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	return &eventLogHandler{w: w, level: level, mu: &sync.Mutex{}, buf: buf, inner: inner}
}

func (h *eventLogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }

func (h *eventLogHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if err := h.inner.Handle(ctx, r); err != nil {
		return err
	}
	msg := strings.TrimSuffix(h.buf.String(), "\n")
	switch {
	case r.Level >= slog.LevelError:
		return h.w.Error(eventID, msg)
	case r.Level >= slog.LevelWarn:
		return h.w.Warning(eventID, msg)
	default:
		return h.w.Info(eventID, msg)
	}
}

func (h *eventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.inner = h.inner.WithAttrs(attrs)
	return &c
}

func (h *eventLogHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.inner = h.inner.WithGroup(name)
	return &c
}
