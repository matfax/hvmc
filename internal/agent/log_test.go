package agent

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "audit.log")
	r, err := OpenRotatingFile(path, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"aaaa\n", "bbbb\n", "cccc\n", "dddd\n", "eeee\n", "ffffffffffffffff\n"} {
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{
		path:        "ffffffffffffffff\n", // larger than the limit: alone in a fresh file
		path + ".1": "eeee\n",
		path + ".2": "cccc\ndddd\n",
	} {
		got, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", filepath.Base(file), got, want)
		}
	}
	if fileExists(t, path+".3") {
		t.Error("kept more than 2 rotated files")
	}
	if _, err := r.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("write after Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestRotatingFileReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	writeTestFile(t, path, []byte("ffffffffffffffff\n"))
	// Reopening appends and counts the existing size.
	r, err := OpenRotatingFile(path, 20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := r.Write([]byte("gggg\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path + ".1"); string(got) != "ffffffffffffffff\n" {
		t.Errorf("reopened file did not rotate at its existing size: .1 = %q", got)
	}
}

// fakeEventLog records Event Log calls.
type fakeEventLog struct{ entries []string }

func (f *fakeEventLog) Info(eid uint32, msg string) error    { return f.add("info", eid, msg) }
func (f *fakeEventLog) Warning(eid uint32, msg string) error { return f.add("warning", eid, msg) }
func (f *fakeEventLog) Error(eid uint32, msg string) error   { return f.add("error", eid, msg) }

func (f *fakeEventLog) add(kind string, eid uint32, msg string) error {
	if eid != eventID {
		return errors.New("unexpected event id")
	}
	f.entries = append(f.entries, kind+": "+msg)
	return nil
}

func TestEventLogHandler(t *testing.T) {
	el := &fakeEventLog{}
	log := slog.New(newEventLogHandler(el, slog.LevelInfo)).With("agent", "host").WithGroup("g")
	log.Debug("hidden")
	log.Info("started", "port", 9443)
	log.Warn("check failing")
	log.Error("failed", "error", "boom")
	want := []string{
		"info: level=INFO msg=started agent=host g.port=9443",
		"warning: level=WARN msg=\"check failing\" agent=host",
		"error: level=ERROR msg=failed agent=host g.error=boom",
	}
	if strings.Join(el.entries, "\n") != strings.Join(want, "\n") {
		t.Errorf("entries:\n%s\nwant:\n%s", strings.Join(el.entries, "\n"), strings.Join(want, "\n"))
	}
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	dir := t.TempDir()
	log, closeFn, err := NewLogger(LogOptions{Stderr: &buf, Dir: dir, Level: slog.LevelWarn})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("quiet")
	log.Warn("hello", "k", "v")
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "msg=hello k=v") || strings.Contains(buf.String(), "quiet") {
		t.Errorf("stderr %q", buf.String())
	}
	if isWindows() {
		data, err := os.ReadFile(filepath.Join(dir, "agent.log"))
		if err != nil || !strings.Contains(string(data), `"msg":"hello"`) {
			t.Errorf("rotating log file %q, %v", data, err)
		}
	}
}
