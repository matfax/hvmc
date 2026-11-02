package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/matfax/hvmc/internal/fake"
)

// t0 is the start time of every manual clock.
var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// testClock adapts fake.ManualClock to Clock.
type testClock struct{ *fake.ManualClock }

func newTestClock() testClock { return testClock{fake.NewManualClock(t0)} }

func (c testClock) NewTimer(d time.Duration) Timer { return c.ManualClock.NewTimer(d) }

func (c testClock) AfterFunc(d time.Duration, f func()) Timer {
	return c.ManualClock.AfterFunc(d, f)
}

// waitTimer waits until a timer is pending on the clock: the main loop
// has finished its tick and armed the next one.
func (c testClock) waitTimer(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.BlockUntil(ctx, 1); err != nil {
		t.Fatalf("waiting for a timer: %v", err)
	}
}

// testLogger returns a logger writing to the test log.
func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(string(p))
	return len(p), nil
}

// testCA is a throwaway CA.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

var serial atomic.Int64

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: "hvmc-ca"},
		NotBefore:             t0.Add(-24 * time.Hour),
		NotAfter:              t0.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leafSpec describes a certificate issued by a testCA.
type leafSpec struct {
	cn        string
	dns       []string
	ips       []net.IP
	usage     []x509.ExtKeyUsage
	notBefore time.Time
	notAfter  time.Time
}

func serverSpec(dns ...string) leafSpec {
	if len(dns) == 0 {
		dns = []string{"localhost"}
	}
	return leafSpec{
		cn: "agent", dns: dns, ips: []net.IP{net.IPv4(127, 0, 0, 1)},
		usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func clientSpec(cn string) leafSpec {
	return leafSpec{cn: cn, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

// issue signs pub with the CA; the leaf is valid from t0-1h to t0+30d
// unless the spec says otherwise.
func (ca *testCA) issue(t *testing.T, pub any, s leafSpec) []byte {
	t.Helper()
	if s.notBefore.IsZero() {
		s.notBefore = t0.Add(-time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = t0.Add(30 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: s.cn},
		DNSNames:     s.dns,
		IPAddresses:  s.ips,
		NotBefore:    s.notBefore,
		NotAfter:     s.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  s.usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// tlsCert returns a fresh key with a certificate issued for it.
func (ca *testCA) tlsCert(t *testing.T, s leafSpec) tls.Certificate {
	t.Helper()
	key := newKey(t)
	der := ca.issue(t, &key.PublicKey, s)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// writeState lays out an enrolled state directory and agent.yaml in a
// temporary directory and returns its paths.
func writeState(t *testing.T, ca *testCA, serving tls.Certificate, configYAML string) Paths {
	t.Helper()
	dir := t.TempDir()
	p := Paths{Config: filepath.Join(dir, "etc", "agent.yaml"), State: filepath.Join(dir, "state")}
	for _, d := range []string{filepath.Dir(p.Config), p.State} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, p.CA(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
	data, err := encodeServing(serving.PrivateKey.(*ecdsa.PrivateKey), serving.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, p.Serving(), data)
	writeTestFile(t, p.Config, []byte(configYAML))
	return p
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

const hostConfigYAML = `role: host
name: host
listen: 127.0.0.1:0
health: 127.0.0.1:0
vms:
  - name: windows-node-1
    min: 6Gi
    max: 24Gi
`

const guestConfigYAML = `role: guest
name: guest-1
listen: 127.0.0.1:0
health: 127.0.0.1:0
`

// env is a test agent with its PKI and clock.
type env struct {
	t     *testing.T
	ca    *testCA
	clk   testClock
	paths Paths
	agent *Agent
	done  chan error
	stop  context.CancelFunc
}

// newEnv builds an agent (not yet running) from configYAML.
func newEnv(t *testing.T, configYAML string, svc Service) *env {
	t.Helper()
	return newEnvWith(t, configYAML, svc, nil)
}

// newEnvWith is newEnv with a hook that adjusts the agent's options.
func newEnvWith(t *testing.T, configYAML string, svc Service, adjust func(*Options)) *env {
	t.Helper()
	ca := newTestCA(t)
	clk := newTestClock()
	paths := writeState(t, ca, ca.tlsCert(t, serverSpec()), configYAML)
	cfg, err := LoadConfig(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		Config: cfg, Paths: paths, Service: svc, Clock: clk, Logger: testLogger(t), Version: "v0.0.0-test",
	}
	if adjust != nil {
		adjust(&o)
	}
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	// Run closes the audit log; agents that never run must not keep it
	// open past the test (Windows cannot remove an open file).
	t.Cleanup(func() { _ = a.auditFile.Close() })
	return &env{t: t, ca: ca, clk: clk, paths: paths, agent: a}
}

// start runs the agent and waits until it listens and has finished its
// first tick. Cleanup stops it.
func (e *env) start() {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e.stop = cancel
	e.done = make(chan error, 1)
	go func() { e.done <- e.agent.Run(ctx) }()
	select {
	case <-e.agent.Started():
	case err := <-e.done:
		e.t.Fatalf("agent stopped early: %v", err)
	}
	e.clk.waitTimer(e.t) // the main loop's next tick is armed
	e.t.Cleanup(func() {
		if err := e.shutdown(); err != nil {
			e.t.Errorf("Run: %v", err)
		}
	})
}

// shutdown cancels the agent and returns Run's result, forcing the drain
// along on the manual clock if it does not finish by itself. It returns
// nil if the agent has already been shut down.
func (e *env) shutdown() error {
	e.stop()
	for {
		select {
		case err, ok := <-e.done:
			if ok {
				close(e.done)
			}
			return err
		case <-time.After(50 * time.Millisecond):
			e.clk.Advance(DrainTimeout)
		}
	}
}

// dial connects to the agent's gRPC port with a client certificate for cn.
func (e *env) dial(cn string) *grpc.ClientConn {
	e.t.Helper()
	return e.dialTLS(&tls.Config{
		Certificates: []tls.Certificate{e.ca.tlsCert(e.t, clientSpec(cn))},
		RootCAs:      e.ca.pool,
		ServerName:   "localhost",
		Time:         e.clk.Now,
		MinVersion:   tls.VersionTLS13,
	})
}

func (e *env) dialTLS(cfg *tls.Config) *grpc.ClientConn {
	e.t.Helper()
	conn, err := grpc.NewClient("passthrough:///"+e.agent.GRPCAddr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// healthURL returns the URL of a path on the health port.
func (e *env) healthURL(path string) string {
	return "http://" + e.agent.HealthAddr().String() + path
}

func isWindows() bool { return runtime.GOOS == "windows" }

// eventually polls cond until it holds or 10 s pass.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}
