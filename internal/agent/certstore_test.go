package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// rotate runs RotateCertificate through conn and signs the CSR with spec.
func rotate(t *testing.T, e *env, client agentv1.CertificateServiceClient, spec leafSpec) (*x509.CertificateRequest, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.RotateCertificate(ctx, &agentv1.RotateCertificateRequest{})
	if err != nil {
		t.Fatalf("RotateCertificate: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(resp.GetCsrDer())
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	return csr, e.ca.issue(t, csr.PublicKey, spec)
}

func install(t *testing.T, client agentv1.CertificateServiceClient, chain ...[]byte) (*agentv1.InstallCertificateResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return client.InstallCertificate(ctx, &agentv1.InstallCertificateRequest{CertificateChainDer: chain})
}

// handshake opens a raw TLS connection to the agent and returns the
// serving certificate it presented, or the client-side error. The TCP
// connection is shut down gracefully (FIN after the TLS alert, then drain),
// never reset, so the server reads a refusal alert on every platform.
func handshake(t *testing.T, e *env, serverName string) (*x509.Certificate, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", e.agent.GRPCAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closeGracefully(raw.(*net.TCPConn))
	tc := tls.Client(raw, &tls.Config{
		Certificates: []tls.Certificate{e.ca.tlsCert(t, clientSpec(CoordinatorClientCN))},
		RootCAs:      e.ca.pool,
		ServerName:   serverName,
		NextProtos:   []string{"h2"},
		Time:         e.clk.Now,
		MinVersion:   tls.VersionTLS13,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	// Read once so the server has processed the client's flight (TLS 1.3
	// completes the client side before the server verified the client).
	_ = tc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = tc.Read(make([]byte, 1))
	return tc.ConnectionState().PeerCertificates[0], nil
}

func closeGracefully(c *net.TCPConn) {
	_ = c.CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, c)
	_ = c.Close()
}

func TestRotationSwapAndConfirm(t *testing.T) {
	e := newEnv(t, guestConfigYAML, nil)
	e.start()
	store := e.agent.Certs()
	old := store.Leaf()
	client := agentv1.NewCertificateServiceClient(e.dial(CoordinatorClientCN))

	csr, der := rotate(t, e, client, serverSpec())
	if csr.Subject.CommonName != old.Subject.CommonName || !cmp.Equal(csr.DNSNames, old.DNSNames) ||
		len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(old.IPAddresses[0]) {
		t.Errorf("CSR subject %v SANs %v %v, want those of the current certificate", csr.Subject, csr.DNSNames, csr.IPAddresses)
	}
	resp, err := install(t, client, der)
	if err != nil {
		t.Fatalf("InstallCertificate: %v", err)
	}
	newLeaf := store.Leaf()
	if !resp.GetNotAfter().AsTime().Equal(newLeaf.NotAfter) || newLeaf.SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Fatalf("installed leaf %v (NotAfter %v), response NotAfter %v", newLeaf.SerialNumber, newLeaf.NotAfter, resp.GetNotAfter().AsTime())
	}
	if !store.Unconfirmed() || !fileExists(t, e.paths.PreviousServing()) {
		t.Fatal("previous pair not kept after install")
	}

	// A restart before confirmation keeps both pairs.
	reopened, err := OpenCertStore(e.paths, e.clk, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Unconfirmed() || reopened.Leaf().SerialNumber.Cmp(newLeaf.SerialNumber) != 0 {
		t.Error("reopened store lost the unconfirmed state")
	}

	served, err := handshake(t, e, "localhost")
	if err != nil {
		t.Fatalf("handshake with the new certificate: %v", err)
	}
	if served.SerialNumber.Cmp(newLeaf.SerialNumber) != 0 {
		t.Errorf("new connection served serial %v, want %v", served.SerialNumber, newLeaf.SerialNumber)
	}
	eventually(t, "confirmation", func() bool { return !store.Unconfirmed() })
	if fileExists(t, e.paths.PreviousServing()) {
		t.Error("previous pair still on disk after confirmation")
	}
}

func TestRotationRollbackWhenClientRefuses(t *testing.T) {
	e := newEnv(t, guestConfigYAML, nil)
	e.start()
	store := e.agent.Certs()
	old := store.Leaf()
	client := agentv1.NewCertificateServiceClient(e.dial(CoordinatorClientCN))

	// The coordinator signs a certificate the clients cannot use: it names
	// another host.
	bad := serverSpec("elsewhere.example.com")
	bad.ips = nil
	_, der := rotate(t, e, client, bad)
	if _, err := install(t, client, der); err != nil {
		t.Fatalf("InstallCertificate: %v", err)
	}
	if _, err := handshake(t, e, "localhost"); err == nil {
		t.Fatal("client accepted a certificate for another host")
	}
	eventually(t, "rollback", func() bool { return store.Leaf().SerialNumber.Cmp(old.SerialNumber) == 0 })
	if store.Unconfirmed() || fileExists(t, e.paths.PreviousServing()) {
		t.Error("previous pair still kept after rollback")
	}
	onDisk, err := loadServing(e.paths.Serving())
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.leaf().SerialNumber.Cmp(old.SerialNumber) != 0 {
		t.Error("serving.pem was not rolled back")
	}
	if _, err := handshake(t, e, "localhost"); err != nil {
		t.Errorf("handshake after rollback: %v", err)
	}
}

func TestRotationTwiceKeepsLastConfirmed(t *testing.T) {
	e := newEnv(t, guestConfigYAML, nil)
	e.start()
	store := e.agent.Certs()
	old := store.Leaf()
	client := agentv1.NewCertificateServiceClient(e.dial(CoordinatorClientCN))
	for range 2 {
		_, der := rotate(t, e, client, serverSpec())
		if _, err := install(t, client, der); err != nil {
			t.Fatal(err)
		}
	}
	prev, err := loadServing(e.paths.PreviousServing())
	if err != nil {
		t.Fatal(err)
	}
	if prev.leaf().SerialNumber.Cmp(old.SerialNumber) != 0 {
		t.Error("a second unconfirmed install replaced the last confirmed pair")
	}
}

func TestInstallErrors(t *testing.T) {
	e := newEnv(t, guestConfigYAML, nil)
	e.start()
	client := agentv1.NewCertificateServiceClient(e.dial(CoordinatorClientCN))
	key := newKey(t)

	if _, err := install(t, client, e.ca.issue(t, &key.PublicKey, serverSpec())); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("install without pending key: %v, want FailedPrecondition", err)
	}
	csr, _ := rotate(t, e, client, serverSpec())
	other := newTestCA(t)
	expired := serverSpec()
	expired.notBefore, expired.notAfter = t0.Add(-48*time.Hour), t0.Add(-time.Hour)
	for name, tc := range map[string]struct {
		chain [][]byte
		want  codes.Code
	}{
		"empty chain":     {nil, codes.InvalidArgument},
		"garbage":         {[][]byte{[]byte("not DER")}, codes.InvalidArgument},
		"client cert":     {[][]byte{e.ca.issue(t, csr.PublicKey, clientSpec("agent"))}, codes.InvalidArgument},
		"foreign CA":      {[][]byte{other.issue(t, csr.PublicKey, serverSpec())}, codes.InvalidArgument},
		"expired":         {[][]byte{e.ca.issue(t, csr.PublicKey, expired)}, codes.InvalidArgument},
		"not pending key": {[][]byte{e.ca.issue(t, &key.PublicKey, serverSpec())}, codes.FailedPrecondition},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := install(t, client, tc.chain...); status.Code(err) != tc.want {
				t.Errorf("install: %v, want %v", err, tc.want)
			}
		})
	}
	if e.agent.Certs().Unconfirmed() {
		t.Error("a failed install changed the serving pair")
	}
}

// rotateDirect runs RotateCertificate on the store and signs the CSR.
func rotateDirect(t *testing.T, store *CertStore, ca *testCA) []byte {
	t.Helper()
	resp, err := store.RotateCertificate(context.Background(), &agentv1.RotateCertificateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(resp.GetCsrDer())
	if err != nil {
		t.Fatal(err)
	}
	return ca.issue(t, csr.PublicKey, serverSpec())
}

func installDirect(store *CertStore, der []byte) error {
	_, err := store.InstallCertificate(context.Background(), &agentv1.InstallCertificateRequest{CertificateChainDer: [][]byte{der}})
	return err
}

func TestInstallStorageFailureKeepsCurrent(t *testing.T) {
	// Fail the first rename (current → previous) or the second (new →
	// current).
	for _, failOn := range []int{1, 2} {
		t.Run(fmt.Sprintf("rename %d", failOn), func(t *testing.T) { testInstallStorageFailure(t, failOn) })
	}
}

func testInstallStorageFailure(t *testing.T, failOn int) {
	ca := newTestCA(t)
	paths := writeState(t, ca, ca.tlsCert(t, serverSpec()), guestConfigYAML)
	store, err := OpenCertStore(paths, newTestClock(), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	old := store.Leaf()
	renames := 0
	store.fs.rename = func(from, to string) error {
		renames++
		if renames == failOn {
			return &fs.PathError{Op: "rename", Path: from, Err: fs.ErrPermission}
		}
		return os.Rename(from, to)
	}
	if err := installDirect(store, rotateDirect(t, store, ca)); status.Code(err) != codes.Internal {
		t.Fatalf("install with a failing rename: %v, want Internal", err)
	}
	if store.Leaf().SerialNumber.Cmp(old.SerialNumber) != 0 || store.Unconfirmed() {
		t.Error("current pair changed after a failed install")
	}
	onDisk, err := loadServing(paths.Serving())
	if err != nil || onDisk.leaf().SerialNumber.Cmp(old.SerialNumber) != 0 {
		t.Errorf("serving.pem after a failed install: %v", err)
	}
	for _, p := range []string{paths.PreviousServing(), paths.Serving() + ".new"} {
		if fileExists(t, p) {
			t.Errorf("%s left behind", p)
		}
	}
}

func TestRollbackKeepsNewWhenPreviousExpired(t *testing.T) {
	ca := newTestCA(t)
	clk := newTestClock()
	shortSpec := serverSpec()
	shortSpec.notAfter = t0.Add(time.Hour)
	paths := writeState(t, ca, ca.tlsCert(t, shortSpec), guestConfigYAML)
	store, err := OpenCertStore(paths, clk, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := installDirect(store, rotateDirect(t, store, ca)); err != nil {
		t.Fatal(err)
	}
	installed := store.Leaf()
	clk.Advance(2 * time.Hour)
	alert := &net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}
	store.handshakeDone(store.current, alert)
	if store.Leaf() != installed {
		t.Error("rolled back to an expired certificate")
	}
	// Local failures (no client certificate, EOF) never roll back.
	store.handshakeDone(store.current, errors.New("tls: client didn't provide a certificate"))
	if store.Leaf() != installed || !store.Unconfirmed() {
		t.Error("a local handshake failure changed the pair")
	}
}

func TestOpenCertStoreAfterCrashBetweenRenames(t *testing.T) {
	ca := newTestCA(t)
	paths := writeState(t, ca, ca.tlsCert(t, serverSpec()), guestConfigYAML)
	if err := os.Rename(paths.Serving(), paths.PreviousServing()); err != nil {
		t.Fatal(err)
	}
	s, err := OpenCertStore(paths, newTestClock(), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.Unconfirmed() || !fileExists(t, paths.Serving()) || fileExists(t, paths.PreviousServing()) {
		t.Error("previous pair not restored as current")
	}
}

func TestOpenCertStoreNotEnrolled(t *testing.T) {
	ca := newTestCA(t)
	paths := writeState(t, ca, ca.tlsCert(t, serverSpec()), guestConfigYAML)
	if err := os.Remove(paths.Serving()); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCertStore(paths, newTestClock(), testLogger(t)); !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("without serving.pem: %v", err)
	}
	if err := os.Remove(paths.CA()); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCertStore(paths, newTestClock(), testLogger(t)); !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("without ca.crt: %v", err)
	}
}

func TestOpenCertStoreBadCA(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.tlsCert(t, serverSpec())
	paths := writeState(t, ca, leaf, guestConfigYAML)
	for name, data := range map[string][]byte{
		"leaf as CA": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}),
		"garbage":    []byte("garbage"),
	} {
		writeTestFile(t, paths.CA(), data)
		if _, err := OpenCertStore(paths, newTestClock(), testLogger(t)); err == nil || errors.Is(err, ErrNotEnrolled) {
			t.Errorf("%s: %v, want an error", name, err)
		}
	}
}

func TestCertCheck(t *testing.T) {
	ca := newTestCA(t)
	clk := newTestClock()
	paths := writeState(t, ca, ca.tlsCert(t, serverSpec()), guestConfigYAML)
	s, err := OpenCertStore(paths, clk, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Check(context.Background()); err != nil {
		t.Errorf("fresh certificate: %v", err)
	}
	clk.Set(t0.Add(30*24*time.Hour - CertMinValidity))
	if err := s.Check(context.Background()); err == nil {
		t.Error("certificate expiring in 72 h passes the check")
	}
}
