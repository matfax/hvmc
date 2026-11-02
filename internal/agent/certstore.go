package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// CertMinValidity is how long the serving certificate must stay valid for
// the agent to report ready (DESIGN §4.8).
const CertMinValidity = 72 * time.Hour

// CertStore holds the agent's serving key pair and the hvmc CA, serves the
// pair to TLS handshakes and implements CertificateService (DESIGN §4.6).
//
// Rotation: RotateCertificate creates a new key, kept in memory as pending,
// and returns a CSR with the subject and SANs of the current certificate.
// InstallCertificate checks the signed chain against the CA and the pending
// key and swaps the pair for new connections. The previous pair is kept, in
// memory and as serving.previous.pem, until the first successful handshake
// with the new one confirms it. If a client instead refuses the new
// certificate during a handshake (it sends a TLS alert), the store rolls
// back to the previous pair, provided that one is still valid. A failure
// while storing a new pair restores the files and leaves the current pair
// active.
type CertStore struct {
	agentv1.UnimplementedCertificateServiceServer

	paths Paths
	clk   Clock
	log   *slog.Logger
	ca    *x509.Certificate
	roots *x509.CertPool
	fs    fileOps

	mu       sync.Mutex
	current  *servingPair
	previous *servingPair // last confirmed pair while current is unconfirmed
	pending  *ecdsa.PrivateKey

	// conns maps a raw connection to the pair its handshake was offered,
	// from GetCertificate until the handshake ends.
	conns sync.Map
}

// servingPair is one key pair with its parsed leaf.
type servingPair struct {
	cert tls.Certificate
}

func (p *servingPair) leaf() *x509.Certificate { return p.cert.Leaf }

// fileOps are the file operations of an install, replaceable in tests to
// inject storage failures.
type fileOps struct {
	write  func(path string, data []byte, perm fs.FileMode) error
	rename func(from, to string) error
	remove func(path string) error
}

func osFileOps() fileOps {
	return fileOps{write: writeFileAtomic, rename: os.Rename, remove: os.Remove}
}

// ErrNotEnrolled is returned by [OpenCertStore] when the state directory
// holds no CA or serving certificate: the agent has to be enrolled first.
var ErrNotEnrolled = errors.New("agent is not enrolled (run `hvmc agent enroll`)")

// OpenCertStore loads the CA and the serving pair from the state directory.
// A serving.previous.pem left by an unconfirmed install is loaded as the
// previous pair; if serving.pem itself is missing (a crash between the two
// renames of an install) the previous pair becomes current again.
func OpenCertStore(paths Paths, clk Clock, log *slog.Logger) (*CertStore, error) {
	ca, err := loadCA(paths.CA())
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	s := &CertStore{paths: paths, clk: clk, log: log, ca: ca, roots: roots, fs: osFileOps()}
	cur, curErr := loadServing(paths.Serving())
	prev, prevErr := loadServing(paths.PreviousServing())
	switch {
	case curErr == nil:
		s.current = cur
		if prevErr == nil {
			s.previous = prev
		}
	case errors.Is(curErr, fs.ErrNotExist) && prevErr == nil:
		if err := os.Rename(paths.PreviousServing(), paths.Serving()); err != nil {
			return nil, fmt.Errorf("restore previous serving pair: %w", err)
		}
		s.current = prev
	case errors.Is(curErr, fs.ErrNotExist):
		return nil, fmt.Errorf("%w: %s missing", ErrNotEnrolled, paths.Serving())
	default:
		return nil, curErr
	}
	return s, nil
}

func loadCA(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the agent's own state file.
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s missing", ErrNotEnrolled, path)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate", path)
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if !ca.IsCA {
		return nil, fmt.Errorf("%s: not a CA certificate", path)
	}
	return ca, nil
}

func loadServing(path string) (*servingPair, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the agent's own state file.
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return &servingPair{cert: cert}, nil
}

// encodeServing returns the PEM file of a serving pair: the PKCS #8 key,
// then the chain, leaf first.
func encodeServing(key crypto.Signer, chainDER [][]byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, c := range chainDER {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	return out, nil
}

// CA returns the hvmc CA certificate.
func (s *CertStore) CA() *x509.Certificate { return s.ca }

// Leaf returns the leaf of the current serving pair.
func (s *CertStore) Leaf() *x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current.leaf()
}

// Unconfirmed reports whether the current pair still waits for its first
// successful handshake (a previous pair is kept for rollback).
func (s *CertStore) Unconfirmed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.previous != nil
}

// Check is the readiness check "serving cert valid for > 72 h".
func (s *CertStore) Check(context.Context) error {
	leaf := s.Leaf()
	now := s.clk.Now()
	switch {
	case now.Before(leaf.NotBefore):
		return fmt.Errorf("serving certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case leaf.NotAfter.Sub(now) <= CertMinValidity:
		return fmt.Errorf("serving certificate expires at %s, less than %s from now",
			leaf.NotAfter.UTC().Format(time.RFC3339), CertMinValidity)
	}
	return nil
}

// ServerTLSConfig returns the TLS configuration of the gRPC port: TLS 1.3,
// client certificates required and verified against the hvmc CA, the
// serving pair taken from the store on every handshake. The client CN is
// checked per call against allowedClients (UNAUTHENTICATED, see the
// interceptors in server.go), not in the handshake.
func (s *CertStore) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		Time:           s.clk.Now,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      s.roots,
		GetCertificate: s.getCertificate,
	}
}

// TransportCredentials returns gRPC server credentials for
// ServerTLSConfig that report every handshake's outcome to the store, which
// confirms or rolls back a newly installed pair.
func (s *CertStore) TransportCredentials() credentials.TransportCredentials {
	return &rotatingCreds{TransportCredentials: credentials.NewTLS(s.ServerTLSConfig()), store: s}
}

func (s *CertStore) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	p := s.current
	s.mu.Unlock()
	if hello.Conn != nil {
		s.conns.Store(hello.Conn, p)
	}
	return &p.cert, nil
}

// rotatingCreds wraps the gRPC TLS credentials to observe handshakes.
type rotatingCreds struct {
	credentials.TransportCredentials
	store *CertStore
}

func (c *rotatingCreds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ServerHandshake(raw)
	if v, ok := c.store.conns.LoadAndDelete(raw); ok {
		c.store.handshakeDone(v.(*servingPair), err)
	}
	return conn, info, err
}

func (c *rotatingCreds) Clone() credentials.TransportCredentials {
	return &rotatingCreds{TransportCredentials: c.TransportCredentials.Clone(), store: c.store}
}

// handshakeDone confirms an unconfirmed pair after a successful handshake
// and rolls it back when the client refused it.
func (s *CertStore) handshakeDone(p *servingPair, err error) {
	switch {
	case err == nil:
		s.confirm(p)
	case isRemoteAlert(err):
		s.rollback(p, err)
	}
}

// isRemoteAlert reports whether a handshake failed because the peer sent a
// TLS alert, i.e. the client refused the server's certificate. Local
// failures (no or bad client certificate, timeouts, EOF) do not count.
func isRemoteAlert(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "remote error"
}

func (s *CertStore) confirm(p *servingPair) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p != s.current || s.previous == nil {
		return
	}
	if err := s.fs.remove(s.paths.PreviousServing()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Warn("removing the previous serving pair failed", "error", err)
	}
	s.previous = nil
	s.log.Info("new serving certificate confirmed by a successful handshake",
		"serial", p.leaf().SerialNumber.String(), "notAfter", p.leaf().NotAfter)
}

func (s *CertStore) rollback(p *servingPair, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p != s.current || s.previous == nil {
		return
	}
	prev := s.previous
	if !s.clk.Now().Before(prev.leaf().NotAfter) {
		s.log.Warn("client refused the new serving certificate; previous one has expired, keeping the new one",
			"error", cause)
		return
	}
	if err := s.fs.rename(s.paths.PreviousServing(), s.paths.Serving()); err != nil {
		s.log.Error("rolling back the serving certificate failed", "error", err)
		return
	}
	s.current, s.previous = prev, nil
	s.log.Warn("client refused the new serving certificate; rolled back to the previous one",
		"error", cause, "serial", prev.leaf().SerialNumber.String())
}

// certSummary is the audit view of the store.
type certSummary struct {
	Serial     string    `json:"serial"`
	NotAfter   time.Time `json:"notAfter"`
	PendingKey bool      `json:"pendingKey"`
	Previous   string    `json:"previousSerial,omitempty"`
}

func (s *CertStore) summaryLocked() certSummary {
	out := certSummary{
		Serial:     s.current.leaf().SerialNumber.String(),
		NotAfter:   s.current.leaf().NotAfter.UTC(),
		PendingKey: s.pending != nil,
	}
	if s.previous != nil {
		out.Previous = s.previous.leaf().SerialNumber.String()
	}
	return out
}

func (s *CertStore) summary() certSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.summaryLocked()
}

// RotateCertificate implements agentv1.CertificateServiceServer.
func (s *CertStore) RotateCertificate(ctx context.Context, _ *agentv1.RotateCertificateRequest) (*agentv1.RotateCertificateResponse, error) {
	SetAuditBefore(ctx, s.summary())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate key: %v", err)
	}
	leaf := s.Leaf()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     leaf.Subject,
		DNSNames:    leaf.DNSNames,
		IPAddresses: leaf.IPAddresses,
		URIs:        leaf.URIs,
	}, key)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create CSR: %v", err)
	}
	s.mu.Lock()
	s.pending = key
	after := s.summaryLocked()
	s.mu.Unlock()
	SetAuditAfter(ctx, after)
	return &agentv1.RotateCertificateResponse{CsrDer: csr}, nil
}

// InstallCertificate implements agentv1.CertificateServiceServer.
func (s *CertStore) InstallCertificate(ctx context.Context, req *agentv1.InstallCertificateRequest) (*agentv1.InstallCertificateResponse, error) {
	SetAuditBefore(ctx, s.summary())
	chainDER := req.GetCertificateChainDer()
	chain, err := verifyServingChain(chainDER, s.roots, s.clk.Now())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return nil, status.Error(codes.FailedPrecondition, "no pending key; call RotateCertificate first")
	}
	if !s.pending.PublicKey.Equal(chain[0].PublicKey) {
		return nil, status.Error(codes.FailedPrecondition, "leaf public key is not the pending key")
	}
	pair := &servingPair{cert: tls.Certificate{Certificate: slices.Clone(chainDER), PrivateKey: s.pending, Leaf: chain[0]}}
	if err := s.storeLocked(pair); err != nil {
		s.log.Error("storing the new serving pair failed; the current pair stays active", "error", err)
		return nil, status.Errorf(codes.Internal, "storing the certificate failed; the current pair stays active: %v", err)
	}
	if s.previous == nil {
		s.previous = s.current
	}
	s.current, s.pending = pair, nil
	SetAuditAfter(ctx, s.summaryLocked())
	s.log.Info("new serving certificate installed; previous pair kept until the next successful handshake",
		"serial", chain[0].SerialNumber.String(), "notAfter", chain[0].NotAfter)
	return &agentv1.InstallCertificateResponse{NotAfter: timestamppb.New(chain[0].NotAfter)}, nil
}

// verifyServingChain parses a DER chain and verifies it against roots as
// a serving certificate at now.
func verifyServingChain(chainDER [][]byte, roots *x509.CertPool, now time.Time) ([]*x509.Certificate, error) {
	if len(chainDER) == 0 {
		return nil, status.Error(codes.InvalidArgument, "certificate chain is empty")
	}
	chain := make([]*x509.Certificate, 0, len(chainDER))
	for _, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parse certificate: %v", err)
		}
		chain = append(chain, c)
	}
	if !slices.Contains(chain[0].ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return nil, status.Error(codes.InvalidArgument, "leaf is not a serving certificate (no serverAuth usage)")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "chain does not verify against the hvmc CA: %v", err)
	}
	return chain, nil
}

// storeLocked writes pair as serving.pem. A confirmed current pair is
// moved to serving.previous.pem first; an unconfirmed one is simply
// replaced, so the previous file always holds the last confirmed pair. On
// any failure the files are restored.
func (s *CertStore) storeLocked(pair *servingPair) error {
	data, err := encodeServing(pair.cert.PrivateKey.(crypto.Signer), pair.cert.Certificate)
	if err != nil {
		return err
	}
	serving, previous := s.paths.Serving(), s.paths.PreviousServing()
	tmp := serving + ".new"
	if err := s.fs.write(tmp, data, 0o600); err != nil {
		return err
	}
	keepCurrent := s.previous == nil
	if keepCurrent {
		if err := s.fs.rename(serving, previous); err != nil {
			_ = s.fs.remove(tmp)
			return err
		}
	}
	if err := s.fs.rename(tmp, serving); err != nil {
		if keepCurrent {
			if rerr := s.fs.rename(previous, serving); rerr != nil {
				err = errors.Join(err, fmt.Errorf("restore: %w", rerr))
			}
		}
		_ = s.fs.remove(tmp)
		return err
	}
	return nil
}
