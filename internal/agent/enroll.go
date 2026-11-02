package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/matfax/hvmc/internal/pki"
	"github.com/matfax/hvmc/internal/policy"
)

// Enrollment client (DESIGN §4.6). The wire format is defined by
// internal/pki (enrollwire.go), which the coordinator's handler shares.
//
// Trust: the token must not reach anyone but the coordinator, so the URL
// must be https and redirects are never followed. The endpoint's TLS
// certificate is verified the standard way against the system roots: the
// endpoint is the Ingress or a TLS-terminating load balancer (DESIGN §8),
// never served with an hvmc CA certificate. Independently, nothing in the
// response is used before its CA certificate matches the pinned SHA-256
// fingerprint; the returned leaf must then chain to that CA as a serving
// certificate and carry the agent's own key.

// EnrollOptions configure Enroll.
type EnrollOptions struct {
	// Server is the enrollment URL, e.g. https://hvmc.example.com/v1/enroll.
	Server string
	// Token is the single-use bootstrap token.
	Token string
	// CASHA256 is the SHA-256 fingerprint of the hvmc CA certificate
	// (`hvmc ca export`): 64 hex digits, colons and a "sha256:" prefix
	// allowed.
	CASHA256 string
	// Agent is the agent's name in HostConfig (a DNS-1123 label).
	Agent string
	// Role is host or guest.
	Role Role
	// RootCAs verify the endpoint's TLS certificate; nil means the system
	// roots.
	RootCAs *x509.CertPool
	// Now is the time source for certificate validity; nil means the
	// system clock.
	Now func() time.Time
}

// Enrollment is the verified result of an enrollment.
type Enrollment struct {
	Key    *ecdsa.PrivateKey
	Chain  [][]byte
	Leaf   *x509.Certificate
	CA     *x509.Certificate
	Config Config
	// Policy is the proposed write policy (host role), nil if none.
	Policy *policy.Policy
}

// Classes of refused enrollments, matched with errors.Is on an
// [EnrollError].
var (
	// ErrEnrollMalformed is a 400: the request was not understood.
	ErrEnrollMalformed = errors.New("enrollment request malformed")
	// ErrEnrollToken is a 401: the token is wrong, expired or used.
	ErrEnrollToken = errors.New("bootstrap token refused")
	// ErrEnrollForbidden is a 403: role or certificate not allowed for
	// this agent.
	ErrEnrollForbidden = errors.New("enrollment not allowed for this agent")
	// ErrEnrollUnknownAgent is a 404: no such agent in HostConfig.
	ErrEnrollUnknownAgent = errors.New("agent not declared in HostConfig")
)

// EnrollError is a refusal by the enrollment endpoint.
type EnrollError struct {
	StatusCode int
	// Message is the endpoint's reason (the error field of the body, or
	// the body itself if it is not JSON).
	Message string
}

func (e *EnrollError) Error() string {
	return fmt.Sprintf("enrollment refused: %d %s: %s", e.StatusCode, http.StatusText(e.StatusCode), e.Message)
}

// Unwrap returns the class of the refusal, nil for an unexpected status.
func (e *EnrollError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusBadRequest:
		return ErrEnrollMalformed
	case http.StatusUnauthorized:
		return ErrEnrollToken
	case http.StatusForbidden:
		return ErrEnrollForbidden
	case http.StatusNotFound:
		return ErrEnrollUnknownAgent
	default:
		return nil
	}
}

// ErrCAPinMismatch is returned when the CA in the response does not have
// the pinned fingerprint.
var ErrCAPinMismatch = errors.New("CA certificate does not match --ca-sha256")

// maxEnrollResponse bounds the response body.
const maxEnrollResponse = 1 << 20

// ParseFingerprint normalizes a SHA-256 fingerprint to the form of
// pki.Fingerprint (64 lowercase hex digits). It accepts upper case, colon
// separators and a "sha256:" prefix.
func ParseFingerprint(s string) (string, error) {
	h := strings.ReplaceAll(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "sha256:"), ":", "")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("CA fingerprint %q is not a SHA-256 hex digest", s)
	}
	return h, nil
}

// Enroll generates the agent's key, sends a CSR with the bootstrap token
// and verifies the response against the pinned CA. Nothing is written; see
// [Enrollment.Write].
func Enroll(ctx context.Context, o EnrollOptions) (*Enrollment, error) {
	if o.Now == nil {
		o.Now = SystemClock().Now
	}
	u, pin, err := checkEnrollOptions(o)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: o.Agent},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	resp, err := postEnroll(ctx, o, u, pki.EnrollRequest{
		Agent: o.Agent,
		Role:  string(o.Role),
		CSR:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
	})
	if err != nil {
		return nil, err
	}
	return verifyEnrollment(o, key, pin, resp)
}

func checkEnrollOptions(o EnrollOptions) (*url.URL, string, error) {
	u, err := url.Parse(o.Server)
	if err != nil {
		return nil, "", fmt.Errorf("enrollment URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, "", fmt.Errorf("enrollment URL %q must be an https URL", o.Server)
	}
	if o.Token == "" {
		return nil, "", errors.New("a bootstrap token is required")
	}
	if errs := validation.IsDNS1123Label(o.Agent); len(errs) > 0 {
		return nil, "", fmt.Errorf("agent name %q: %s", o.Agent, strings.Join(errs, "; "))
	}
	if o.Role != RoleHost && o.Role != RoleGuest {
		return nil, "", fmt.Errorf("role %q, want %q or %q", o.Role, RoleHost, RoleGuest)
	}
	pin, err := ParseFingerprint(o.CASHA256)
	if err != nil {
		return nil, "", err
	}
	return u, pin, nil
}

func postEnroll(ctx context.Context, o EnrollOptions, u *url.URL, body pki.EnrollRequest) (*pki.EnrollResponse, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+o.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: enrollTLSConfig(o),
		},
		// Never follow a redirect: it would carry the token elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrollment request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollResponse))
	if err != nil {
		return nil, fmt.Errorf("read enrollment response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &EnrollError{StatusCode: resp.StatusCode, Message: errorMessage(raw)}
	}
	var out pki.EnrollResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode enrollment response: %w", err)
	}
	return &out, nil
}

// errorMessage extracts the reason of a refusal.
func errorMessage(body []byte) string {
	var e pki.EnrollErrorResponse
	if err := json.Unmarshal(body, &e); err == nil && e.Error != "" {
		return e.Error
	}
	return strings.TrimSpace(string(body))
}

// enrollTLSConfig verifies the endpoint with Go's standard verification
// against RootCAs (nil: the system roots).
func enrollTLSConfig(o EnrollOptions) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs, Time: o.Now}
}

// verifyEnrollment checks a response: first the CA against the pin, then
// the chain against that CA and the agent's key, then settings and policy.
func verifyEnrollment(o EnrollOptions, key *ecdsa.PrivateKey, pin string, r *pki.EnrollResponse) (*Enrollment, error) {
	ca, err := pki.ParseCertificatePEM([]byte(r.CACertificate))
	if err != nil {
		return nil, fmt.Errorf("enrollment response: CA certificate: %w", err)
	}
	if got := pki.Fingerprint(ca); got != pin {
		return nil, fmt.Errorf("%w: got sha256:%s", ErrCAPinMismatch, got)
	}
	if !ca.IsCA {
		return nil, errors.New("enrollment response: caCertificate is not a CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	chainDER, err := certificatesPEM([]byte(r.Certificate))
	if err != nil {
		return nil, fmt.Errorf("enrollment response: certificate: %w", err)
	}
	chain, err := verifyServingChain(chainDER, roots, o.Now())
	if err != nil {
		return nil, fmt.Errorf("enrollment response: %w", err)
	}
	if !key.PublicKey.Equal(chain[0].PublicKey) {
		return nil, errors.New("enrollment response: certificate is not for this agent's key")
	}
	cfg := settingsConfig(o, r.Settings)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("enrollment response: settings: %w", err)
	}
	e := &Enrollment{Key: key, Chain: chainDER, Leaf: chain[0], CA: ca, Config: cfg}
	if r.Policy != "" {
		p, err := policy.Parse([]byte(r.Policy))
		if err != nil {
			return nil, fmt.Errorf("enrollment response: %w", err)
		}
		e.Policy = &p
	}
	return e, nil
}

// settingsConfig turns the enrollment settings into agent.yaml settings,
// listening on all IPv4 interfaces.
func settingsConfig(o EnrollOptions, s pki.AgentSettings) Config {
	c := Config{Name: o.Agent, Role: o.Role, AllowedClients: s.AllowedClients}
	if s.Port != 0 {
		c.Listen = net.JoinHostPort("0.0.0.0", strconv.Itoa(int(s.Port)))
	}
	if s.HealthPort != 0 {
		c.Health = net.JoinHostPort("0.0.0.0", strconv.Itoa(int(s.HealthPort)))
	}
	c.applyDefaults()
	return c
}

// certificatesPEM returns the DER of every CERTIFICATE block in data.
func certificatesPEM(data []byte) ([][]byte, error) {
	var out [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return out, nil
}

// Write stores an enrollment: the CA and the serving pair in the state
// directory (replacing earlier ones), the settings merged into agent.yaml
// (other keys, such as an active policy, kept) and, for the host role, the
// proposed policy as pending. The policy is never activated here: the
// operator confirms it with `hvmc agent policy sync` (or during `hvmc
// agent install`). The returned bool reports whether a policy is pending.
func (e *Enrollment) Write(paths Paths) (pending bool, err error) {
	if err := os.MkdirAll(paths.State, 0o700); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(paths.Config), 0o750); err != nil {
		return false, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.CA.Raw})
	if err := writeFileAtomic(paths.CA(), caPEM, 0o600); err != nil {
		return false, err
	}
	serving, err := encodeServing(e.Key, e.Chain)
	if err != nil {
		return false, err
	}
	if err := writeFileAtomic(paths.Serving(), serving, 0o600); err != nil {
		return false, err
	}
	if err := os.Remove(paths.PreviousServing()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := MergeConfigFile(paths.Config, e.Config); err != nil {
		return false, err
	}
	if e.Config.Role != RoleHost || e.Policy == nil {
		return false, nil
	}
	store := OpenPolicyStore(paths, slog.New(slog.DiscardHandler))
	if err := store.Check(context.Background()); err != nil {
		return false, err
	}
	_, pendingDigest, err := store.Propose(*e.Policy)
	if err != nil {
		return false, err
	}
	return pendingDigest != "", nil
}
