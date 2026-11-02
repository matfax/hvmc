package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/matfax/hvmc/internal/pki"
	"github.com/matfax/hvmc/internal/policy"
)

const testToken = "abcdef.0123456789abcdef"

// enrollServer is a stand-in for the coordinator's /v1/enroll handler.
type enrollServer struct {
	t   *testing.T
	ca  *testCA
	srv *httptest.Server

	mu      sync.Mutex
	got     pki.EnrollRequest
	headers http.Header
	// respond overrides the response; nil signs the CSR.
	respond func(w http.ResponseWriter, csr *x509.CertificateRequest)
	policy  string
}

func newEnrollServer(t *testing.T) *enrollServer {
	t.Helper()
	ca := newTestCA(t)
	es := &enrollServer{t: t, ca: ca}
	es.srv = httptest.NewUnstartedServer(http.HandlerFunc(es.handle))
	// The endpoint's certificate is issued by the hvmc CA and the chain
	// carries the CA, so only the pin makes it trusted.
	cert := ca.tlsCert(t, serverSpec())
	cert.Certificate = append(cert.Certificate, ca.cert.Raw)
	es.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	es.srv.StartTLS()
	t.Cleanup(es.srv.Close)
	return es
}

func (es *enrollServer) handle(w http.ResponseWriter, r *http.Request) {
	var req pki.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnrollError(w, http.StatusBadRequest, "body: "+err.Error())
		return
	}
	es.mu.Lock()
	es.got, es.headers = req, r.Header.Clone()
	respond, pol := es.respond, es.policy
	es.mu.Unlock()
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		writeEnrollError(w, http.StatusBadRequest, "csr is not PEM")
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		writeEnrollError(w, http.StatusBadRequest, "bad csr")
		return
	}
	if respond != nil {
		respond(w, csr)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		writeEnrollError(w, http.StatusUnauthorized, "token refused")
		return
	}
	es.writeResponse(w, es.ca, es.ca.issue(es.t, csr.PublicKey, serverSpec(req.Agent+".example.com")), pol)
}

func (es *enrollServer) writeResponse(w http.ResponseWriter, ca *testCA, leaf []byte, pol string) {
	resp := pki.EnrollResponse{
		Certificate:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})),
		CACertificate: string(pki.EncodeCertificatePEM(ca.cert)),
		Settings:      pki.AgentSettings{Port: 9443, HealthPort: 9090, AllowedClients: []string{pki.CoordinatorCommonName}},
		Policy:        pol,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeEnrollError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(pki.EnrollErrorResponse{Error: msg})
}

// checkRequest checks the last request's body and headers.
func (es *enrollServer) checkRequest(agent, role string) {
	es.t.Helper()
	es.mu.Lock()
	got, headers := es.got, es.headers
	es.mu.Unlock()
	if got.Agent != agent || got.Role != role {
		es.t.Errorf("request agent %q role %q, want %q %q", got.Agent, got.Role, agent, role)
	}
	if headers.Get("Authorization") != "Bearer "+testToken || headers.Get("Content-Type") != "application/json" {
		es.t.Errorf("request headers %v", headers)
	}
}

func (es *enrollServer) options(agent string, role Role) EnrollOptions {
	return EnrollOptions{
		Server: es.srv.URL + pki.EnrollPath, Token: testToken, CASHA256: pki.Fingerprint(es.ca.cert),
		Agent: agent, Role: role, Now: newTestClock().Now,
		// The test endpoint's certificate comes from the test CA, which
		// stands in for an Ingress certificate trusted by the system roots.
		RootCAs: es.ca.pool,
	}
}

func enroll(t *testing.T, o EnrollOptions) (*Enrollment, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Enroll(ctx, o)
}

func TestEnrollHost(t *testing.T) {
	es := newEnrollServer(t)
	pol := policy.Policy{VMs: []policy.VM{{Name: "windows-node-1", Min: 6 << 30, Max: 24 << 30}}}
	es.policy = string(pol.Canonical())

	e, err := enroll(t, es.options("host", RoleHost))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	es.checkRequest("host", pki.EnrollRoleHost)
	if !e.Key.PublicKey.Equal(e.Leaf.PublicKey) || pki.Fingerprint(e.CA) != pki.Fingerprint(es.ca.cert) {
		t.Error("enrollment does not hold the agent's key and the pinned CA")
	}
	want := Config{Name: "host", Role: RoleHost, Listen: "0.0.0.0:9443", Health: "0.0.0.0:9090", AllowedClients: []string{"hvmc-coordinator"}}
	if diff := cmp.Diff(want, e.Config); diff != "" {
		t.Errorf("settings (-want +got):\n%s", diff)
	}
	if e.Policy == nil || e.Policy.Digest() != pol.Digest() {
		t.Fatalf("policy %v, want %v", e.Policy, pol)
	}

	checkWrittenHost(t, e, want, pol)
}

// checkWrittenHost writes a host enrollment and checks that the agent can
// load it, with the proposed policy pending and the empty policy active.
func checkWrittenHost(t *testing.T, e *Enrollment, want Config, pol policy.Policy) {
	t.Helper()
	dir := t.TempDir()
	paths := Paths{Config: filepath.Join(dir, "etc", "agent.yaml"), State: filepath.Join(dir, "state")}
	pending, err := e.Write(paths)
	if err != nil || !pending {
		t.Fatalf("Write: pending %v, %v", pending, err)
	}
	store, err := OpenCertStore(paths, newTestClock(), testLogger(t))
	if err != nil {
		t.Fatalf("written state does not load: %v", err)
	}
	if store.Leaf().SerialNumber.Cmp(e.Leaf.SerialNumber) != 0 {
		t.Error("written serving certificate differs")
	}
	cfg, err := LoadConfig(paths.Config)
	if err != nil || cmp.Diff(want, cfg) != "" {
		t.Errorf("written config %+v, %v", cfg, err)
	}
	ps := OpenPolicyStore(paths, testLogger(t))
	if got, ok := ps.Pending(); !ok || got.Digest() != pol.Digest() {
		t.Error("enrolled policy is not pending")
	}
	if len(ps.Active().VMs) != 0 || ps.Check(context.Background()) != nil {
		t.Errorf("active policy after enrollment %v, want the empty, valid policy", ps.Active())
	}
}

func TestEnrollGuest(t *testing.T) {
	es := newEnrollServer(t)
	e, err := enroll(t, es.options("docker-host-1", RoleGuest))
	if err != nil {
		t.Fatal(err)
	}
	if e.Policy != nil || e.Config.Role != RoleGuest {
		t.Errorf("guest enrollment: role %q policy %v", e.Config.Role, e.Policy)
	}
	paths := Paths{Config: filepath.Join(t.TempDir(), "agent.yaml"), State: t.TempDir()}
	if pending, err := e.Write(paths); err != nil || pending {
		t.Errorf("Write: pending %v, %v", pending, err)
	}
}

func TestEnrollRefusals(t *testing.T) {
	for _, tc := range []struct {
		code int
		want error
	}{
		{http.StatusBadRequest, ErrEnrollMalformed},
		{http.StatusUnauthorized, ErrEnrollToken},
		{http.StatusForbidden, ErrEnrollForbidden},
		{http.StatusNotFound, ErrEnrollUnknownAgent},
	} {
		t.Run(http.StatusText(tc.code), func(t *testing.T) {
			es := newEnrollServer(t)
			es.respond = func(w http.ResponseWriter, _ *x509.CertificateRequest) {
				writeEnrollError(w, tc.code, "reason for "+http.StatusText(tc.code))
			}
			_, err := enroll(t, es.options("host", RoleHost))
			var ee *EnrollError
			if !errors.Is(err, tc.want) || !errors.As(err, &ee) || ee.StatusCode != tc.code {
				t.Fatalf("Enroll: %v, want %v", err, tc.want)
			}
			if ee.Message != "reason for "+http.StatusText(tc.code) {
				t.Errorf("message %q", ee.Message)
			}
		})
	}
	t.Run("wrong token", func(t *testing.T) {
		es := newEnrollServer(t)
		o := es.options("host", RoleHost)
		o.Token = "wrong"
		if _, err := enroll(t, o); !errors.Is(err, ErrEnrollToken) {
			t.Errorf("Enroll with a wrong token: %v", err)
		}
	})
	t.Run("plain-text error and redirect", func(t *testing.T) {
		es := newEnrollServer(t)
		es.respond = func(w http.ResponseWriter, _ *x509.CertificateRequest) {
			w.Header().Set("Location", "https://elsewhere.example.com/")
			http.Error(w, "moved", http.StatusTemporaryRedirect)
		}
		_, err := enroll(t, es.options("host", RoleHost))
		var ee *EnrollError
		if !errors.As(err, &ee) || ee.StatusCode != http.StatusTemporaryRedirect || ee.Message != "moved" || errors.Unwrap(ee) != nil {
			t.Errorf("redirect: %v", err)
		}
	})
}

func TestEnrollVerifiesResponse(t *testing.T) {
	other := newTestCA(t)
	for name, tc := range map[string]struct {
		respond func(es *enrollServer, w http.ResponseWriter, csr *x509.CertificateRequest)
		want    string
	}{
		"CA fingerprint mismatch": {
			func(es *enrollServer, w http.ResponseWriter, csr *x509.CertificateRequest) {
				es.writeResponse(w, other, other.issue(es.t, csr.PublicKey, serverSpec()), "")
			}, "does not match --ca-sha256",
		},
		"leaf for another key": {
			func(es *enrollServer, w http.ResponseWriter, _ *x509.CertificateRequest) {
				es.writeResponse(w, es.ca, es.ca.issue(es.t, &newKey(es.t).PublicKey, serverSpec()), "")
			}, "not for this agent's key",
		},
		"leaf from another CA": {
			func(es *enrollServer, w http.ResponseWriter, csr *x509.CertificateRequest) {
				es.writeResponse(w, es.ca, other.issue(es.t, csr.PublicKey, serverSpec()), "")
			}, "does not verify",
		},
		"client certificate": {
			func(es *enrollServer, w http.ResponseWriter, csr *x509.CertificateRequest) {
				es.writeResponse(w, es.ca, es.ca.issue(es.t, csr.PublicKey, clientSpec("host")), "")
			}, "not a serving certificate",
		},
		"invalid policy": {
			func(es *enrollServer, w http.ResponseWriter, csr *x509.CertificateRequest) {
				es.writeResponse(w, es.ca, es.ca.issue(es.t, csr.PublicKey, serverSpec()), "vms: [{name: x}]")
			}, "invalid policy",
		},
		"not JSON": {
			func(_ *enrollServer, w http.ResponseWriter, _ *x509.CertificateRequest) {
				_, _ = w.Write([]byte("<html>"))
			}, "decode enrollment response",
		},
	} {
		t.Run(name, func(t *testing.T) {
			es := newEnrollServer(t)
			es.respond = func(w http.ResponseWriter, csr *x509.CertificateRequest) { tc.respond(es, w, csr) }
			_, err := enroll(t, es.options("host", RoleHost))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Enroll: %v, want an error containing %q", err, tc.want)
			}
			if name == "CA fingerprint mismatch" && !errors.Is(err, ErrCAPinMismatch) {
				t.Errorf("Enroll: %v, want ErrCAPinMismatch", err)
			}
		})
	}
}

func TestEnrollEndpointTrust(t *testing.T) {
	es := newEnrollServer(t)
	other := newTestCA(t)

	// An endpoint the roots do not trust is refused, even when its
	// certificate comes from the pinned CA: the token is never sent.
	o := es.options("host", RoleHost)
	o.RootCAs = other.pool
	var unknown x509.UnknownAuthorityError
	if _, err := enroll(t, o); !errors.As(err, &unknown) {
		t.Errorf("untrusted endpoint: %v, want x509.UnknownAuthorityError", err)
	}
	es.mu.Lock()
	sent := es.headers
	es.mu.Unlock()
	if sent != nil {
		t.Error("the request reached an untrusted endpoint")
	}

	// Trusted through the roots (an Ingress certificate), the response's
	// CA must still match the pin.
	o.RootCAs = es.ca.pool
	o.CASHA256 = pki.Fingerprint(other.cert)
	if _, err := enroll(t, o); !errors.Is(err, ErrCAPinMismatch) {
		t.Errorf("trusted endpoint, wrong pin: %v, want ErrCAPinMismatch", err)
	}
}

func TestEnrollOptionErrors(t *testing.T) {
	es := newEnrollServer(t)
	for name, mutate := range map[string]func(*EnrollOptions){
		"http URL":        func(o *EnrollOptions) { o.Server = strings.Replace(o.Server, "https://", "http://", 1) },
		"no token":        func(o *EnrollOptions) { o.Token = "" },
		"bad fingerprint": func(o *EnrollOptions) { o.CASHA256 = "abc" },
		"bad agent name":  func(o *EnrollOptions) { o.Agent = "Host_1" },
		"bad role":        func(o *EnrollOptions) { o.Role = "coordinator" },
	} {
		t.Run(name, func(t *testing.T) {
			o := es.options("host", RoleHost)
			mutate(&o)
			if _, err := enroll(t, o); err == nil {
				t.Error("Enroll accepted the options")
			}
		})
	}
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.headers != nil {
		t.Error("invalid options still sent a request")
	}
}

func TestParseFingerprint(t *testing.T) {
	ca := newTestCA(t)
	fp := pki.Fingerprint(ca.cert)
	var colons []string
	for i := 0; i < len(fp); i += 2 {
		colons = append(colons, strings.ToUpper(fp[i:i+2]))
	}
	for _, in := range []string{fp, strings.ToUpper(fp), "sha256:" + fp, strings.Join(colons, ":"), " " + fp + "\n"} {
		if got, err := ParseFingerprint(in); err != nil || got != fp {
			t.Errorf("ParseFingerprint(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "zz", fp[:62], fp + "00"} {
		if _, err := ParseFingerprint(in); err == nil {
			t.Errorf("ParseFingerprint(%q) accepted", in)
		}
	}
}
