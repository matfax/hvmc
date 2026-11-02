package cli

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matfax/hvmc/internal/agent"
	"github.com/matfax/hvmc/internal/pki"
	"github.com/matfax/hvmc/internal/policy"
)

// fixedClock reads testNow.
type fixedClock struct{}

func (fixedClock) Now() time.Time { return testNow }

const cliToken = "tok-123"

// newEnrollEndpoint serves /v1/enroll like the coordinator. Its TLS
// certificate comes from the same CA, which the returned env trusts in place
// of the system roots (an Ingress certificate). It returns the URL, the CA
// fingerprint and that env.
func newEnrollEndpoint(t *testing.T, status int) (url, fingerprint string, e env) {
	t.Helper()
	ca, err := pki.GenerateCA(pki.WithClock(fixedClock{}))
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.Policy{VMs: []policy.VM{{Name: "windows-node-1", Min: 6 << 30, Max: 24 << 30}}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req pki.EnrollRequest
		if status != http.StatusOK || r.Header.Get("Authorization") != "Bearer "+cliToken ||
			json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(pki.EnrollErrorResponse{Error: "token refused"})
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		leaf, err := ca.SignCSR(block.Bytes, pki.Identity{CommonName: req.Agent, DNSNames: []string{req.Agent + ".example.com"}})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(pki.EnrollResponse{
			Certificate:   string(pki.EncodeCertificatePEM(leaf)),
			CACertificate: string(ca.CertPEM()),
			Settings:      pki.AgentSettings{Port: 9443, HealthPort: 9090},
			Policy:        string(pol.Canonical()),
		})
	}))
	kp, err := ca.IssueServing(pki.Identity{DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*kp.TLSCertificate()}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL + pki.EnrollPath, ca.Fingerprint(), env{now: func() time.Time { return testNow }, rootCAs: ca.Pool()}
}

func TestAgentEnroll(t *testing.T) {
	url, fp, e := newEnrollEndpoint(t, http.StatusOK)
	dir := t.TempDir()
	cfgPath, state := filepath.Join(dir, "etc", "agent.yaml"), filepath.Join(dir, "state")
	code, out, errOut := runCLIEnv(t, e, "agent", "enroll", "--enroll", url, "--token", cliToken, "--ca-sha256", fp,
		"--agent", "host", "--role", "host", "--config", cfgPath, "--state-dir", state)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{`Enrolled agent "host" (role host).`, "NOT active", "windows-node-1", "hvmc agent policy sync"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	cfg, err := agent.LoadConfig(cfgPath)
	if err != nil || cfg.Name != "host" || cfg.Listen != "0.0.0.0:9443" {
		t.Errorf("written config %+v, %v", cfg, err)
	}
	for _, f := range []string{"ca.crt", "serving.pem", "policy.pending.yaml"} {
		if _, err := os.Stat(filepath.Join(state, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestAgentEnrollRefused(t *testing.T) {
	url, fp, e := newEnrollEndpoint(t, http.StatusUnauthorized)
	dir := t.TempDir()
	code, _, errOut := runCLIEnv(t, e, "agent", "enroll", "--enroll", url, "--token", "wrong", "--ca-sha256", fp,
		"--agent", "host", "--role", "host", "--config", filepath.Join(dir, "agent.yaml"), "--state-dir", dir)
	if code != ExitFailure || !strings.Contains(errOut, "401 Unauthorized: token refused") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func TestAgentEnrollUsage(t *testing.T) {
	base := []string{"agent", "enroll", "--enroll", "https://hvmc.example.com/v1/enroll", "--token", "t", "--ca-sha256", "00"}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no agent": {append(base, "--role", "host"), "--agent is required"},
		"bad role": {append(base, "--agent", "host", "--role", "coordinator"), "--role must be host or guest"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, errOut := runCLI(t, tc.args...)
			if code != ExitUsage || !strings.Contains(errOut, tc.want) {
				t.Errorf("exit %d, stderr %q; want usage error %q", code, errOut, tc.want)
			}
		})
	}
}

func TestAgentRun(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	if code, _, errOut := runCLI(t, "agent", "run", "--config", cfg, "--state-dir", dir); code != ExitFailure || errOut == "" {
		t.Errorf("without config: exit %d, stderr %q", code, errOut)
	}
	if err := os.WriteFile(cfg, []byte("role: guest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "agent", "run", "--config", cfg, "--state-dir", dir)
	if want := "Error: hvmc agent run: role guest: not implemented yet\n"; code != ExitFailure || errOut != want {
		t.Errorf("exit %d, stderr %q; want %q", code, errOut, want)
	}
}
