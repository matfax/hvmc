package agentclient_test

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/matfax/hvmc/internal/agentclient"
	"github.com/matfax/hvmc/internal/fake"
	"github.com/matfax/hvmc/internal/pki"
)

func mustQuantity(s string) resource.Quantity { return resource.MustParse(s) }

func failInstall(n int) envOption {
	return withScenario(func(sc *fake.Scenario) {
		sc.Host.Certificate = &fake.CertSpec{FailInstall: n}
	})
}

// Acceptance: rotation RotateCertificate → sign → InstallCertificate,
// including a failing install that leaves the agent's pair in place.
func TestRotation(t *testing.T) {
	e := newEnv(t, failInstall(1))
	e.sync()
	rot := &agentclient.Rotator{CA: e.ca, Events: e.events}
	before, err := e.pool.Probe(e.ctx, "host")
	must(t, err)

	_, err = rot.Rotate(e.ctx, e.hc, "host", e.certs("host"))
	wantErr(t, err, agentclient.ErrInternal)
	st, err := e.sim.Certificate("host")
	must(t, err)
	if st.Installs != 0 || st.Current.SerialNumber.Cmp(before.SerialNumber) != 0 {
		t.Fatalf("certificate after failed install = %+v", st)
	}
	if after, err := e.pool.Probe(e.ctx, "host"); err != nil || after.SerialNumber.Cmp(before.SerialNumber) != 0 {
		t.Fatalf("agent serves %v, %v after a failed install", after, err)
	}
	if e.events.count("host", agentclient.ReasonCertificateRotationFailed) != 1 {
		t.Errorf("events = %+v", e.events.events)
	}

	cert, err := rot.Rotate(e.ctx, e.hc, "host", e.certs("host"))
	must(t, err)
	if !slices.Equal(cert.DNSNames, []string{"host.example.com"}) || cert.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Errorf("new certificate names %v, serial %v", cert.DNSNames, cert.SerialNumber)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: e.ca.Pool(), CurrentTime: e.clk.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("new certificate does not verify: %v", err)
	}
	if st, _ := e.sim.Certificate("host"); st.Installs != 1 || st.PendingKey {
		t.Errorf("certificate state = %+v", st)
	}
	served, err := e.pool.Probe(e.ctx, "host")
	must(t, err)
	if served.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("new connections see serial %v, want %v", served.SerialNumber, cert.SerialNumber)
	}
	// The pool's own connection keeps working.
	_, err = e.host().GetHost(e.ctx)
	must(t, err)
	if e.events.count("host", agentclient.ReasonCertificateRotated) != 1 {
		t.Errorf("events = %+v", e.events.events)
	}

	// Unknown agents and a missing CA are refused before any call.
	if _, err := rot.Rotate(e.ctx, e.hc, "nobody", e.certs("host")); err == nil {
		t.Error("rotating an undeclared agent succeeded")
	}
	if _, err := (&agentclient.Rotator{}).Rotate(e.ctx, e.hc, "host", e.certs("host")); err == nil {
		t.Error("rotating without a CA succeeded")
	}
}

func TestTrackerRotatesWhenDue(t *testing.T) {
	e := newEnv(t, failInstall(1))
	tr := e.tracker(func(o *agentclient.TrackerOptions) {
		o.Rotator = &agentclient.Rotator{CA: e.ca, Events: e.events}
	})
	tr.Poll(e.ctx)
	if n := e.sim.CallCount("host", "RotateCertificate"); n != 0 {
		t.Fatalf("rotated a fresh certificate (%d calls)", n)
	}
	st, _ := tr.Status("host")
	first := st.CertNotAfter

	// Two thirds into the 30-day lifetime the certificate is due.
	e.clk.Advance(pki.LeafValidity * 2 / 3)
	tr.Poll(e.ctx)
	if n := e.sim.CallCount("host", "RotateCertificate"); n != 1 {
		t.Fatalf("RotateCertificate called %d times when due", n)
	}
	// The install failed; no retry before RotationRetry passed.
	tr.Poll(e.ctx)
	if n := e.sim.CallCount("host", "RotateCertificate"); n != 1 {
		t.Fatalf("RotateCertificate retried immediately (%d calls)", n)
	}
	e.clk.Advance(agentclient.DefaultRotationRetry)
	tr.Poll(e.ctx)
	if n := e.sim.CallCount("host", "RotateCertificate"); n != 2 {
		t.Fatalf("RotateCertificate called %d times after the retry delay", n)
	}
	st, _ = tr.Status("host")
	if !st.CertNotAfter.After(first) || !st.CertificateValid {
		t.Errorf("certificate after rotation: notAfter %v (was %v), valid %v", st.CertNotAfter, first, st.CertificateValid)
	}
	if v := e.gauge("hvmc_agent_cert_expiry_seconds", map[string]string{"agent": "host"}); v != float64(st.CertNotAfter.Unix()) {
		t.Errorf("hvmc_agent_cert_expiry_seconds = %v, want %v", v, st.CertNotAfter.Unix())
	}
	// Renewed: not due again.
	e.clk.Advance(time.Hour)
	tr.Poll(e.ctx)
	if n := e.sim.CallCount("host", "RotateCertificate"); n != 2 {
		t.Errorf("rotated again (%d calls)", n)
	}
	if agentclient.RotationDue(nil, t0) {
		t.Error("RotationDue(nil) is true")
	}
}
