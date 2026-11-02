package agentclient_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/matfax/hvmc/api/v1alpha1"
	"github.com/matfax/hvmc/internal/agentclient"
	"github.com/matfax/hvmc/internal/fake"
	"github.com/matfax/hvmc/internal/hostconfig"
	"github.com/matfax/hvmc/internal/ledger"
	"github.com/matfax/hvmc/internal/pki"
)

const (
	gib = int64(fake.GiB)
	mib = int64(fake.MiB)
)

// t0 is the start of every test clock.
var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// testClock adapts fake.ManualClock to agentclient.Clock.
type testClock struct{ *fake.ManualClock }

func (c testClock) NewTimer(d time.Duration) agentclient.Timer { return c.ManualClock.NewTimer(d) }

// scenario is the simulated host: one static Windows VM with a linked guest
// agent, and a fixed Linux VM without one (unmanaged on the host side of the
// tests that do not list it in HostConfig).
const scenario = `
host:
  name: host
  total: 64Gi
  overhead: 4Gi
policy:
  vms:
    - name: vm-a
      min: 4Gi
      max: 32Gi
    - name: vm-dm
      min: 2Gi
      max: 16Gi
vms:
  - name: vm-a
    startup: 8Gi
    shrinkFloor: 7Gi
  - name: vm-dm
    startup: 2Gi
    dynamicMemory:
      minimum: 2Gi
      maximum: 8Gi
  - name: linux-1
    startup: 4Gi
guests:
  - name: vm-a
    vm: vm-a
    os: windows
    offset: 256Mi
    used: 3Gi
    pageFile: 2Gi
`

// env is a fake host and guest agent served over mTLS on loopback, a
// HostConfig pointing at them, the coordinator's CA and client certificate,
// a ledger and recording sinks.
type env struct {
	t       *testing.T
	ctx     context.Context
	clk     *fake.ManualClock
	ca      *pki.CA
	client  *pki.Reloader
	sim     *fake.Sim
	servers map[string]*fake.Server
	hc      *v1alpha1.HostConfig
	reader  client.Reader
	pool    *agentclient.Pool
	led     *ledger.Ledger
	events  *eventLog
	reg     *prometheus.Registry
	metrics *agentclient.PrometheusMetrics
}

type envOption func(*envConfig)

type envConfig struct {
	edit   func(*fake.Scenario)
	reader client.Reader
	// guestNode maps vm-a to this node (its address then comes from the
	// Node's InternalIP) instead of giving it an address override.
	guestNode string
}

func withScenario(edit func(*fake.Scenario)) envOption {
	return func(c *envConfig) { c.edit = edit }
}

func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()
	var cfg envConfig
	for _, o := range opts {
		o(&cfg)
	}
	sc, err := fake.ParseScenario([]byte(scenario))
	must(t, err)
	if cfg.edit != nil {
		cfg.edit(sc)
	}
	clk := fake.NewManualClock(t0)
	ca, err := pki.GenerateCA(pki.WithClock(clk))
	must(t, err)
	reloader, err := pki.NewReloader(ca.IssueClient, pki.ReloaderConfig{Name: "client", Clock: clk})
	must(t, err)
	sim, err := fake.New(sc, fake.WithClock(clk), fake.WithCertificateAuthority(ca.Pool()))
	must(t, err)
	e := &env{
		t: t, ctx: t.Context(), clk: clk, ca: ca, client: reloader, sim: sim,
		servers: map[string]*fake.Server{}, reader: cfg.reader, events: &eventLog{}, reg: prometheus.NewRegistry(),
	}
	e.metrics, err = agentclient.NewPrometheusMetrics(e.reg)
	must(t, err)
	e.hc = &v1alpha1.HostConfig{
		ObjectMeta: metav1.ObjectMeta{Name: v1alpha1.HostConfigName},
		Spec: v1alpha1.HostConfigSpec{
			Agents: []v1alpha1.AgentSpec{{Name: "host", Role: v1alpha1.AgentRoleHost, DNSName: "host.example.com", Address: "127.0.0.1"}},
			VMs: []v1alpha1.VMSpec{{
				Name: "vm-a", GuestOS: v1alpha1.GuestOSWindows, Mode: v1alpha1.VMModeStatic, Base: resource.MustParse("4Gi"),
				GuestAgent: &v1alpha1.GuestAgentSpec{DNSName: "vm-a.example.com", Address: "127.0.0.1"},
			}},
		},
	}
	if cfg.guestNode != "" {
		e.hc.Spec.VMs[0].Node = cfg.guestNode
		e.hc.Spec.VMs[0].GuestAgent = &v1alpha1.GuestAgentSpec{}
	}
	e.serve("host")
	e.serve("vm-a")
	ledCfg, err := hostconfig.ToLedgerConfig(e.hc)
	must(t, err)
	e.led = ledger.New(ledCfg, clk)
	e.pool = agentclient.NewPool(agentclient.PoolOptions{
		TLS: reloader.ClientTLSConfig(ca.Pool()), Clock: testClock{clk},
		Resolver: agentclient.DefaultResolver(cfg.reader),
	})
	t.Cleanup(e.pool.Close)
	return e
}

// serve issues the agent's serving certificate from HostConfig and serves
// it on a fresh loopback port, which it writes into HostConfig.
func (e *env) serve(agent string) {
	e.t.Helper()
	id, err := pki.AgentIdentity(e.ctx, e.reader, e.hc, agent)
	must(e.t, err)
	kp, err := e.ca.IssueServing(id)
	must(e.t, err)
	must(e.t, e.sim.SetServingCertificate(agent, *kp.TLSCertificate()))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	must(e.t, err)
	creds := grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  e.ca.Pool(),
		Time:       e.clk.Now,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return e.sim.ServingCertificate(agent)
		},
	}))
	var srv *fake.Server
	if agent == "host" {
		srv = e.sim.ServeHost(lis, creds)
	} else {
		srv, err = e.sim.ServeGuest(agent, lis, creds)
		must(e.t, err)
	}
	e.t.Cleanup(srv.Stop)
	e.servers[agent] = srv
	port := int32(lis.Addr().(*net.TCPAddr).Port)
	if agent == "host" {
		e.hc.Spec.Agents[0].Port = port
		return
	}
	e.hc.Spec.VMs[0].GuestAgent.Port = port
}

// stop stops an agent's server; connections fail from now on.
func (e *env) stop(agent string) { e.servers[agent].Stop() }

// restart serves the agent on a new port and reconfigures the tracker.
func (e *env) restart(tr *agentclient.Tracker, agent string) {
	e.t.Helper()
	e.serve(agent)
	must(e.t, tr.Configure(e.ctx, e.hc))
}

func (e *env) sync() {
	e.t.Helper()
	must(e.t, e.pool.Sync(e.ctx, agentclient.Endpoints(e.hc)))
}

func (e *env) tracker(edit ...func(*agentclient.TrackerOptions)) *agentclient.Tracker {
	e.t.Helper()
	opts := agentclient.TrackerOptions{
		Pool: e.pool, Ledger: e.led, Clock: testClock{e.clk}, Events: e.events, Metrics: e.metrics,
		CallTimeout: 5 * time.Second,
	}
	for _, f := range edit {
		f(&opts)
	}
	tr := agentclient.NewTracker(opts)
	must(e.t, tr.Configure(e.ctx, e.hc))
	return tr
}

func (e *env) host() agentclient.Host {
	e.t.Helper()
	h, err := e.pool.Host("host")
	must(e.t, err)
	return h
}

func (e *env) guest() agentclient.Guest {
	e.t.Helper()
	g, err := e.pool.Guest("vm-a")
	must(e.t, err)
	return g
}

func (e *env) health(agent string) agentclient.Health {
	e.t.Helper()
	h, err := e.pool.Health(agent)
	must(e.t, err)
	return h
}

func (e *env) certs(agent string) agentclient.Certs {
	e.t.Helper()
	c, err := e.pool.Certs(agent)
	must(e.t, err)
	return c
}

func (e *env) state(tr *agentclient.Tracker, agent string) ledger.AgentState {
	e.t.Helper()
	st, ok := tr.Status(agent)
	if !ok {
		e.t.Fatalf("no status for agent %s", agent)
	}
	return st.State
}

func (e *env) wantState(tr *agentclient.Tracker, agent string, want ledger.AgentState) {
	e.t.Helper()
	if got := e.state(tr, agent); got != want {
		st, _ := tr.Status(agent)
		e.t.Fatalf("agent %s is %s (%s: %s), want %s", agent, got, st.Reason, st.Message, want)
	}
}

// vmA returns the ledger's view of vm-a.
func (e *env) vmA() ledger.VMView {
	const name = "vm-a"
	e.t.Helper()
	for _, v := range e.led.Snapshot().VMs {
		if string(v.Name) == name {
			return v
		}
	}
	e.t.Fatalf("ledger has no VM %s", name)
	return ledger.VMView{}
}

// gauge returns the value of a gauge with the given labels, or -1.
func (e *env) gauge(name string, labels map[string]string) float64 {
	e.t.Helper()
	mfs, err := e.reg.Gather()
	must(e.t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if matches(m, labels) {
				return m.GetGauge().GetValue()
			}
		}
	}
	return -1
}

func matches(m *dto.Metric, labels map[string]string) bool {
	n := 0
	for _, lp := range m.GetLabel() {
		if v, ok := labels[lp.GetName()]; ok {
			if v != lp.GetValue() {
				return false
			}
			n++
		}
	}
	return n == len(labels)
}

// eventLog records events.
type eventLog struct {
	mu     sync.Mutex
	events []agentclient.Event
}

func (l *eventLog) Emit(e agentclient.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) count(agent, reason string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(slices.DeleteFunc(slices.Clone(l.events), func(e agentclient.Event) bool {
		return e.Agent != agent || e.Reason != reason
	}))
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t testing.TB, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

// eventually polls cond until it holds or a generous timeout passes.
func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !cond() {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting until %s", what)
		case <-tick.C:
		}
	}
}

func ptr[T any](v T) *T { return &v }
