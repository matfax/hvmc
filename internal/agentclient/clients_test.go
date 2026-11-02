package agentclient_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/matfax/hvmc/api/v1alpha1"
	"github.com/matfax/hvmc/internal/agentclient"
	"github.com/matfax/hvmc/internal/fake"
	"github.com/matfax/hvmc/internal/ledger"
)

func TestEndpoints(t *testing.T) {
	hc := &v1alpha1.HostConfig{Spec: v1alpha1.HostConfigSpec{
		Agents: []v1alpha1.AgentSpec{{Name: "host", DNSName: "hyperv-01.example.com", Port: 9555}},
		VMs: []v1alpha1.VMSpec{
			{Name: "node-vm", Node: "node-1"},
			{Name: "docker-1", GuestAgent: &v1alpha1.GuestAgentSpec{DNSName: "docker-1.example.com", Address: "192.0.2.7"}},
			{Name: "both", Node: "node-2", GuestAgent: &v1alpha1.GuestAgentSpec{DNSName: "both.example.com", Port: 9000}},
		},
	}}
	want := []agentclient.Endpoint{
		{Name: "host", Role: agentclient.RoleHost, DNSName: "hyperv-01.example.com", Port: 9555, ServerName: "hyperv-01.example.com"},
		{Name: "node-vm", Role: agentclient.RoleGuest, VM: "node-vm", Node: "node-1", Port: 9443, ServerName: "node-1"},
		{Name: "docker-1", Role: agentclient.RoleGuest, VM: "docker-1", DNSName: "docker-1.example.com", Address: "192.0.2.7", Port: 9443, ServerName: "docker-1.example.com"},
		{Name: "both", Role: agentclient.RoleGuest, VM: "both", Node: "node-2", DNSName: "both.example.com", Port: 9000, ServerName: "both.example.com"},
	}
	if diff := cmp.Diff(want, agentclient.Endpoints(hc)); diff != "" {
		t.Errorf("Endpoints (-want +got):\n%s", diff)
	}
	if got := agentclient.Endpoints(nil); got != nil {
		t.Errorf("Endpoints(nil) = %v", got)
	}
}

func TestDefaultResolver(t *testing.T) {
	resolve := agentclient.DefaultResolver(nil)
	for _, tc := range []struct {
		ep   agentclient.Endpoint
		want string
	}{
		{agentclient.Endpoint{Name: "a", Address: "192.0.2.1", DNSName: "a.example.com", Port: 9443}, "192.0.2.1:9443"},
		{agentclient.Endpoint{Name: "b", DNSName: "b.example.com", Port: 9000}, "b.example.com:9000"},
		{agentclient.Endpoint{Name: "c", Node: "node-1", DNSName: "c.example.com"}, "c.example.com:9443"},
		{agentclient.Endpoint{Name: "v6", Address: "2001:db8::1", Port: 9443}, "[2001:db8::1]:9443"},
	} {
		got, err := resolve(t.Context(), tc.ep)
		if err != nil || got != tc.want {
			t.Errorf("resolve(%s) = %q, %v; want %q", tc.ep.Name, got, err, tc.want)
		}
	}
	if _, err := resolve(t.Context(), agentclient.Endpoint{Name: "none", Node: "node-1"}); err == nil {
		t.Error("resolving an agent without address, dnsName and node reader succeeded")
	}
}

func TestHostClient(t *testing.T) {
	e := newEnv(t)
	e.sync()
	h := e.host()

	info, err := h.GetHost(e.ctx)
	must(t, err)
	if info.Name != "host" || info.Total != 64*gib || info.Free != 64*gib-4*gib-14*gib || !info.ObservedAt.Equal(t0) ||
		info.Agent.Role != agentclient.RoleHost || info.Agent.OS != "windows" || info.Agent.Version != fake.DefaultAgentVersion ||
		info.PolicyDigest == "" || info.PendingPolicyDigest != "" {
		t.Errorf("GetHost = %+v", info)
	}
	if o := info.Observation(); o.Total != info.Total || o.Free != info.Free || !o.ObservedAt.Equal(t0) {
		t.Errorf("host observation = %+v", o)
	}

	vms, err := h.ListVMs(e.ctx)
	must(t, err)
	byName := map[string]agentclient.VMInfo{}
	for _, v := range vms {
		byName[v.Name] = v
	}
	if a := byName["vm-a"]; a.State != agentclient.VMStateRunning || a.Assigned != 8*gib || a.Startup != 8*gib || a.Dynamic != nil || a.ID == "" {
		t.Errorf("vm-a = %+v", a)
	}
	dm := byName["vm-dm"]
	if dm.Dynamic == nil || dm.Dynamic.Minimum != 2*gib || dm.Dynamic.Maximum != 8*gib {
		t.Errorf("vm-dm = %+v", dm)
	}
	if o := dm.Observation(); o.Dynamic == nil || o.Dynamic.Maximum != 8*gib || o.Name != "vm-dm" {
		t.Errorf("vm-dm observation = %+v", o)
	}
}

func TestHostClientWatchAndWrites(t *testing.T) {
	e := newEnv(t)
	e.sync()
	h := e.host()

	ch, err := h.WatchVMs(e.ctx)
	must(t, err)
	snap := <-ch
	if len(snap.VMs) != 3 || !snap.ObservedAt.Equal(t0) {
		t.Errorf("first snapshot = %+v", snap)
	}
	if o := snap.Observation(); !o.CompleteVMList || len(o.VMs) != 3 {
		t.Errorf("snapshot observation = %+v", o)
	}

	res, err := h.SetStartup(e.ctx, "vm-a", 10*gib)
	must(t, err)
	if res.Before.Assigned != 8*gib || res.After.Assigned != 10*gib || res.After.Startup != 10*gib {
		t.Errorf("SetStartup = %+v", res)
	}
	if out := res.Outcome(); out.AssignedBefore != 8*gib || out.AssignedAfter != 10*gib || out.StartupAfter != 10*gib || out.ObservedAt.IsZero() {
		t.Errorf("outcome = %+v", out)
	}
	if snap := <-ch; findVM(snap.VMs, "vm-a").Assigned != 10*gib {
		t.Errorf("snapshot after grow = %+v", snap)
	}

	res, err = h.SetDynamicLimits(e.ctx, "vm-dm", nil, ptr(12*gib))
	must(t, err)
	if res.After.Dynamic == nil || res.After.Dynamic.Maximum != 12*gib || res.Outcome().MaximumAfter != 12*gib {
		t.Errorf("SetDynamicLimits = %+v", res)
	}
}

func findVM(vms []agentclient.VMInfo, name string) agentclient.VMInfo {
	for _, v := range vms {
		if v.Name == name {
			return v
		}
	}
	return agentclient.VMInfo{}
}

func TestHostClientErrors(t *testing.T) {
	e := newEnv(t)
	e.sync()
	h := e.host()

	_, err := h.SetStartup(e.ctx, "linux-1", 6*gib) // not in the policy
	wantErr(t, err, agentclient.ErrPolicyDenied)
	_, err = h.SetStartup(e.ctx, "vm-dm", 4*gib) // Dynamic Memory VM
	wantErr(t, err, agentclient.ErrFixedVM)
	must(t, e.sim.UpdateHost(func(h *fake.HostSpec) { h.Overhead = 40 * fake.GiB })) // 10Gi free
	_, err = h.SetStartup(e.ctx, "vm-a", 31*gib)
	wantErr(t, err, agentclient.ErrHostOutOfMemory)
	if !agentclient.Retryable(err) {
		t.Error("host out of memory is not retryable")
	}
	_, err = h.SetStartup(e.ctx, "missing", 4*gib)
	wantErr(t, err, agentclient.ErrNotFound)
	_, err = h.SetStartup(e.ctx, "vm-a", 4*gib+1)
	wantErr(t, err, agentclient.ErrInvalidArgument)
	if agentclient.Retryable(err) {
		t.Error("invalid argument is retryable")
	}

	_, err = h.SetStartup(e.ctx, "vm-a", 6*gib) // the guest gives up memory only down to 7Gi
	wantErr(t, err, agentclient.ErrShrinkRefused)
	if res, ok := agentclient.ResultOf(err); !ok || res.After.Assigned != 7*gib {
		t.Errorf("result of refused shrink = %+v, %v", res, ok)
	}

	must(t, e.sim.SetVMMSDown(true))
	_, err = h.GetHost(e.ctx)
	wantErr(t, err, agentclient.ErrVMMSDown)
	wantErr(t, err, agentclient.ErrUnavailable)
	if !agentclient.Retryable(err) {
		t.Error("vmms down is not retryable")
	}
	_, err = h.WatchVMs(e.ctx)
	wantErr(t, err, agentclient.ErrVMMSDown)
}

func TestGuestClient(t *testing.T) {
	e := newEnv(t)
	e.sync()
	g := e.guest()

	m, err := g.GetMemory(e.ctx)
	must(t, err)
	total := 8*gib - 256*mib
	if m.Total != total || m.Available != total-3*gib || m.CommitLimit == nil || *m.CommitLimit != total+2*gib ||
		m.CommitAvailable == nil || m.Agent.Role != agentclient.RoleGuest || m.Agent.OS != "windows" || !m.ObservedAt.Equal(t0) {
		t.Errorf("GetMemory = %+v", m)
	}
	o := m.Observation("vm-a")
	if o.VM != "vm-a" || o.Total != total || o.CommitLimit != total+2*gib {
		t.Errorf("guest observation = %+v", o)
	}

	ch, err := g.WatchMemory(e.ctx)
	must(t, err)
	if first := <-ch; first.Total != total || first.Agent.Version != "" {
		t.Errorf("first reading = %+v", first)
	}
	must(t, e.sim.UpdateGuest("vm-a", func(g *fake.GuestSpec) { g.Used = 4 * fake.GiB }))
	if next := <-ch; next.Available != total-4*gib {
		t.Errorf("reading after change = %+v", next)
	}

	must(t, e.sim.UpdateGuest("vm-a", func(g *fake.GuestSpec) { g.SourceDown = true }))
	_, err = g.GetMemory(e.ctx)
	wantErr(t, err, agentclient.ErrUnavailable)
	if _, open := <-ch; open {
		t.Error("WatchMemory channel still open after the stream ended")
	}

	if _, err := e.pool.Guest("host"); err == nil {
		t.Error("Guest(host) returned a client")
	}
	wantErr(t, func() error { _, err := e.pool.Host("vm-a"); return err }(), agentclient.ErrUnknownAgent)
}

func TestVerified(t *testing.T) {
	step := 256 * mib
	offset := 256 * mib
	if !agentclient.Verified(10*gib-offset, 10*gib, offset, step) {
		t.Error("exact total not verified")
	}
	if !agentclient.Verified(10*gib-offset-step/2, 10*gib, offset, step) {
		t.Error("total within step/2 not verified")
	}
	if agentclient.Verified(8*gib-offset, 10*gib, offset, step) {
		t.Error("old total verified")
	}
	if got := agentclient.Offset(8*gib, 8*gib-offset); got != offset {
		t.Errorf("Offset = %d", got)
	}
}

func TestHealthClient(t *testing.T) {
	e := newEnv(t)
	e.sync()
	h := e.health("host")
	st, err := h.Check(e.ctx, agentclient.HostAgentService)
	must(t, err)
	if st != agentclient.HealthServing {
		t.Errorf("Check = %s", st)
	}
	st, err = h.Check(e.ctx, "no.such.Service")
	if err == nil {
		t.Errorf("Check(unknown service) = %s, nil", st)
	}

	ch, err := h.Watch(e.ctx, agentclient.HostAgentService)
	must(t, err)
	if first := <-ch; first != agentclient.HealthServing {
		t.Errorf("first watch status = %s", first)
	}
	must(t, e.sim.SetNotServing("host", true))
	if next := <-ch; next != agentclient.HealthNotServing {
		t.Errorf("watch status after NotServing = %s", next)
	}
	st, err = h.Check(e.ctx, "")
	must(t, err)
	if st != agentclient.HealthNotServing {
		t.Errorf("overall Check = %s", st)
	}
	if cert := e.pool.PeerCertificate("host"); cert == nil || cert.DNSNames[0] != "host.example.com" {
		t.Errorf("peer certificate = %v", cert)
	}
}

func TestAgentIdentityIsVerified(t *testing.T) {
	e := newEnv(t)
	// The host agent's certificate names host.example.com; a HostConfig that
	// expects another name must not accept it.
	e.hc.Spec.Agents[0].DNSName = "other.example.com"
	e.sync()
	_, err := e.health("host").Check(e.ctx, "")
	wantErr(t, err, agentclient.ErrUnavailable)
	if cert := e.pool.PeerCertificate("host"); cert != nil {
		t.Errorf("peer certificate recorded for a rejected agent: %v", cert.DNSNames)
	}
	// The guest is still fine.
	if _, err := e.health("vm-a").Check(e.ctx, ""); err != nil {
		t.Errorf("guest Check: %v", err)
	}
}

func TestPoolSync(t *testing.T) {
	e := newEnv(t)
	e.sync()
	h := e.host()
	_, err := h.GetHost(e.ctx)
	must(t, err)

	// A guest without address, dnsName or node cannot be resolved: Sync
	// reports it, and its calls fail as unavailable.
	e.hc.Spec.VMs = append(e.hc.Spec.VMs, v1alpha1.VMSpec{
		Name: "lost", GuestOS: v1alpha1.GuestOSWindows, Mode: v1alpha1.VMModeStatic, Base: resource.MustParse("2Gi"),
	})
	if err := e.pool.Sync(e.ctx, agentclient.Endpoints(e.hc)); err == nil {
		t.Error("Sync with an unresolvable agent succeeded")
	}
	lost, err := e.pool.Health("lost")
	must(t, err)
	_, err = lost.Check(e.ctx, "")
	wantErr(t, err, agentclient.ErrUnavailable)

	// The host client keeps working across Syncs.
	_, err = h.GetHost(e.ctx)
	must(t, err)

	// Removing the agent closes its connection.
	e.hc.Spec.Agents = nil
	e.hc.Spec.VMs = e.hc.Spec.VMs[:1]
	e.sync()
	_, err = h.GetHost(e.ctx)
	wantErr(t, err, agentclient.ErrUnavailable)
	wantErr(t, func() error { _, err := e.pool.Host("host"); return err }(), agentclient.ErrUnknownAgent)
}

func TestLedgerConversions(t *testing.T) {
	at := t0.Add(time.Second)
	v := agentclient.VMInfo{Name: "vm-a", Assigned: 8 * gib, Startup: 8 * gib, ObservedAt: at}
	if got, want := v.Observation(), (ledger.VMObservation{Name: "vm-a", Assigned: 8 * gib, Startup: 8 * gib, ObservedAt: at}); !cmp.Equal(got, want) {
		t.Errorf("VMInfo.Observation = %+v", got)
	}
	m := agentclient.GuestMemory{Total: 4 * gib, Available: gib, ObservedAt: at}
	if o := m.Observation("vm-a"); o.CommitLimit != 0 || o.CommitAvailable != 0 || o.Total != 4*gib {
		t.Errorf("Linux guest observation = %+v", o)
	}
}
