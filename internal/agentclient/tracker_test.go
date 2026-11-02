package agentclient_test

import (
	"errors"
	"testing"
	"time"

	"github.com/matfax/hvmc/api/v1alpha1"
	"github.com/matfax/hvmc/internal/agentclient"
	"github.com/matfax/hvmc/internal/fake"
	"github.com/matfax/hvmc/internal/ledger"
)

// grant puts a 1Gi lease on vm-a into Granted (no resize needed: vm-a has
// 8Gi assigned, floor 4Gi base + 2Gi margin).
func (e *env) grant(id ledger.RequestID) {
	e.t.Helper()
	_, err := e.led.Enqueue(ledger.Request{ID: id, Kind: ledger.KindExternal, VM: "vm-a", Bytes: gib})
	must(e.t, err)
	res, err := e.led.Reserve(id, "vm-a")
	must(e.t, err)
	must(e.t, e.led.Commit(res, ledger.ResizeOutcome{}))
}

// wantGranted fails unless the lease ext-a is Granted.
func (e *env) wantGranted() {
	e.t.Helper()
	const id ledger.RequestID = "ext-a"
	lv, ok := e.led.Lease(id)
	if !ok || lv.Phase != ledger.PhaseGranted {
		e.t.Fatalf("lease %s = %+v, %v; want Granted", id, lv, ok)
	}
}

func TestTrackerFeedsLedger(t *testing.T) {
	e := newEnv(t)
	tr := e.tracker()
	e.wantState(tr, "host", ledger.AgentUnknown)
	if !e.led.Snapshot().Frozen {
		t.Fatal("ledger not frozen before the host agent was seen")
	}

	tr.Poll(e.ctx)
	e.wantState(tr, "host", ledger.AgentReady)
	e.wantState(tr, "vm-a", ledger.AgentReady)
	snap := e.led.Snapshot()
	if snap.Frozen || snap.HostFree != 46*gib || snap.Agents["host"] != ledger.AgentReady || snap.Agents["vm-a"] != ledger.AgentReady {
		t.Fatalf("ledger snapshot = %+v", snap)
	}
	vm := e.vmA()
	if vm.State != ledger.VMReady || vm.Assigned != 8*gib || !vm.UsedKnown || vm.Used != 3*gib {
		t.Errorf("vm-a = %+v", vm)
	}
	if off, ok := tr.Offset("vm-a"); !ok || off != 256*mib {
		t.Errorf("offset(vm-a) = %d, %v; want 256Mi", off, ok)
	}

	st, _ := tr.Status("host")
	if st.Version != fake.DefaultAgentVersion || !st.LastSeen.Equal(t0) || st.Reason != agentclient.StateReasonServing ||
		!st.CertificateValid || st.CertNotAfter.IsZero() || st.Role != agentclient.RoleHost {
		t.Errorf("host status = %+v", st)
	}
	if got := len(tr.Statuses()); got != 2 {
		t.Errorf("%d statuses", got)
	}
	if e.events.count("host", agentclient.ReasonAgentReady) != 1 || e.events.count("vm-a", agentclient.ReasonAgentReady) != 1 {
		t.Errorf("events = %+v", e.events.events)
	}
	if up := e.gauge("hvmc_agent_up", map[string]string{"agent": "host", "role": "host"}); up != 1 {
		t.Errorf("hvmc_agent_up = %v", up)
	}
	if exp := e.gauge("hvmc_agent_cert_expiry_seconds", map[string]string{"agent": "vm-a"}); exp != float64(st.CertNotAfter.Unix()) && exp <= 0 {
		t.Errorf("hvmc_agent_cert_expiry_seconds = %v", exp)
	}
}

// Acceptance: the host agent going down freezes the ledger after three
// failed checks; nothing is revoked.
func TestHostAgentDownFreezesLedger(t *testing.T) {
	e := newEnv(t)
	tr := e.tracker()
	tr.Poll(e.ctx)
	e.grant("ext-a")

	e.stop("host")
	for i := 1; i <= 2; i++ {
		tr.Poll(e.ctx)
		e.wantState(tr, "host", ledger.AgentReady)
		if e.led.Snapshot().Frozen {
			t.Fatalf("ledger frozen after %d failed checks", i)
		}
	}
	tr.Poll(e.ctx)
	e.wantState(tr, "host", ledger.AgentUnreachable)
	st, _ := tr.Status("host")
	if st.ConsecutiveFailures != 3 || st.Reason != agentclient.StateReasonUnreachable {
		t.Errorf("host status = %+v", st)
	}
	if !e.led.Snapshot().Frozen {
		t.Fatal("ledger not frozen with the host agent Unreachable")
	}
	e.wantGranted()
	_, err := e.led.Enqueue(ledger.Request{ID: "ext-b", Kind: ledger.KindExternal, VM: "vm-a", Bytes: gib})
	must(t, err)
	_, err = e.led.Reserve("ext-b", "vm-a")
	wantErr(t, err, ledger.ErrFrozen)
	e.wantState(tr, "vm-a", ledger.AgentReady)

	tr.Poll(e.ctx)
	if n := e.events.count("host", agentclient.ReasonAgentUnreachable); n != 1 {
		t.Errorf("%d AgentUnreachable events", n)
	}
	if v := e.gauge("hvmc_agent_state", map[string]string{"agent": "host", "state": "Unreachable"}); v != 1 {
		t.Errorf("hvmc_agent_state{Unreachable} = %v", v)
	}
	if v := e.gauge("hvmc_agent_up", map[string]string{"agent": "host"}); v != 0 {
		t.Errorf("hvmc_agent_up = %v", v)
	}

	// The agent comes back on a new address: one good check unfreezes.
	e.restart(tr, "host")
	tr.Poll(e.ctx)
	e.wantState(tr, "host", ledger.AgentReady)
	if e.led.Snapshot().Frozen {
		t.Error("ledger still frozen after the host agent recovered")
	}
	e.wantGranted()
	if n := e.events.count("host", agentclient.ReasonAgentReady); n != 2 {
		t.Errorf("%d AgentReady events", n)
	}
}

// Acceptance: a guest agent going down makes its VM Unknown; leases stay.
func TestGuestAgentDownMakesVMUnknown(t *testing.T) {
	e := newEnv(t)
	tr := e.tracker()
	tr.Poll(e.ctx)
	e.grant("ext-a")

	e.stop("vm-a")
	for range 3 {
		tr.Poll(e.ctx)
	}
	e.wantState(tr, "vm-a", ledger.AgentUnreachable)
	e.wantState(tr, "host", ledger.AgentReady)
	if vm := e.vmA(); vm.State != ledger.VMUnknown {
		t.Errorf("vm-a state = %s, want Unknown", vm.State)
	}
	snap := e.led.Snapshot()
	if snap.Frozen {
		t.Error("ledger frozen by a guest agent")
	}
	e.wantGranted()

	// A grant that needs no resize is still possible on an Unknown VM.
	_, err := e.led.Enqueue(ledger.Request{ID: "ext-b", Kind: ledger.KindExternal, VM: "vm-a", Bytes: 512 * mib})
	must(t, err)
	_, err = e.led.Reserve("ext-b", "vm-a")
	must(t, err)
}

func TestDegraded(t *testing.T) {
	e := newEnv(t)
	tr := e.tracker()
	tr.Poll(e.ctx)

	// NOT_SERVING → Degraded at the next check; the VM is Unknown.
	must(t, e.sim.SetNotServing("vm-a", true))
	tr.Poll(e.ctx)
	e.wantState(tr, "vm-a", ledger.AgentDegraded)
	if st, _ := tr.Status("vm-a"); st.Reason != agentclient.StateReasonNotServing {
		t.Errorf("reason = %s", st.Reason)
	}
	if vm := e.vmA(); vm.State != ledger.VMUnknown {
		t.Errorf("vm-a state = %s", vm.State)
	}
	must(t, e.sim.SetNotServing("vm-a", false))
	tr.Poll(e.ctx)
	e.wantState(tr, "vm-a", ledger.AgentReady)

	// Stale host data → Degraded → frozen.
	must(t, e.sim.SetStale("host", 0))
	e.clk.Advance(31 * time.Second)
	tr.Poll(e.ctx)
	e.wantState(tr, "host", ledger.AgentDegraded)
	if st, _ := tr.Status("host"); st.Reason != agentclient.StateReasonDataStale {
		t.Errorf("reason = %s", st.Reason)
	}
	if !e.led.Snapshot().Frozen {
		t.Error("ledger not frozen with stale host data")
	}
	if n := e.events.count("host", agentclient.ReasonAgentDegraded); n != 1 {
		t.Errorf("%d AgentDegraded events", n)
	}
	must(t, e.sim.ClearStale("host"))
	tr.Poll(e.ctx)
	e.wantState(tr, "host", ledger.AgentReady)
}

func TestTrackerRunsWatchesAndLoops(t *testing.T) {
	e := newEnv(t)
	tr := e.tracker()
	ctx := e.ctx
	done := make(chan error, 1)
	go func() { done <- tr.Start(ctx) }()
	changes, cancel := tr.Subscribe()
	defer cancel()

	// The health watch alone makes an agent Ready once data is in: the
	// WatchMemory stream delivers the guest's data.
	eventually(t, "the guest is Ready from its watches", func() bool {
		return e.state(tr, "vm-a") == ledger.AgentReady
	})
	select {
	case <-changes:
	default:
		t.Error("no change notification")
	}

	// WatchVMs delivers VM changes without a poll.
	must(t, e.sim.UpdateVM("vm-a", func(v *fake.VMSpec) { v.Startup = 9 * fake.GiB; v.Assigned = nil }))
	eventually(t, "the ledger sees the new assignment", func() bool {
		v := e.vmA()
		return v.Assigned == 9*gib
	})
	// The health watch reports NOT_SERVING without a poll.
	must(t, e.sim.SetNotServing("vm-a", true))
	eventually(t, "the guest is Degraded", func() bool { return e.state(tr, "vm-a") == ledger.AgentDegraded })

	// The loop checks once per interval of the clock.
	before := e.sim.CallCount("host", "GetHost")
	eventually(t, "the loop polled the host", func() bool {
		e.clk.Advance(agentclient.DefaultCheckInterval)
		return e.sim.CallCount("host", "GetHost") > before
	})
	if err := tr.Start(ctx); err == nil {
		t.Error("second Start succeeded")
	}
}

func TestConfigureRemovesAgents(t *testing.T) {
	e := newEnv(t)
	tr := e.tracker()
	tr.Poll(e.ctx)
	e.hc.Spec.VMs = nil
	must(t, tr.Configure(e.ctx, e.hc))
	if _, ok := tr.Status("vm-a"); ok {
		t.Error("vm-a still tracked")
	}
	if s := e.led.Snapshot().Agents["vm-a"]; s != ledger.AgentUnknown {
		t.Errorf("ledger state of vm-a = %s", s)
	}
	if v := e.gauge("hvmc_agent_up", map[string]string{"agent": "vm-a"}); v != -1 {
		t.Errorf("hvmc_agent_up for a removed agent = %v", v)
	}
	if _, ok := tr.Offset("vm-a"); ok {
		t.Error("offset kept for a removed agent")
	}
}

// Acceptance: a policy mismatch sends the proposal exactly once per digest.
func TestPolicyProposedOncePerDigest(t *testing.T) {
	e := newEnv(t)
	tr := e.tracker()
	for range 3 {
		tr.Poll(e.ctx)
	}
	if n := e.sim.CallCount("host", "ProposePolicy"); n != 1 {
		t.Fatalf("ProposePolicy called %d times, want 1", n)
	}
	st, _ := tr.Status("host")
	want := agentclient.DesiredPolicy(e.hc, 64*gib).Digest()
	if p := st.Policy; p == nil || p.InSync || p.Desired != want || p.Pending != want || p.Err != nil {
		t.Fatalf("policy status = %+v", p)
	}
	if _, pending := e.sim.PolicyDigests(); pending != want {
		t.Errorf("agent's pending digest = %s, want %s", pending, want)
	}
	if e.events.count("host", agentclient.ReasonPolicyOutOfSync) != 1 || e.events.count("host", agentclient.ReasonPolicyProposed) != 1 {
		t.Errorf("events = %+v", e.events.events)
	}

	// A HostConfig change makes a new digest: proposed once more.
	e.hc.Spec.VMs[0].Policy = &v1alpha1.VMPolicy{Min: mustQuantity("6Gi"), Max: mustQuantity("24Gi")}
	must(t, tr.Configure(e.ctx, e.hc))
	for range 2 {
		tr.Poll(e.ctx)
	}
	if n := e.sim.CallCount("host", "ProposePolicy"); n != 2 {
		t.Fatalf("ProposePolicy called %d times after the change, want 2", n)
	}

	// Activating the pending policy on the host brings it in sync.
	must(t, e.sim.ActivatePendingPolicy())
	tr.Poll(e.ctx)
	if st, _ := tr.Status("host"); st.Policy == nil || !st.Policy.InSync {
		t.Errorf("policy status after activation = %+v", st.Policy)
	}
	if e.events.count("host", agentclient.ReasonPolicyInSync) != 1 {
		t.Errorf("events = %+v", e.events.events)
	}
	if n := e.sim.CallCount("host", "ProposePolicy"); n != 2 {
		t.Errorf("ProposePolicy called %d times in sync", n)
	}
}

func TestPolicyProposalRetriedOnlyWhenRetryable(t *testing.T) {
	e := newEnv(t)
	tr := e.tracker(func(o *agentclient.TrackerOptions) { o.CallTimeout = 300 * time.Millisecond })
	must(t, e.sim.SetHang("host", "ProposePolicy"))
	tr.Poll(e.ctx)
	st, _ := tr.Status("host")
	if st.Policy == nil || !errors.Is(st.Policy.Err, agentclient.ErrDeadlineExceeded) {
		t.Fatalf("policy status = %+v", st.Policy)
	}
	must(t, e.sim.SetHang("host"))
	tr.Poll(e.ctx)
	if n := e.sim.CallCount("host", "ProposePolicy"); n != 2 {
		t.Errorf("ProposePolicy called %d times, want a retry after the timeout", n)
	}
	if e.events.count("host", agentclient.ReasonPolicyProposalFailed) != 1 {
		t.Errorf("events = %+v", e.events.events)
	}

	// An agent whose digest disagrees refuses every proposal with
	// INVALID_ARGUMENT, which is not retried.
	e2 := newEnv(t, withScenario(func(sc *fake.Scenario) { sc.Host.PolicyDigestSkew = true }))
	tr2 := e2.tracker()
	for range 3 {
		tr2.Poll(e2.ctx)
	}
	if n := e2.sim.CallCount("host", "ProposePolicy"); n != 1 {
		t.Errorf("ProposePolicy called %d times on a refusing agent, want 1", n)
	}
	if st, _ := tr2.Status("host"); st.Policy == nil || !errors.Is(st.Policy.Err, agentclient.ErrInvalidArgument) {
		t.Errorf("policy status = %+v", st.Policy)
	}
}

func TestDesiredPolicy(t *testing.T) {
	e := newEnv(t)
	unobserved := agentclient.DesiredPolicy(e.hc, 0)
	observed := agentclient.DesiredPolicy(e.hc, 64*gib)
	if unobserved.Digest() == observed.Digest() {
		t.Error("observing the host does not change the derived policy")
	}
	vm, ok := observed.Lookup("vm-a")
	if !ok || vm.Min != 4*gib || vm.Max != 60*gib {
		t.Errorf("vm-a = %+v", vm)
	}
	e.hc.Spec.Capacity = ptr(mustQuantity("32Gi"))
	vm, _ = agentclient.DesiredPolicy(e.hc, 64*gib).Lookup("vm-a")
	if vm.Max != 28*gib {
		t.Errorf("vm-a with spec.capacity = %+v", vm)
	}
	if e.hc.Status.ObservedHost != nil {
		t.Error("DesiredPolicy changed its input")
	}
}
