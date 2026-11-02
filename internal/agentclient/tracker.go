package agentclient

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"

	"github.com/matfax/hvmc/api/v1alpha1"
	"github.com/matfax/hvmc/internal/ledger"
)

// Defaults of the health tracker (DESIGN §4.8).
const (
	// DefaultCheckInterval is the period of Check (and of the data polls).
	DefaultCheckInterval = 5 * time.Second
	// DefaultCheckTimeout is the deadline of one Check.
	DefaultCheckTimeout = 2 * time.Second
	// DefaultCallTimeout is the deadline of the tracker's data polls, policy
	// proposals and rotations.
	DefaultCallTimeout = 10 * time.Second
	// DefaultFailureThreshold is the number of consecutive failed checks
	// after which an agent is Unreachable.
	DefaultFailureThreshold = 3
	// DefaultRotationRetry is the wait after a failed certificate rotation.
	DefaultRotationRetry = 5 * time.Minute
)

// LedgerSink is the part of *ledger.Ledger the tracker feeds.
type LedgerSink interface {
	SetAgentState(agent ledger.AgentName, s ledger.AgentState)
	Observe(o ledger.Observation)
}

// Event is a Kubernetes event about an agent.
type Event struct {
	Agent string
	// Type is corev1.EventTypeNormal or corev1.EventTypeWarning.
	Type    string
	Reason  string
	Action  string
	Message string
}

// EventEmitter receives the tracker's events. Emit must not block.
type EventEmitter interface {
	Emit(e Event)
}

// NewRecorderEmitter returns an EventEmitter that records events through rec
// (e.g. the manager's GetEventRecorder) regarding obj, normally the
// HostConfig.
func NewRecorderEmitter(rec events.EventRecorder, regarding runtime.Object) EventEmitter {
	return recorderSink{rec: rec, obj: regarding}
}

type recorderSink struct {
	rec events.EventRecorder
	obj runtime.Object
}

func (s recorderSink) Emit(e Event) {
	s.rec.Eventf(s.obj, nil, e.Type, e.Reason, e.Action, "agent %s: %s", e.Agent, e.Message)
}

// Event reasons of the tracker.
const (
	ReasonAgentReady           = "AgentReady"
	ReasonAgentDegraded        = "AgentDegraded"
	ReasonAgentUnreachable     = "AgentUnreachable"
	ReasonPolicyInSync         = "PolicyInSync"
	ReasonPolicyOutOfSync      = "PolicyOutOfSync"
	ReasonPolicyProposed       = "PolicyProposed"
	ReasonPolicyProposalFailed = "PolicyProposalFailed"
)

// Reasons for an agent's state (AgentStatus.Reason), usable as condition
// reasons.
const (
	StateReasonServing      = "Serving"
	StateReasonNotServing   = "NotServing"
	StateReasonDataStale    = "DataStale"
	StateReasonUnreachable  = "Unreachable"
	StateReasonNotContacted = "NotContacted"
)

// Metrics receives the tracker's metric updates.
type Metrics interface {
	// AgentState records an agent's current state.
	AgentState(agent string, role Role, s ledger.AgentState)
	// CertExpiry records the NotAfter of an agent's serving certificate.
	CertExpiry(agent string, role Role, notAfter time.Time)
	// Forget drops an agent that is no longer configured.
	Forget(agent string)
}

// agentStates are the values of the state label of hvmc_agent_state.
var agentStates = []ledger.AgentState{ledger.AgentUnknown, ledger.AgentReady, ledger.AgentDegraded, ledger.AgentUnreachable}

// PrometheusMetrics implements Metrics with the gauges of DESIGN §4.8.
type PrometheusMetrics struct {
	up     *prometheus.GaugeVec
	state  *prometheus.GaugeVec
	expiry *prometheus.GaugeVec
}

// NewPrometheusMetrics registers hvmc_agent_up, hvmc_agent_state and
// hvmc_agent_cert_expiry_seconds with reg (e.g. controller-runtime's
// metrics.Registry).
func NewPrometheusMetrics(reg prometheus.Registerer) (*PrometheusMetrics, error) {
	m := &PrometheusMetrics{
		up: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hvmc_agent_up",
			Help: "1 if the agent answers health checks (state Ready or Degraded), else 0.",
		}, []string{"agent", "role"}),
		state: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hvmc_agent_state",
			Help: "1 for the agent's current state (Unknown, Ready, Degraded, Unreachable), 0 for the others.",
		}, []string{"agent", "role", "state"}),
		expiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hvmc_agent_cert_expiry_seconds",
			Help: "NotAfter of the agent's serving certificate, in seconds since the Unix epoch.",
		}, []string{"agent", "role"}),
	}
	for _, c := range []prometheus.Collector{m.up, m.state, m.expiry} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// AgentState implements Metrics.
func (m *PrometheusMetrics) AgentState(agent string, role Role, s ledger.AgentState) {
	up := 0.0
	if s == ledger.AgentReady || s == ledger.AgentDegraded {
		up = 1
	}
	m.up.WithLabelValues(agent, string(role)).Set(up)
	for _, x := range agentStates {
		v := 0.0
		if x == s {
			v = 1
		}
		m.state.WithLabelValues(agent, string(role), string(x)).Set(v)
	}
}

// CertExpiry implements Metrics.
func (m *PrometheusMetrics) CertExpiry(agent string, role Role, notAfter time.Time) {
	m.expiry.WithLabelValues(agent, string(role)).Set(float64(notAfter.Unix()))
}

// Forget implements Metrics.
func (m *PrometheusMetrics) Forget(agent string) {
	l := prometheus.Labels{"agent": agent}
	m.up.DeletePartialMatch(l)
	m.state.DeletePartialMatch(l)
	m.expiry.DeletePartialMatch(l)
}

// AgentStatus is the tracker's view of one agent, the input for
// HostConfig status.agents[] and the agent's EndpointSlice conditions.
type AgentStatus struct {
	Name string
	Role Role
	// VM is the guest agent's VM; empty for the host agent.
	VM    string
	State ledger.AgentState
	// Reason (StateReason*) and Message explain State.
	Reason  string
	Message string
	// LastTransition is when State last changed.
	LastTransition time.Time
	// LastSeen is the last successful call to the agent.
	LastSeen time.Time
	// ConsecutiveFailures counts failed health checks since the last
	// successful one.
	ConsecutiveFailures int
	// Version is the agent's software version.
	Version string
	// CertNotAfter is the NotAfter of the agent's serving certificate as
	// last presented or installed; zero if unknown.
	CertNotAfter time.Time
	// CertificateValid: the certificate is known and within its validity.
	CertificateValid bool
	// Policy is the latest policy comparison (host agent only); nil until
	// the first GetHost.
	Policy *PolicyStatus
}

// TrackerOptions configures a Tracker. Pool is required; nil sinks
// discard their input.
type TrackerOptions struct {
	Pool    *Pool
	Ledger  LedgerSink
	Clock   Clock
	Events  EventEmitter
	Metrics Metrics
	// Rotator renews certificates when due; nil disables rotation.
	Rotator *Rotator

	CheckInterval    time.Duration
	CheckTimeout     time.Duration
	CallTimeout      time.Duration
	FailureThreshold int
	RotationRetry    time.Duration
}

func (o *TrackerOptions) setDefaults() {
	if o.Clock == nil {
		o.Clock = SystemClock()
	}
	o.CheckInterval = durationOr(o.CheckInterval, DefaultCheckInterval)
	o.CheckTimeout = durationOr(o.CheckTimeout, DefaultCheckTimeout)
	o.CallTimeout = durationOr(o.CallTimeout, DefaultCallTimeout)
	o.RotationRetry = durationOr(o.RotationRetry, DefaultRotationRetry)
	if o.FailureThreshold <= 0 {
		o.FailureThreshold = DefaultFailureThreshold
	}
}

func durationOr(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Tracker is the coordinator's health tracker (DESIGN §4.8). Per agent it
// keeps a Health.Watch stream open, calls Check every CheckInterval with a
// CheckTimeout deadline, and polls the agent's data on the same tick (host:
// GetHost and ListVMs, kept current between ticks by WatchVMs; guest:
// GetMemory, kept current by WatchMemory). It derives each agent's state:
//
//   - Unreachable after FailureThreshold consecutive failed checks;
//   - Ready when the agent reports SERVING and its data is fresh
//     (staleAfter);
//   - Degraded when it is reachable but NOT_SERVING or its data is stale;
//   - Unknown before the first contact.
//
// It feeds every observation into the ledger and every state transition
// into Ledger.SetAgentState, which freezes the ledger (host agent) or makes
// a VM Unknown (guest agent); nothing is revoked. Transitions also emit
// events and metrics. For the host agent it keeps PolicyInSync and proposes
// the policy derived from HostConfig on mismatch; for every guest it records
// offset(vm) on first contact; for every agent it renews the serving
// certificate when due.
//
// Configure sets the agents; Start runs the loops (leader only); Poll runs
// one round synchronously, e.g. before a ledger rebuild.
type Tracker struct {
	opts TrackerOptions

	mu         sync.Mutex
	hc         *v1alpha1.HostConfig
	staleAfter time.Duration
	agents     map[string]*tracked
	offsets    map[string]int64
	vms        map[string]VMInfo
	runCtx     context.Context //nolint:containedctx // lifetime of Start, for the per-agent workers
	subs       map[uint64]chan struct{}
	subSeq     uint64
}

// tracked is one agent's tracker state; fields after pollMu are guarded by
// Tracker.mu.
type tracked struct {
	pollMu sync.Mutex

	ep         Endpoint
	st         AgentStatus
	failures   int
	lastErr    error
	contacted  bool
	serving    bool
	dataAt     time.Time
	guestTotal int64
	guestAt    time.Time
	peer       *x509.Certificate
	installed  *x509.Certificate
	nextRotate time.Time
	policy     PolicySync
	loop       *worker
	healthW    *worker
	dataW      *worker
}

// worker is a goroutine with its own cancel.
type worker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (w *worker) alive() bool {
	if w == nil {
		return false
	}
	select {
	case <-w.done:
		return false
	default:
		return true
	}
}

func (w *worker) stop() {
	if w != nil {
		w.cancel()
	}
}

// NewTracker returns a Tracker without agents.
func NewTracker(opts TrackerOptions) *Tracker {
	opts.setDefaults()
	return &Tracker{
		opts: opts, staleAfter: ledger.DefaultStaleAfter,
		agents: map[string]*tracked{}, offsets: map[string]int64{}, vms: map[string]VMInfo{},
		subs: map[uint64]chan struct{}{},
	}
}

// Configure applies a HostConfig: the pool connects to its agents, new
// agents start in Unknown, agents no longer declared are dropped (their
// ledger state becomes Unknown). Errors resolving an agent's address are
// returned; that agent stays tracked and turns Unreachable.
func (t *Tracker) Configure(ctx context.Context, hc *v1alpha1.HostConfig) error {
	eps := Endpoints(hc)
	err := t.opts.Pool.Sync(ctx, eps)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hc = hc.DeepCopy()
	t.staleAfter = ledger.DefaultStaleAfter
	if hc != nil && hc.Spec.StaleAfter != nil && hc.Spec.StaleAfter.Duration > 0 {
		t.staleAfter = hc.Spec.StaleAfter.Duration
	}
	seen := make(map[string]bool, len(eps))
	for _, ep := range eps {
		seen[ep.Name] = true
		t.addOrUpdateLocked(ep) //nolint:contextcheck // agent workers live as long as Start's context, not the caller's
	}
	for name, a := range t.agents {
		if !seen[name] {
			t.removeLocked(name, a)
		}
	}
	t.notifyLocked()
	return err
}

func (t *Tracker) addOrUpdateLocked(ep Endpoint) {
	a, ok := t.agents[ep.Name]
	if !ok {
		a = &tracked{ep: ep, st: AgentStatus{
			Name: ep.Name, Role: ep.Role, VM: ep.VM, State: ledger.AgentUnknown,
			Reason: StateReasonNotContacted, LastTransition: t.opts.Clock.Now(),
		}}
		t.agents[ep.Name] = a
		if t.opts.Metrics != nil {
			t.opts.Metrics.AgentState(ep.Name, ep.Role, ledger.AgentUnknown)
		}
		if t.runCtx != nil {
			t.startLocked(a)
		}
		return
	}
	if a.ep != ep {
		a.ep = ep
		a.st.Role, a.st.VM = ep.Role, ep.VM
		// Streams on the old connection end; restart them on the new one.
		a.healthW.stop()
		a.dataW.stop()
		a.healthW, a.dataW = nil, nil
		t.ensureWatchesLocked(a)
	}
}

func (t *Tracker) removeLocked(name string, a *tracked) {
	a.loop.stop()
	a.healthW.stop()
	a.dataW.stop()
	delete(t.agents, name)
	delete(t.offsets, name)
	if t.opts.Ledger != nil {
		t.opts.Ledger.SetAgentState(ledger.AgentName(name), ledger.AgentUnknown)
	}
	if t.opts.Metrics != nil {
		t.opts.Metrics.Forget(name)
	}
}

// Start runs the per-agent loops and watches until ctx is done. Each loop
// polls once per CheckInterval; the first poll happens one interval after
// Start (call Poll for an immediate one). It implements controller-runtime's
// manager.Runnable.
func (t *Tracker) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.runCtx != nil {
		t.mu.Unlock()
		return errors.New("agentclient: tracker already running")
	}
	t.runCtx = ctx
	for _, a := range t.agents {
		t.startLocked(a) //nolint:contextcheck // agent workers live as long as Start's context, not the caller's
	}
	t.mu.Unlock()

	<-ctx.Done()

	t.mu.Lock()
	var workers []*worker
	for _, a := range t.agents {
		workers = append(workers, a.loop, a.healthW, a.dataW)
		a.loop, a.healthW, a.dataW = nil, nil, nil
	}
	t.runCtx = nil
	t.mu.Unlock()
	for _, w := range workers {
		if w != nil {
			<-w.done
		}
	}
	return nil
}

// NeedLeaderElection reports true: only the leader talks to agents (§4.1).
func (t *Tracker) NeedLeaderElection() bool { return true }

func (t *Tracker) startLocked(a *tracked) {
	a.loop = t.spawnLocked(a, t.loop)
	t.ensureWatchesLocked(a)
}

func (t *Tracker) spawnLocked(a *tracked, fn func(context.Context, *tracked)) *worker {
	ctx, cancel := context.WithCancel(t.runCtx)
	w := &worker{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(w.done)
		defer cancel()
		fn(ctx, a)
	}()
	return w
}

func (t *Tracker) ensureWatchesLocked(a *tracked) {
	if t.runCtx == nil {
		return
	}
	if !a.healthW.alive() {
		a.healthW = t.spawnLocked(a, t.healthWatch)
	}
	if !a.dataW.alive() {
		a.dataW = t.spawnLocked(a, t.dataWatch)
	}
}

func (t *Tracker) loop(ctx context.Context, a *tracked) {
	for {
		timer := t.opts.Clock.NewTimer(t.opts.CheckInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
		t.pollAgent(ctx, a)
	}
}

// Poll runs one round for every agent now and returns when it is done: data
// polls, policy sync, health check, state update, rotation if due. While
// the tracker runs it also restarts watches that ended.
func (t *Tracker) Poll(ctx context.Context) {
	t.mu.Lock()
	agents := slices.Collect(maps.Values(t.agents))
	t.mu.Unlock()
	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Go(func() { t.pollAgent(ctx, a) })
	}
	wg.Wait()
}

func (t *Tracker) pollAgent(ctx context.Context, a *tracked) {
	a.pollMu.Lock()
	defer a.pollMu.Unlock()
	t.mu.Lock()
	if t.agents[a.ep.Name] != a {
		t.mu.Unlock()
		return // removed meanwhile
	}
	ep := a.ep
	t.ensureWatchesLocked(a) //nolint:contextcheck // agent workers live as long as Start's context, not the caller's
	t.mu.Unlock()

	if ep.Role == RoleHost {
		t.pollHost(ctx, a, ep)
	} else {
		t.pollGuest(ctx, a, ep)
	}
	st, err := t.check(ctx, ep)
	t.recordCheck(a, ep, st, err)
	t.maybeRotate(ctx, a, ep)
}

func serviceOf(r Role) string {
	if r == RoleHost {
		return HostAgentService
	}
	return GuestAgentService
}

func (t *Tracker) check(ctx context.Context, ep Endpoint) (HealthStatus, error) {
	h, err := t.opts.Pool.Health(ep.Name)
	if err != nil {
		return HealthUnknown, err
	}
	ctx, cancel := context.WithTimeout(ctx, t.opts.CheckTimeout)
	defer cancel()
	return h.Check(ctx, serviceOf(ep.Role))
}

func (t *Tracker) pollHost(ctx context.Context, a *tracked, ep Endpoint) {
	h, err := t.opts.Pool.Host(ep.Name)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, t.opts.CallTimeout)
	defer cancel()
	if info, err := h.GetHost(ctx); err == nil {
		t.observeHost(a, info)
		t.syncPolicy(ctx, a, h, info)
	}
	if vms, err := h.ListVMs(ctx); err == nil {
		t.observeVMs(vmsObservation(vms), vms)
	}
}

func (t *Tracker) pollGuest(ctx context.Context, a *tracked, ep Endpoint) {
	g, err := t.opts.Pool.Guest(ep.Name)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, t.opts.CallTimeout)
	defer cancel()
	if m, err := g.GetMemory(ctx); err == nil {
		t.observeGuest(a, ep, m)
	}
}

func (t *Tracker) healthWatch(ctx context.Context, a *tracked) {
	t.mu.Lock()
	ep := a.ep
	t.mu.Unlock()
	h, err := t.opts.Pool.Health(ep.Name)
	if err != nil {
		return
	}
	ch, err := h.Watch(ctx, serviceOf(ep.Role))
	if err != nil {
		return
	}
	for st := range ch {
		t.recordWatch(a, st)
	}
}

func (t *Tracker) dataWatch(ctx context.Context, a *tracked) {
	t.mu.Lock()
	ep := a.ep
	t.mu.Unlock()
	if ep.Role == RoleHost {
		h, err := t.opts.Pool.Host(ep.Name)
		if err != nil {
			return
		}
		ch, err := h.WatchVMs(ctx)
		if err != nil {
			return
		}
		for snap := range ch {
			t.observeVMs(snap.Observation(), snap.VMs)
		}
		return
	}
	g, err := t.opts.Pool.Guest(ep.Name)
	if err != nil {
		return
	}
	ch, err := g.WatchMemory(ctx)
	if err != nil {
		return
	}
	for m := range ch {
		t.observeGuest(a, ep, m)
	}
}

func (t *Tracker) observe(o ledger.Observation) {
	if t.opts.Ledger != nil {
		t.opts.Ledger.Observe(o)
	}
}

func (t *Tracker) observeHost(a *tracked, info HostInfo) {
	t.observe(ledger.Observation{Host: info.Observation()})
	t.mu.Lock()
	defer t.mu.Unlock()
	a.dataAt = later(a.dataAt, info.ObservedAt)
	t.seenLocked(a, info.Agent.Version)
	t.evaluateLocked(a)
}

func (t *Tracker) observeVMs(o ledger.Observation, vms []VMInfo) {
	t.observe(o)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.vms = make(map[string]VMInfo, len(vms))
	for _, v := range vms {
		t.vms[v.Name] = v
	}
	for vm := range t.agents {
		t.tryOffsetLocked(vm)
	}
}

func (t *Tracker) observeGuest(a *tracked, ep Endpoint, m GuestMemory) {
	t.observe(ledger.Observation{Guest: m.Observation(ep.VM)})
	t.mu.Lock()
	defer t.mu.Unlock()
	a.dataAt = later(a.dataAt, m.ObservedAt)
	if !m.ObservedAt.Before(a.guestAt) {
		a.guestTotal, a.guestAt = m.Total, m.ObservedAt
	}
	t.seenLocked(a, m.Agent.Version)
	t.tryOffsetLocked(ep.Name)
	t.evaluateLocked(a)
}

// seenLocked records a successful call.
func (t *Tracker) seenLocked(a *tracked, version string) {
	a.st.LastSeen = t.opts.Clock.Now()
	if version != "" && version != a.st.Version {
		a.st.Version = version
		t.notifyLocked()
	}
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// tryOffsetLocked records offset(vm) = assigned − guest total once, from a
// running VM's host data and a guest reading that are both fresh.
func (t *Tracker) tryOffsetLocked(name string) {
	a, ok := t.agents[name]
	if !ok || a.ep.Role != RoleGuest {
		return
	}
	if _, done := t.offsets[name]; done {
		return
	}
	v, ok := t.vms[a.ep.VM]
	now := t.opts.Clock.Now()
	if !ok || v.State != VMStateRunning || v.Assigned <= 0 || !t.freshLocked(now, v.ObservedAt) || !t.freshLocked(now, a.guestAt) {
		return
	}
	t.offsets[name] = Offset(v.Assigned, a.guestTotal)
}

func (t *Tracker) freshLocked(now, at time.Time) bool {
	return !at.IsZero() && now.Sub(at) <= t.staleAfter
}

// Offset returns offset(vm) as recorded on first contact (DESIGN §4.4):
// the VM's assigned memory minus its guest's total. The grant executor
// verifies a grow with Verified(guestTotal, newAssigned, offset, step).
func (t *Tracker) Offset(vm string) (int64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	o, ok := t.offsets[vm]
	return o, ok
}

func (t *Tracker) syncPolicy(ctx context.Context, a *tracked, h Host, info HostInfo) {
	t.mu.Lock()
	hc := t.hc
	t.mu.Unlock()
	st := a.policy.Sync(ctx, h, hc, info)
	t.mu.Lock()
	defer t.mu.Unlock()
	prev := a.st.Policy
	a.st.Policy = &st
	t.policyEventsLocked(a, prev, st)
	if prev == nil || prev.InSync != st.InSync || prev.Desired != st.Desired || prev.Active != st.Active || prev.Pending != st.Pending {
		t.notifyLocked()
	}
}

func (t *Tracker) policyEventsLocked(a *tracked, prev *PolicyStatus, st PolicyStatus) {
	switch {
	case st.Proposed && st.Err != nil:
		t.emitLocked(a, corev1.EventTypeWarning, ReasonPolicyProposalFailed, "ProposePolicy",
			fmt.Sprintf("proposing policy %s failed: %v", st.Desired, st.Err))
	case st.Proposed:
		t.emitLocked(a, corev1.EventTypeNormal, ReasonPolicyProposed, "ProposePolicy",
			fmt.Sprintf("proposed policy %s (active %s); activate it on the host with `hvmc agent policy sync`", st.Desired, st.Active))
	}
	if prev != nil && prev.InSync == st.InSync {
		return
	}
	if st.InSync {
		t.emitLocked(a, corev1.EventTypeNormal, ReasonPolicyInSync, "PolicySync", "active policy matches HostConfig ("+st.Active+")")
		return
	}
	t.emitLocked(a, corev1.EventTypeWarning, ReasonPolicyOutOfSync, "PolicySync",
		fmt.Sprintf("active policy %s differs from the policy %s derived from HostConfig", st.Active, st.Desired))
}

func (t *Tracker) recordCheck(a *tracked, ep Endpoint, st HealthStatus, err error) {
	peer := t.opts.Pool.PeerCertificate(ep.Name)
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		a.failures++
		a.lastErr = err
	} else {
		a.failures, a.lastErr = 0, nil
		a.contacted, a.serving = true, st == HealthServing
		t.seenLocked(a, "")
	}
	if peer != nil {
		a.peer = peer
	}
	t.evaluateLocked(a)
}

func (t *Tracker) recordWatch(a *tracked, st HealthStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a.failures, a.lastErr = 0, nil
	a.contacted, a.serving = true, st == HealthServing
	t.seenLocked(a, "")
	t.evaluateLocked(a)
}

// state derives an agent's state from what the tracker knows.
func (t *Tracker) stateLocked(a *tracked, now time.Time) (ledger.AgentState, string, string) {
	switch {
	case a.failures >= t.opts.FailureThreshold:
		return ledger.AgentUnreachable, StateReasonUnreachable,
			fmt.Sprintf("%d consecutive health checks failed, last: %v", a.failures, a.lastErr)
	case !a.contacted:
		return ledger.AgentUnknown, StateReasonNotContacted, "not contacted yet"
	case !a.serving:
		return ledger.AgentDegraded, StateReasonNotServing, "agent reports NOT_SERVING"
	case !t.freshLocked(now, a.dataAt):
		return ledger.AgentDegraded, StateReasonDataStale, fmt.Sprintf("no data newer than %s", t.staleAfter)
	default:
		return ledger.AgentReady, StateReasonServing, "serving with fresh data"
	}
}

func (t *Tracker) evaluateLocked(a *tracked) {
	now := t.opts.Clock.Now()
	t.certLocked(a, now)
	s, reason, msg := t.stateLocked(a, now)
	a.st.ConsecutiveFailures = a.failures
	if s == a.st.State && reason == a.st.Reason {
		a.st.Message = msg
		return
	}
	changed := s != a.st.State
	a.st.State, a.st.Reason, a.st.Message = s, reason, msg
	t.notifyLocked()
	if !changed {
		return
	}
	a.st.LastTransition = now
	if t.opts.Ledger != nil {
		t.opts.Ledger.SetAgentState(ledger.AgentName(a.ep.Name), s)
	}
	if t.opts.Metrics != nil {
		t.opts.Metrics.AgentState(a.ep.Name, a.ep.Role, s)
	}
	switch s {
	case ledger.AgentReady:
		t.emitLocked(a, corev1.EventTypeNormal, ReasonAgentReady, "HealthCheck", "agent is Ready")
	case ledger.AgentDegraded:
		t.emitLocked(a, corev1.EventTypeWarning, ReasonAgentDegraded, "HealthCheck", "agent is Degraded: "+msg)
	case ledger.AgentUnreachable:
		t.emitLocked(a, corev1.EventTypeWarning, ReasonAgentUnreachable, "HealthCheck", "agent is Unreachable: "+msg)
	default:
	}
}

// knownCert is the newer of the presented and the installed certificate.
func (a *tracked) knownCert() *x509.Certificate {
	switch {
	case a.installed == nil:
		return a.peer
	case a.peer == nil || a.installed.NotAfter.After(a.peer.NotAfter):
		return a.installed
	default:
		return a.peer
	}
}

func (t *Tracker) certLocked(a *tracked, now time.Time) {
	c := a.knownCert()
	if c == nil {
		return
	}
	valid := !now.Before(c.NotBefore) && !now.After(c.NotAfter)
	if c.NotAfter.Equal(a.st.CertNotAfter) && valid == a.st.CertificateValid {
		return
	}
	if !c.NotAfter.Equal(a.st.CertNotAfter) && t.opts.Metrics != nil {
		t.opts.Metrics.CertExpiry(a.ep.Name, a.ep.Role, c.NotAfter)
	}
	a.st.CertNotAfter, a.st.CertificateValid = c.NotAfter, valid
	t.notifyLocked()
}

func (t *Tracker) maybeRotate(ctx context.Context, a *tracked, ep Endpoint) {
	if t.opts.Rotator == nil {
		return
	}
	t.mu.Lock()
	now := t.opts.Clock.Now()
	due := a.contacted && a.failures == 0 && RotationDue(a.knownCert(), now) && !now.Before(a.nextRotate)
	hc := t.hc
	t.mu.Unlock()
	if !due {
		return
	}
	certs, err := t.opts.Pool.Certs(ep.Name)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, t.opts.CallTimeout)
	defer cancel()
	cert, err := t.opts.Rotator.Rotate(ctx, hc, ep.Name, certs)
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		a.nextRotate = t.opts.Clock.Now().Add(t.opts.RotationRetry)
		return
	}
	a.installed = cert
	t.certLocked(a, t.opts.Clock.Now())
}

func (t *Tracker) emitLocked(a *tracked, typ, reason, action, msg string) {
	if t.opts.Events != nil {
		t.opts.Events.Emit(Event{Agent: a.ep.Name, Type: typ, Reason: reason, Action: action, Message: msg})
	}
}

// Status returns one agent's status.
func (t *Tracker) Status(agent string) (AgentStatus, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.agents[agent]
	if !ok {
		return AgentStatus{}, false
	}
	return a.statusLocked(), true
}

// Statuses returns every agent's status, ordered by name.
func (t *Tracker) Statuses() []AgentStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]AgentStatus, 0, len(t.agents))
	for _, a := range t.agents {
		out = append(out, a.statusLocked())
	}
	slices.SortFunc(out, func(x, y AgentStatus) int { return strings.Compare(x.Name, y.Name) })
	return out
}

func (a *tracked) statusLocked() AgentStatus {
	st := a.st
	if a.st.Policy != nil {
		p := *a.st.Policy
		st.Policy = &p
	}
	return st
}

// Subscribe returns a channel that receives a value after any status
// change; changes in quick succession may be coalesced into one value. Read
// the new state with Statuses. cancel ends the subscription.
func (t *Tracker) Subscribe() (<-chan struct{}, func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.subSeq++
	id := t.subSeq
	ch := make(chan struct{}, 1)
	t.subs[id] = ch
	return ch, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		delete(t.subs, id)
	}
}

func (t *Tracker) notifyLocked() {
	for _, ch := range t.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
