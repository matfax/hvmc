package agentclient

import (
	"context"
	"time"

	"google.golang.org/grpc"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
	"github.com/matfax/hvmc/internal/ledger"
	"github.com/matfax/hvmc/internal/policy"
)

// Host is the host agent (DESIGN §4.2). Errors are *RPCError (errors.go).
type Host interface {
	// GetHost returns host memory, the agent's identity and the digests of
	// its active and pending policies.
	GetHost(ctx context.Context) (HostInfo, error)
	// ListVMs returns every VM on the host, managed or not.
	ListVMs(ctx context.Context) ([]VMInfo, error)
	// WatchVMs returns the first full snapshot as soon as the agent sends
	// it, then one per change. The channel is closed when the stream ends
	// (agent gone, vmms down, ctx done); the caller watches again.
	WatchVMs(ctx context.Context) (<-chan VMSnapshot, error)
	// SetStartup sets a static VM's startup memory (runtime resize).
	SetStartup(ctx context.Context, vm string, bytes int64) (ResizeResult, error)
	// SetDynamicLimits changes a Dynamic Memory VM's minimum and/or maximum;
	// nil leaves a limit unchanged.
	SetDynamicLimits(ctx context.Context, vm string, minimum, maximum *int64) (ResizeResult, error)
	// ProposePolicy stores p as the agent's pending policy; it never changes
	// the active one (DESIGN §4.3).
	ProposePolicy(ctx context.Context, p policy.Policy) error
}

// AgentInfo identifies the agent software answering a call.
type AgentInfo struct {
	Version string
	// Role is "host" or "guest"; empty if the agent did not say.
	Role Role
	// OS is "linux" or "windows"; empty if the agent did not say.
	OS string
}

// HostInfo is GetHost's result.
type HostInfo struct {
	Name  string
	Total int64
	Free  int64
	Agent AgentInfo
	// PolicyDigest is the digest of the agent's active policy.
	PolicyDigest string
	// PendingPolicyDigest is the digest of a proposed, not yet activated
	// policy; empty if none.
	PendingPolicyDigest string
	ObservedAt          time.Time
}

// Observation returns the host data in the ledger's form.
func (h HostInfo) Observation() *ledger.HostObservation {
	return &ledger.HostObservation{Total: h.Total, Free: h.Free, ObservedAt: h.ObservedAt}
}

// VMState is the coarse Hyper-V state of a VM.
type VMState string

// VM states (host.proto VMState).
const (
	VMStateUnknown   VMState = ""
	VMStateOther     VMState = "Other"
	VMStateOff       VMState = "Off"
	VMStateStarting  VMState = "Starting"
	VMStateRunning   VMState = "Running"
	VMStateStopping  VMState = "Stopping"
	VMStateSaving    VMState = "Saving"
	VMStateSaved     VMState = "Saved"
	VMStatePausing   VMState = "Pausing"
	VMStatePaused    VMState = "Paused"
	VMStateResuming  VMState = "Resuming"
	VMStateResetting VMState = "Resetting"
)

var vmStates = map[agentv1.VMState]VMState{
	agentv1.VMState_VM_STATE_OTHER:     VMStateOther,
	agentv1.VMState_VM_STATE_OFF:       VMStateOff,
	agentv1.VMState_VM_STATE_STARTING:  VMStateStarting,
	agentv1.VMState_VM_STATE_RUNNING:   VMStateRunning,
	agentv1.VMState_VM_STATE_STOPPING:  VMStateStopping,
	agentv1.VMState_VM_STATE_SAVING:    VMStateSaving,
	agentv1.VMState_VM_STATE_SAVED:     VMStateSaved,
	agentv1.VMState_VM_STATE_PAUSING:   VMStatePausing,
	agentv1.VMState_VM_STATE_PAUSED:    VMStatePaused,
	agentv1.VMState_VM_STATE_RESUMING:  VMStateResuming,
	agentv1.VMState_VM_STATE_RESETTING: VMStateResetting,
}

// DynamicMemory is a VM's Dynamic Memory configuration.
type DynamicMemory struct {
	Minimum       int64
	Maximum       int64
	BufferPercent int32
	Priority      int32
}

// VMInfo is one VM as the host agent reports it.
type VMInfo struct {
	Name string
	ID   string
	// State is the coarse state; HyperVState is Hyper-V's own string.
	State       VMState
	HyperVState string
	Assigned    int64
	Startup     int64
	// Dynamic is set when Dynamic Memory is enabled.
	Dynamic    *DynamicMemory
	ObservedAt time.Time
}

// Observation returns the VM in the ledger's form.
func (v VMInfo) Observation() ledger.VMObservation {
	o := ledger.VMObservation{Name: ledger.VMName(v.Name), Assigned: v.Assigned, Startup: v.Startup, ObservedAt: v.ObservedAt}
	if d := v.Dynamic; d != nil {
		o.Dynamic = &ledger.DynamicMemory{Minimum: d.Minimum, Maximum: d.Maximum, Buffer: int64(d.BufferPercent), Priority: int(d.Priority)}
	}
	return o
}

// VMSnapshot is the state of every VM on the host at one point in time.
type VMSnapshot struct {
	VMs        []VMInfo
	ObservedAt time.Time
}

// Observation returns the snapshot as the host's complete VM list.
func (s VMSnapshot) Observation() ledger.Observation {
	return vmsObservation(s.VMs)
}

func vmsObservation(vms []VMInfo) ledger.Observation {
	o := ledger.Observation{CompleteVMList: true, VMs: make([]ledger.VMObservation, 0, len(vms))}
	for _, v := range vms {
		o.VMs = append(o.VMs, v.Observation())
	}
	return o
}

// ResizeResult is a VM before and after a write.
type ResizeResult struct {
	Before VMInfo
	After  VMInfo
}

// Outcome returns the result in the ledger's form (Commit, CommitShrink).
func (r ResizeResult) Outcome() ledger.ResizeOutcome {
	out := ledger.ResizeOutcome{
		AssignedBefore: r.Before.Assigned, AssignedAfter: r.After.Assigned,
		StartupBefore: r.Before.Startup, StartupAfter: r.After.Startup,
		ObservedAt: r.After.ObservedAt,
	}
	if d := r.After.Dynamic; d != nil {
		out.MaximumAfter = d.Maximum
	}
	return out
}

func agentInfoFromProto(a *agentv1.AgentInfo) AgentInfo {
	info := AgentInfo{Version: a.GetVersion()}
	switch a.GetRole() {
	case agentv1.AgentRole_AGENT_ROLE_HOST:
		info.Role = RoleHost
	case agentv1.AgentRole_AGENT_ROLE_GUEST:
		info.Role = RoleGuest
	default:
	}
	switch a.GetOperatingSystem() {
	case agentv1.OperatingSystem_OPERATING_SYSTEM_LINUX:
		info.OS = "linux"
	case agentv1.OperatingSystem_OPERATING_SYSTEM_WINDOWS:
		info.OS = "windows"
	default:
	}
	return info
}

func hostInfoFromProto(h *agentv1.Host) HostInfo {
	return HostInfo{
		Name: h.GetName(), Total: h.GetTotalBytes(), Free: h.GetFreeBytes(),
		Agent:        agentInfoFromProto(h.GetAgent()),
		PolicyDigest: h.GetPolicyDigest(), PendingPolicyDigest: h.GetPendingPolicyDigest(),
		ObservedAt: timeOf(h.GetObservedAt()),
	}
}

func vmFromProto(v *agentv1.VM) VMInfo {
	out := VMInfo{
		Name: v.GetName(), ID: v.GetId(), State: vmStates[v.GetState()], HyperVState: v.GetHypervState(),
		Assigned: v.GetAssignedBytes(), Startup: v.GetStartupBytes(), ObservedAt: timeOf(v.GetObservedAt()),
	}
	if d := v.GetDynamicMemory(); d.GetEnabled() {
		out.Dynamic = &DynamicMemory{
			Minimum: d.GetMinimumBytes(), Maximum: d.GetMaximumBytes(),
			BufferPercent: d.GetBufferPercent(), Priority: d.GetPriority(),
		}
	}
	return out
}

func snapshotFromProto(s *agentv1.VMSnapshot) VMSnapshot {
	out := VMSnapshot{ObservedAt: timeOf(s.GetObservedAt()), VMs: make([]VMInfo, 0, len(s.GetVms()))}
	for _, v := range s.GetVms() {
		out.VMs = append(out.VMs, vmFromProto(v))
	}
	return out
}

func resizeResultFromProto(r *agentv1.ResizeResult) ResizeResult {
	return ResizeResult{Before: vmFromProto(r.GetBefore()), After: vmFromProto(r.GetAfter())}
}

// hostClient implements Host over gRPC.
type hostClient struct {
	agent string
	c     agentv1.HostAgentClient
}

func newHostClient(agent string, cc grpc.ClientConnInterface) *hostClient {
	return &hostClient{agent: agent, c: agentv1.NewHostAgentClient(cc)}
}

func (h *hostClient) call(method string, write bool) call {
	return call{agent: h.agent, method: method, host: true, write: write}
}

// GetHost implements Host.
func (h *hostClient) GetHost(ctx context.Context) (HostInfo, error) {
	resp, err := h.c.GetHost(ctx, &agentv1.GetHostRequest{})
	if err != nil {
		return HostInfo{}, h.call("GetHost", false).wrap(err)
	}
	return hostInfoFromProto(resp.GetHost()), nil
}

// ListVMs implements Host.
func (h *hostClient) ListVMs(ctx context.Context) ([]VMInfo, error) {
	resp, err := h.c.ListVMs(ctx, &agentv1.ListVMsRequest{})
	if err != nil {
		return nil, h.call("ListVMs", false).wrap(err)
	}
	return snapshotFromProto(resp.GetSnapshot()).VMs, nil
}

// WatchVMs implements Host.
func (h *hostClient) WatchVMs(ctx context.Context) (<-chan VMSnapshot, error) {
	c := h.call("WatchVMs", false)
	return watch(ctx, c, func(ctx context.Context) (grpc.ServerStreamingClient[agentv1.WatchVMsResponse], error) {
		return h.c.WatchVMs(ctx, &agentv1.WatchVMsRequest{})
	}, func(m *agentv1.WatchVMsResponse) VMSnapshot { return snapshotFromProto(m.GetSnapshot()) })
}

// SetStartup implements Host.
func (h *hostClient) SetStartup(ctx context.Context, vm string, bytes int64) (ResizeResult, error) {
	resp, err := h.c.SetStartup(ctx, &agentv1.SetStartupRequest{VmName: vm, StartupBytes: bytes})
	if err != nil {
		return ResizeResult{}, h.call("SetStartup", true).wrap(err)
	}
	return resizeResultFromProto(resp.GetResult()), nil
}

// SetDynamicLimits implements Host.
func (h *hostClient) SetDynamicLimits(ctx context.Context, vm string, minimum, maximum *int64) (ResizeResult, error) {
	resp, err := h.c.SetDynamicLimits(ctx, &agentv1.SetDynamicLimitsRequest{VmName: vm, MinimumBytes: minimum, MaximumBytes: maximum})
	if err != nil {
		return ResizeResult{}, h.call("SetDynamicLimits", true).wrap(err)
	}
	return resizeResultFromProto(resp.GetResult()), nil
}

// ProposePolicy implements Host. The digest sent along is p.Digest(), the
// canonical digest the agent recomputes.
func (h *hostClient) ProposePolicy(ctx context.Context, p policy.Policy) error {
	_, err := h.c.ProposePolicy(ctx, &agentv1.ProposePolicyRequest{Policy: p.Proto(), Digest: p.Digest()})
	return h.call("ProposePolicy", false).wrap(err)
}

// watch opens a server stream and returns its first message's arrival as
// the call's result: an error if the stream fails before the first message,
// otherwise a channel carrying that message and every later one. The channel
// is closed when the stream ends or ctx is done.
func watch[M any, T any](ctx context.Context, c call,
	open func(context.Context) (grpc.ServerStreamingClient[M], error), conv func(*M) T,
) (<-chan T, error) {
	ctx, cancel := context.WithCancel(ctx)
	stream, err := open(ctx)
	if err != nil {
		cancel()
		return nil, c.wrap(err)
	}
	first, err := stream.Recv()
	if err != nil {
		cancel()
		return nil, c.wrap(err)
	}
	out := make(chan T, 1)
	out <- conv(first)
	go func() {
		defer cancel()
		defer close(out)
		for {
			m, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case out <- conv(m):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
