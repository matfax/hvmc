package agentclient

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
	"github.com/matfax/hvmc/internal/ledger"
)

// Guest is a guest agent (DESIGN §4.4). Errors are *RPCError (errors.go).
type Guest interface {
	// GetMemory reads the guest's memory now.
	GetMemory(ctx context.Context) (GuestMemory, error)
	// WatchMemory returns the first reading as soon as the agent sends it,
	// then one every 5 s and on change. The channel is closed when the
	// stream ends; the caller watches again.
	WatchMemory(ctx context.Context) (<-chan GuestMemory, error)
}

// GuestMemory is one reading of a guest's memory. used = Total − Available.
type GuestMemory struct {
	Total     int64
	Available int64
	// CommitLimit and CommitAvailable are set by Windows guests only.
	CommitLimit     *int64
	CommitAvailable *int64
	ObservedAt      time.Time
	// Agent is set by GetMemory only.
	Agent AgentInfo
}

// Observation returns the reading in the ledger's form for vm.
func (m GuestMemory) Observation(vm string) *ledger.GuestObservation {
	o := &ledger.GuestObservation{VM: ledger.VMName(vm), Total: m.Total, Available: m.Available, ObservedAt: m.ObservedAt}
	if m.CommitLimit != nil {
		o.CommitLimit = *m.CommitLimit
	}
	if m.CommitAvailable != nil {
		o.CommitAvailable = *m.CommitAvailable
	}
	return o
}

// Offset is the difference between a VM's assigned memory and its guest's
// total (firmware and kernel reservations), recorded on first contact
// (DESIGN §4.4).
func Offset(assigned, guestTotal int64) int64 { return assigned - guestTotal }

// Verified reports whether a grow to assigned is visible in the guest:
// guest total ≥ assigned − offset − step/2 (DESIGN §4.4).
func Verified(guestTotal, assigned, offset, step int64) bool {
	return guestTotal >= assigned-offset-step/2
}

func guestMemoryFromProto(m *agentv1.GuestMemory) GuestMemory {
	out := GuestMemory{Total: m.GetTotalBytes(), Available: m.GetAvailableBytes(), ObservedAt: timeOf(m.GetObservedAt())}
	if m.CommitLimitBytes != nil {
		v := m.GetCommitLimitBytes()
		out.CommitLimit = &v
	}
	if m.CommitAvailableBytes != nil {
		v := m.GetCommitAvailableBytes()
		out.CommitAvailable = &v
	}
	return out
}

// timeOf converts a timestamp; nil is the zero time.
func timeOf(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// guestClient implements Guest over gRPC.
type guestClient struct {
	agent string
	c     agentv1.GuestAgentClient
}

func newGuestClient(agent string, cc grpc.ClientConnInterface) *guestClient {
	return &guestClient{agent: agent, c: agentv1.NewGuestAgentClient(cc)}
}

// GetMemory implements Guest.
func (g *guestClient) GetMemory(ctx context.Context) (GuestMemory, error) {
	resp, err := g.c.GetMemory(ctx, &agentv1.GetMemoryRequest{})
	if err != nil {
		return GuestMemory{}, call{agent: g.agent, method: "GetMemory"}.wrap(err)
	}
	m := guestMemoryFromProto(resp.GetMemory())
	m.Agent = agentInfoFromProto(resp.GetAgent())
	return m, nil
}

// WatchMemory implements Guest.
func (g *guestClient) WatchMemory(ctx context.Context) (<-chan GuestMemory, error) {
	return watch(ctx, call{agent: g.agent, method: "WatchMemory"},
		func(ctx context.Context) (grpc.ServerStreamingClient[agentv1.WatchMemoryResponse], error) {
			return g.c.WatchMemory(ctx, &agentv1.WatchMemoryRequest{})
		},
		func(m *agentv1.WatchMemoryResponse) GuestMemory { return guestMemoryFromProto(m.GetMemory()) })
}
