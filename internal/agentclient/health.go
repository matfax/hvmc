package agentclient

import (
	"context"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// Health service names an agent serves (common.proto): "" is the agent as a
// whole.
var (
	HostAgentService  = agentv1.HostAgent_ServiceDesc.ServiceName
	GuestAgentService = agentv1.GuestAgent_ServiceDesc.ServiceName
)

// Health is grpc.health.v1 as every agent serves it (DESIGN §4.8). Errors
// are *RPCError (errors.go).
type Health interface {
	// Check returns the serving status of service.
	Check(ctx context.Context, service string) (HealthStatus, error)
	// Watch returns the current status as soon as the agent sends it, then
	// every change. The channel is closed when the stream ends.
	Watch(ctx context.Context, service string) (<-chan HealthStatus, error)
}

// HealthStatus is a grpc.health.v1 serving status.
type HealthStatus string

// Serving statuses.
const (
	HealthUnknown        HealthStatus = "Unknown"
	HealthServing        HealthStatus = "Serving"
	HealthNotServing     HealthStatus = "NotServing"
	HealthServiceUnknown HealthStatus = "ServiceUnknown"
)

func healthStatusFromProto(s healthpb.HealthCheckResponse_ServingStatus) HealthStatus {
	switch s {
	case healthpb.HealthCheckResponse_SERVING:
		return HealthServing
	case healthpb.HealthCheckResponse_NOT_SERVING:
		return HealthNotServing
	case healthpb.HealthCheckResponse_SERVICE_UNKNOWN:
		return HealthServiceUnknown
	default:
		return HealthUnknown
	}
}

// healthClient implements Health over gRPC.
type healthClient struct {
	agent string
	c     healthpb.HealthClient
}

func newHealthClient(agent string, cc grpc.ClientConnInterface) *healthClient {
	return &healthClient{agent: agent, c: healthpb.NewHealthClient(cc)}
}

// Check implements Health.
func (h *healthClient) Check(ctx context.Context, service string) (HealthStatus, error) {
	resp, err := h.c.Check(ctx, &healthpb.HealthCheckRequest{Service: service})
	if err != nil {
		return HealthUnknown, call{agent: h.agent, method: "Check"}.wrap(err)
	}
	return healthStatusFromProto(resp.GetStatus()), nil
}

// Watch implements Health.
func (h *healthClient) Watch(ctx context.Context, service string) (<-chan HealthStatus, error) {
	return watch(ctx, call{agent: h.agent, method: "Watch"},
		func(ctx context.Context) (grpc.ServerStreamingClient[healthpb.HealthCheckResponse], error) {
			return h.c.Watch(ctx, &healthpb.HealthCheckRequest{Service: service})
		},
		func(m *healthpb.HealthCheckResponse) HealthStatus { return healthStatusFromProto(m.GetStatus()) })
}
