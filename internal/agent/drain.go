package agent

import (
	"context"
	"time"

	"google.golang.org/grpc"
)

// DrainTimeout is how long a stopping agent waits for in-flight calls
// (DESIGN §4.5: SCM stop/shutdown/preshutdown and SIGTERM).
const DrainTimeout = 20 * time.Second

// drain stops the agent in this order:
//
//  1. grpc.health.v1 reports NOT_SERVING for every service, so the
//     coordinator's health tracker sees the stop instead of a timeout;
//  2. every open stream (Health.Watch, WatchVMs, WatchMemory) ends: their
//     contexts are cancelled by the drain stream interceptor, since a
//     stream never finishes by itself and would hold up the drain;
//  3. the gRPC server stops accepting connections and waits for in-flight
//     unary calls, at most DrainTimeout on the agent's clock, then closes
//     what is left;
//  4. the health HTTP server closes.
func (a *Agent) drain() {
	a.log.Info("draining", "timeout", DrainTimeout)
	a.health.Shutdown()
	close(a.draining)
	if !drainWithin(a.clk, DrainTimeout, a.grpc.GracefulStop, a.grpc.Stop) {
		a.log.Warn("drain timed out; closed the remaining connections", "timeout", DrainTimeout)
	}
	_ = a.http.Close()
}

// drainWithin runs graceful and calls force if graceful has not returned
// after timeout on clk. It reports whether graceful finished in time. After
// force it does not wait for graceful any longer: a handler that ignores
// its cancelled context must not keep the agent from stopping.
func drainWithin(clk Clock, timeout time.Duration, graceful, force func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		graceful()
	}()
	t := clk.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C():
		force()
		return false
	}
}

// drainStream ends a stream's context when draining starts.
func (a *Agent) drainStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, cancel := context.WithCancel(ss.Context())
	defer cancel()
	go func() {
		select {
		case <-a.draining:
			cancel()
		case <-ctx.Done():
		}
	}()
	return handler(srv, &drainingStream{ServerStream: ss, ctx: ctx})
}

// drainingStream replaces a stream's context.
type drainingStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *drainingStream) Context() context.Context { return s.ctx }
