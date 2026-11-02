package agent

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// startRun runs the agent without the env's cleanup so a test controls
// the stop.
func startRun(t *testing.T, e *env) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done, envDone := make(chan error, 1), make(chan error, 1)
	go func() {
		err := e.agent.Run(ctx)
		done <- err
		envDone <- err
	}()
	<-e.agent.Started()
	e.clk.waitTimer(t)
	e.stop, e.done = cancel, envDone
	t.Cleanup(func() { _ = e.shutdown() })
	return cancel, done
}

func notDone(t *testing.T, done chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("Run returned (%v) %s", err, what)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDrainWaitsForInFlightCalls(t *testing.T) {
	svc := newTestService()
	e := newEnv(t, hostConfigYAML, svc)
	cancel, done := startRun(t, e)
	host := agentv1.NewHostAgentClient(e.dial(CoordinatorClientCN))

	// An open stream must not hold up the drain.
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	stream, err := host.WatchVMs(ctx, &agentv1.WatchVMsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}

	block := make(chan struct{})
	svc.setBlock(block)
	inFlight := make(chan error, 1)
	go func() {
		_, err := host.GetHost(ctx, &agentv1.GetHostRequest{})
		inFlight <- err
	}()
	<-svc.entered

	cancel()
	if _, err := stream.Recv(); err == nil {
		t.Error("stream still open after drain started")
	}
	notDone(t, done, "while a call was in flight")
	resp, err := e.agent.health.Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("health while draining: %v, %v; want NOT_SERVING", resp.GetStatus(), err)
	}

	close(block)
	if err := <-inFlight; err != nil {
		t.Errorf("in-flight call failed during the drain: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the last call finished")
	}
}

func TestDrainForcedAfterTimeout(t *testing.T) {
	svc := newTestService()
	e := newEnv(t, hostConfigYAML, svc)
	cancel, done := startRun(t, e)
	host := agentv1.NewHostAgentClient(e.dial(CoordinatorClientCN))
	block := make(chan struct{})
	defer close(block)
	svc.setBlock(block)
	inFlight := make(chan error, 1)
	go func() {
		_, err := host.GetHost(context.Background(), &agentv1.GetHostRequest{})
		inFlight <- err
	}()
	<-svc.entered

	cancel()
	notDone(t, done, "before the drain timeout")
	for {
		e.clk.Advance(DrainTimeout)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
			if got := e.clk.Now().Sub(t0); got < DrainTimeout {
				t.Errorf("forced stop after %v, want ≥ %v", got, DrainTimeout)
			}
			if err := <-inFlight; status.Code(err) != codes.Unavailable {
				t.Errorf("call cut off by the drain: %v, want Unavailable", err)
			}
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestDrainWithin(t *testing.T) {
	clk := newTestClock()
	release := make(chan struct{})
	forced := make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		result <- drainWithin(clk, DrainTimeout, func() { <-release }, func() { close(forced); close(release) })
	}()
	clk.waitTimer(t)
	clk.Advance(DrainTimeout - time.Millisecond)
	select {
	case <-forced:
		t.Fatal("forced before the timeout")
	case <-time.After(20 * time.Millisecond):
	}
	clk.Advance(time.Millisecond)
	if <-result {
		t.Error("drainWithin reported a graceful stop after forcing")
	}
	<-release
	if !drainWithin(clk, DrainTimeout, func() {}, func() { t.Error("forced a graceful stop") }) {
		t.Error("graceful stop reported as forced")
	}
	if clk.Timers() != 0 {
		t.Errorf("%d timers left", clk.Timers())
	}
}
