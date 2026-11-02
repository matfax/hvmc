package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// testService is a stand-in for the host role: it registers HostAgent,
// one readiness check and delegates ProposePolicy to the framework.
type testService struct {
	agentv1.UnimplementedHostAgentServer
	deps Deps

	mu       sync.Mutex
	checkErr error
	block    chan struct{} // check and GetHost block on it when set
	entered  chan struct{} // GetHost signals here when it starts
	checking chan struct{} // check signals here before it blocks
	runErr   error
}

func newTestService() *testService {
	return &testService{entered: make(chan struct{}, 10), checking: make(chan struct{}, 10)}
}

func (s *testService) ServiceName() string { return agentv1.HostAgent_ServiceDesc.ServiceName }

func (s *testService) Register(reg grpc.ServiceRegistrar, deps Deps) error {
	s.deps = deps
	agentv1.RegisterHostAgentServer(reg, s)
	return deps.Readiness.Register("test", s.check)
}

func (s *testService) Run(ctx context.Context) error {
	if s.runErr != nil {
		return s.runErr
	}
	<-ctx.Done()
	return nil
}

func (s *testService) setCheck(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkErr = err
}

func (s *testService) setBlock(ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.block = ch
}

func (s *testService) check(context.Context) error {
	s.mu.Lock()
	err, block := s.checkErr, s.block
	s.mu.Unlock()
	if block != nil {
		s.checking <- struct{}{}
		<-block
	}
	return err
}

func (s *testService) GetHost(ctx context.Context, _ *agentv1.GetHostRequest) (*agentv1.GetHostResponse, error) {
	s.entered <- struct{}{}
	s.mu.Lock()
	block := s.block
	s.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
	return &agentv1.GetHostResponse{Host: &agentv1.Host{PolicyDigest: s.deps.Policy.ActiveDigest()}}, nil
}

func (s *testService) WatchVMs(_ *agentv1.WatchVMsRequest, stream agentv1.HostAgent_WatchVMsServer) error {
	if err := stream.Send(&agentv1.WatchVMsResponse{}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return status.FromContextError(stream.Context().Err()).Err()
}

func (s *testService) SetStartup(ctx context.Context, req *agentv1.SetStartupRequest) (*agentv1.SetStartupResponse, error) {
	SetAuditBefore(ctx, map[string]int64{"startupBytes": 4 << 30})
	if req.GetStartupBytes() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "startup_bytes must be positive")
	}
	SetAuditAfter(ctx, map[string]int64{"startupBytes": req.GetStartupBytes()})
	return &agentv1.SetStartupResponse{}, nil
}

func (s *testService) ProposePolicy(ctx context.Context, req *agentv1.ProposePolicyRequest) (*agentv1.ProposePolicyResponse, error) {
	return s.deps.Policy.ProposePolicy(ctx, req)
}

func healthCheck(t *testing.T, conn *grpc.ClientConn, service string) (healthpb.HealthCheckResponse_ServingStatus, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: service})
	return resp.GetStatus(), err
}

func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestClientCNRejection(t *testing.T) {
	e := newEnv(t, hostConfigYAML, newTestService())
	e.start()

	ok := e.dial(CoordinatorClientCN)
	if st, err := healthCheck(t, ok, ""); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("allowed client: status %v, err %v", st, err)
	}

	bad := e.dial("intruder")
	if _, err := healthCheck(t, bad, ""); status.Code(err) != codes.Unauthenticated {
		t.Errorf("unary call from CN intruder: %v, want Unauthenticated", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := agentv1.NewHostAgentClient(bad).WatchVMs(ctx, &agentv1.WatchVMsRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("stream from CN intruder: %v, want Unauthenticated", err)
	}
	if _, err := agentv1.NewCertificateServiceClient(bad).RotateCertificate(ctx, &agentv1.RotateCertificateRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("RotateCertificate from CN intruder: %v, want Unauthenticated", err)
	}
	if e.agent.Certs().pending != nil {
		t.Error("refused RotateCertificate created a pending key")
	}

	// A certificate from another CA never completes the handshake.
	other := newTestCA(t)
	foreign := e.dialTLS(&tls.Config{
		Certificates: []tls.Certificate{other.tlsCert(t, clientSpec(CoordinatorClientCN))},
		RootCAs:      e.ca.pool, ServerName: "localhost", Time: e.clk.Now, MinVersion: tls.VersionTLS13,
	})
	if _, err := healthCheck(t, foreign, ""); status.Code(err) != codes.Unavailable {
		t.Errorf("client from a foreign CA: %v, want Unavailable", err)
	}
}

func TestAllowedClientsFromConfig(t *testing.T) {
	cfg := strings.Replace(guestConfigYAML, "role: guest\n", "role: guest\nallowedClients: [ops-tool]\n", 1)
	e := newEnv(t, cfg, nil)
	e.start()
	if _, err := healthCheck(t, e.dial("ops-tool"), ""); err != nil {
		t.Errorf("ops-tool: %v", err)
	}
	if _, err := healthCheck(t, e.dial(CoordinatorClientCN), ""); status.Code(err) != codes.Unauthenticated {
		t.Errorf("coordinator not in allowedClients: %v, want Unauthenticated", err)
	}
}

// wantHealth checks grpc.health.v1 for "" and service and /readyz.
func wantHealth(t *testing.T, e *env, conn *grpc.ClientConn, service string, want healthpb.HealthCheckResponse_ServingStatus, wantHTTP int) {
	t.Helper()
	for _, name := range []string{"", service} {
		if st, err := healthCheck(t, conn, name); err != nil || st != want {
			t.Errorf("health %q: %v, %v; want %v", name, st, err, want)
		}
	}
	if code, body := httpGet(t, e.healthURL("/readyz")); code != wantHTTP {
		t.Errorf("/readyz: %d %q, want %d", code, body, wantHTTP)
	}
}

// tick advances the clock by one tick and waits for it to finish.
func (e *env) tick() {
	e.t.Helper()
	e.clk.Advance(TickInterval)
	e.clk.waitTimer(e.t)
}

func TestReadinessTransitions(t *testing.T) {
	svc := newTestService()
	var mu sync.Mutex
	var changes []bool
	e := newEnvWith(t, hostConfigYAML, svc, func(o *Options) {
		o.OnReadyChange = func(r bool) { mu.Lock(); changes = append(changes, r); mu.Unlock() }
	})
	e.start()
	conn := e.dial(CoordinatorClientCN)
	service := svc.ServiceName()

	wantHealth(t, e, conn, service, healthpb.HealthCheckResponse_SERVING, http.StatusOK)

	svc.setCheck(errors.New("vmms is stopped"))
	e.tick()
	wantHealth(t, e, conn, service, healthpb.HealthCheckResponse_NOT_SERVING, http.StatusServiceUnavailable)
	if _, body := httpGet(t, e.healthURL("/readyz")); !strings.Contains(body, "[-] test: vmms is stopped") ||
		!strings.Contains(body, "[+] certificate") {
		t.Errorf("/readyz body %q lacks the check results", body)
	}
	rep := e.agent.Readiness().Report()
	if rep.Ready || rep.Checks[len(rep.Checks)-1].Since != t0.Add(TickInterval) {
		t.Errorf("report %+v: want not ready, failing since the second tick", rep)
	}

	e.tick() // still failing: no new transition
	svc.setCheck(nil)
	e.tick()
	wantHealth(t, e, conn, service, healthpb.HealthCheckResponse_SERVING, http.StatusOK)

	mu.Lock()
	defer mu.Unlock()
	if diff := cmp.Diff([]bool{true, false, true}, changes); diff != "" {
		t.Errorf("OnReadyChange calls (-want +got):\n%s", diff)
	}
}

func TestReadinessCertificateExpiry(t *testing.T) {
	e := newEnv(t, guestConfigYAML, nil)
	e.start()
	conn := e.dial(CoordinatorClientCN)
	// The serving certificate is valid until t0+30d; 72 h before that the
	// agent turns not ready.
	e.clk.Set(t0.Add(30*24*time.Hour - CertMinValidity))
	e.clk.waitTimer(t)
	if st, err := healthCheck(t, conn, ""); err == nil && st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("health with a certificate expiring in 72 h: %v, want NOT_SERVING", st)
	}
}

func TestLiveness(t *testing.T) {
	svc := newTestService()
	e := newEnv(t, hostConfigYAML, svc)
	e.start()
	if code, body := httpGet(t, e.healthURL("/healthz")); code != http.StatusOK {
		t.Fatalf("/healthz: %d %q", code, body)
	}
	// Hang the main loop inside a readiness check.
	block := make(chan struct{})
	svc.setBlock(block)
	e.clk.Advance(TickInterval) // the tick starts and hangs
	<-svc.checking
	e.clk.Advance(LivenessTimeout)
	if code, _ := httpGet(t, e.healthURL("/healthz")); code != http.StatusOK {
		t.Errorf("/healthz %d exactly at the limit, want 200", code)
	}
	e.clk.Advance(time.Second)
	if code, body := httpGet(t, e.healthURL("/healthz")); code != http.StatusServiceUnavailable {
		t.Errorf("/healthz with a hung main loop: %d %q, want 503", code, body)
	}
	svc.setBlock(nil)
	close(block)
	e.clk.waitTimer(t)
	e.clk.Advance(TickInterval) // the next tick records liveness again
	e.clk.waitTimer(t)
	if code, body := httpGet(t, e.healthURL("/healthz")); code != http.StatusOK {
		t.Errorf("/healthz after the loop recovered: %d %q", code, body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	e := newEnv(t, hostConfigYAML, newTestService())
	e.start()
	code, body := httpGet(t, e.healthURL("/metrics"))
	if code != http.StatusOK {
		t.Fatalf("/metrics: %d", code)
	}
	for _, want := range []string{
		"hvmc_agent_ready 1",
		`hvmc_agent_readiness_check{check="certificate"} 1`,
		`hvmc_agent_readiness_check{check="policy"} 1`,
		`hvmc_agent_readiness_check{check="test"} 1`,
		`hvmc_agent_info{name="host",role="host",version="v0.0.0-test"} 1`,
		"hvmc_agent_policy_pending 0",
		"hvmc_agent_serving_cert_not_after_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
}

func TestRunStopsOnServiceError(t *testing.T) {
	svc := newTestService()
	svc.runErr = errors.New("worker failed 5 times in 5 minutes")
	e := newEnv(t, hostConfigYAML, svc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.agent.Run(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, svc.runErr) {
			t.Errorf("Run: %v, want the service's error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop after the service failed")
	}
}

func TestNewNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{Config: dir + "/agent.yaml", State: dir}
	cfg, err := ParseConfig([]byte(guestConfigYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Config: cfg, Paths: paths}); !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("New without certificates: %v, want ErrNotEnrolled", err)
	}
}

func TestGuestHasNoPolicy(t *testing.T) {
	e := newEnv(t, guestConfigYAML, nil)
	if e.agent.Policy() != nil {
		t.Error("guest agent has a policy store")
	}
	for _, c := range e.agent.Readiness().Report().Checks {
		if c.Name == "policy" {
			t.Error("guest agent registers the policy check")
		}
	}
	e.start()
	// Without a role service, only the overall health status exists.
	if _, err := healthCheck(t, e.dial(CoordinatorClientCN), agentv1.GuestAgent_ServiceDesc.ServiceName); status.Code(err) != codes.NotFound {
		t.Errorf("health for an unregistered service: %v, want NotFound", err)
	}
}
