// Package agent is the role-independent framework of the hvmc host and
// guest agents (DESIGN §4): the mTLS gRPC server with its allowedClients
// check, grpc.health.v1 and the plain-HTTP health port, readiness checks,
// local configuration, the serving certificate with coordinator-driven
// rotation, the host's active/pending write policy, the audit log of every
// write, enrollment, the stop drain and logging.
//
// The role-specific services plug in through [Service]: the host agent
// (internal/agent/host) serves HostAgent, the guest agent
// (internal/agent/guest) GuestAgent. Service integration
// (internal/agent/svc) wraps [Agent.Run] with the platform's service
// manager through [Options.OnTick] and [Options.OnReadyChange].
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// TickInterval is the period of the main loop: liveness, policy reload,
// readiness evaluation and the OnTick hook (systemd watchdog).
const TickInterval = 5 * time.Second

// Service is a role's plug-in: the host agent's HostAgent server or the
// guest agent's GuestAgent server.
type Service interface {
	// ServiceName is the fully qualified gRPC service the role serves
	// ("hvmc.agent.v1.HostAgent" or "hvmc.agent.v1.GuestAgent"). It is
	// also its grpc.health.v1 service name.
	ServiceName() string
	// Register registers the role's gRPC services on reg and its readiness
	// checks on deps.Readiness. It is called once, by New.
	Register(reg grpc.ServiceRegistrar, deps Deps) error
	// Run does the role's background work (polling, worker supervision)
	// until ctx ends, which happens when the agent starts draining. An
	// error stops the agent.
	Run(ctx context.Context) error
}

// Deps is what the framework hands to a role.
type Deps struct {
	Config    Config
	Clock     Clock
	Log       *slog.Logger
	Readiness *Readiness
	// Audit is the audit log. Write RPCs are audited automatically
	// ([WriteMethods]); handlers add before/after with SetAuditBefore and
	// SetAuditAfter.
	Audit *Audit
	// Policy is the host's write policy; nil for the guest role.
	Policy *PolicyStore
	// Certs is the serving certificate store.
	Certs *CertStore
	// Metrics registers the role's metrics on the /metrics endpoint.
	Metrics prometheus.Registerer
	// Version is the agent's version, reported in GetHost / GetMemory.
	Version string
}

// Options configure an Agent.
type Options struct {
	Config Config
	Paths  Paths
	// Service is the role's plug-in; nil serves only the framework's
	// services (CertificateService, health).
	Service Service
	// Clock defaults to SystemClock.
	Clock Clock
	// Logger defaults to discarding.
	Logger *slog.Logger
	// Version of the binary.
	Version string
	// OnTick is called after every main-loop tick (systemd watchdog).
	OnTick func()
	// OnReadyChange is called whenever the overall readiness changes,
	// first after the initial evaluation (sd_notify READY=1).
	OnReadyChange func(ready bool)
}

// Agent is one running host or guest agent.
type Agent struct {
	opts   Options
	cfg    Config
	clk    Clock
	log    *slog.Logger
	certs  *CertStore
	policy *PolicyStore
	audit  *Audit
	ready  *Readiness
	live   *Liveness
	health *health.Server
	grpc   *grpc.Server
	http   *http.Server

	auditFile *RotatingFile
	draining  chan struct{}
	started   chan struct{}

	mu         sync.Mutex
	grpcAddr   net.Addr
	healthAddr net.Addr
}

// New loads the agent's certificates and policy, opens the audit log and
// builds both servers. It does not listen yet; see Run.
func New(o Options) (*Agent, error) {
	if o.Clock == nil {
		o.Clock = SystemClock()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	a := &Agent{
		opts: o, cfg: o.Config, clk: o.Clock, log: o.Logger,
		live:     NewLiveness(o.Clock),
		ready:    NewReadiness(o.Clock, o.Logger),
		health:   health.NewServer(),
		draining: make(chan struct{}),
		started:  make(chan struct{}),
	}
	if err := a.cfg.Validate(); err != nil {
		return nil, err
	}
	certs, err := OpenCertStore(o.Paths, o.Clock, o.Logger)
	if err != nil {
		return nil, err
	}
	a.certs = certs
	if err := a.ready.Register("certificate", certs.Check); err != nil {
		return nil, err
	}
	if a.cfg.Role == RoleHost {
		a.policy = OpenPolicyStore(o.Paths, o.Logger)
		if err := a.ready.Register("policy", a.policy.Check); err != nil {
			return nil, err
		}
	}
	if a.auditFile, err = OpenRotatingFile(o.Paths.AuditLog(), DefaultRotateBytes, DefaultRotateKeep); err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	a.audit = NewAudit(a.auditFile, a.cfg.Name, o.Clock, o.Logger)
	if err := a.build(); err != nil {
		_ = a.auditFile.Close()
		return nil, err
	}
	return a, nil
}

// build creates the gRPC and HTTP servers and registers every service.
func (a *Agent) build() error {
	a.grpc = grpc.NewServer(
		grpc.Creds(a.certs.TransportCredentials()),
		grpc.ChainUnaryInterceptor(a.authorizeUnary, a.audit.UnaryInterceptor),
		grpc.ChainStreamInterceptor(a.authorizeStream, a.drainStream),
	)
	agentv1.RegisterCertificateServiceServer(a.grpc, a.certs)
	healthpb.RegisterHealthServer(a.grpc, a.health)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		newReadinessCollector(a.ready),
		a.metrics(),
	)

	services := []string{""}
	if s := a.opts.Service; s != nil {
		services = append(services, s.ServiceName())
		if err := s.Register(a.grpc, a.Deps(reg)); err != nil {
			return fmt.Errorf("register %s: %w", s.ServiceName(), err)
		}
	}
	for _, name := range services {
		a.health.SetServingStatus(name, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	a.ready.Subscribe(func(rep ReadinessReport) {
		st := healthpb.HealthCheckResponse_NOT_SERVING
		if rep.Ready {
			st = healthpb.HealthCheckResponse_SERVING
		}
		for _, name := range services {
			a.health.SetServingStatus(name, st) // ignored once draining (Shutdown)
		}
		if a.opts.OnReadyChange != nil {
			a.opts.OnReadyChange(rep.Ready)
		}
	})
	a.http = &http.Server{
		Handler:           healthMux(a.live, a.ready, reg),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return nil
}

// metrics returns the framework's own gauges.
func (a *Agent) metrics() prometheus.Collector {
	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hvmc_agent_info", Help: "Agent version, role and name (always 1).",
	}, []string{"version", "role", "name"})
	info.WithLabelValues(a.opts.Version, string(a.cfg.Role), a.cfg.Name).Set(1)
	cs := []prometheus.Collector{
		info,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "hvmc_agent_serving_cert_not_after_seconds",
			Help: "NotAfter of the serving certificate, Unix seconds.",
		}, func() float64 { return float64(a.certs.Leaf().NotAfter.Unix()) }),
	}
	if a.policy != nil {
		cs = append(cs, prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "hvmc_agent_policy_pending",
			Help: "1 while a proposed policy waits for local confirmation.",
		}, func() float64 { _, ok := a.policy.Pending(); return boolValue(ok) }))
	}
	return collectorList(cs)
}

// collectorList registers several collectors as one.
type collectorList []prometheus.Collector

func (l collectorList) Describe(ch chan<- *prometheus.Desc) {
	for _, c := range l {
		c.Describe(ch)
	}
}

func (l collectorList) Collect(ch chan<- prometheus.Metric) {
	for _, c := range l {
		c.Collect(ch)
	}
}

// Deps returns what a role needs, with reg as its metrics registerer.
func (a *Agent) Deps(reg prometheus.Registerer) Deps {
	return Deps{
		Config: a.cfg, Clock: a.clk, Log: a.log, Readiness: a.ready, Audit: a.audit,
		Policy: a.policy, Certs: a.certs, Metrics: reg, Version: a.opts.Version,
	}
}

// Readiness returns the readiness registry.
func (a *Agent) Readiness() *Readiness { return a.ready }

// Certs returns the certificate store.
func (a *Agent) Certs() *CertStore { return a.certs }

// Policy returns the host's policy store; nil for the guest role.
func (a *Agent) Policy() *PolicyStore { return a.policy }

// Started is closed once Run listens on both ports.
func (a *Agent) Started() <-chan struct{} { return a.started }

// GRPCAddr is the gRPC listener's address (after Started).
func (a *Agent) GRPCAddr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.grpcAddr
}

// HealthAddr is the health listener's address (after Started).
func (a *Agent) HealthAddr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.healthAddr
}

// Run listens on the gRPC and health ports, runs the main loop and the
// role until ctx ends or a component fails, then drains (DrainTimeout)
// and closes the audit log. It returns nil after a stop through ctx.
func (a *Agent) Run(ctx context.Context) error {
	defer func() { _ = a.auditFile.Close() }()
	var lc net.ListenConfig
	gl, err := lc.Listen(ctx, "tcp", a.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", a.cfg.Listen, err)
	}
	hl, err := lc.Listen(ctx, "tcp", a.cfg.Health)
	if err != nil {
		_ = gl.Close()
		return fmt.Errorf("listen %s: %w", a.cfg.Health, err)
	}
	a.mu.Lock()
	a.grpcAddr, a.healthAddr = gl.Addr(), hl.Addr()
	a.mu.Unlock()

	runCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := a.grpc.Serve(gl); err != nil {
			stop(fmt.Errorf("grpc server: %w", err))
		}
	})
	wg.Go(func() {
		if err := a.http.Serve(hl); err != nil && !errors.Is(err, http.ErrServerClosed) {
			stop(fmt.Errorf("health server: %w", err))
		}
	})
	wg.Go(func() { a.loop(runCtx) })
	if s := a.opts.Service; s != nil {
		wg.Go(func() {
			if err := s.Run(runCtx); err != nil && runCtx.Err() == nil {
				stop(fmt.Errorf("%s: %w", s.ServiceName(), err))
			}
		})
	}
	a.log.Info("agent started", "role", a.cfg.Role, "name", a.cfg.Name, "version", a.opts.Version,
		"listen", gl.Addr().String(), "health", hl.Addr().String(), "pid", os.Getpid())
	close(a.started)

	<-runCtx.Done()
	cause := context.Cause(runCtx)
	a.drain()
	wg.Wait()
	if ctx.Err() != nil {
		a.log.Info("agent stopped")
		return nil
	}
	a.log.Error("agent stopped after a failure", "error", cause)
	return cause
}

// loop is the main loop: one tick now, then every TickInterval.
func (a *Agent) loop(ctx context.Context) {
	for {
		a.tick(ctx)
		t := a.clk.NewTimer(TickInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C():
		}
	}
}

func (a *Agent) tick(ctx context.Context) {
	a.live.Tick()
	if a.policy != nil {
		a.policy.Reload()
	}
	a.ready.Evaluate(ctx)
	if a.opts.OnTick != nil {
		a.opts.OnTick()
	}
}

// ClientCN returns the CN of the verified client certificate of a gRPC
// call, or "" without one.
func ClientCN(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return ""
	}
	return info.State.VerifiedChains[0][0].Subject.CommonName
}

// authorize refuses callers whose certificate CN is not in allowedClients
// with UNAUTHENTICATED (error model, common.proto).
func (a *Agent) authorize(ctx context.Context, method string) error {
	cn := ClientCN(ctx)
	if a.cfg.Allows(cn) {
		return nil
	}
	a.log.Warn("refused call from a client not in allowedClients", "client", cn, "method", method)
	return status.Errorf(codes.Unauthenticated, "client %q is not in allowedClients", cn)
}

func (a *Agent) authorizeUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := a.authorize(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (a *Agent) authorizeStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := a.authorize(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}
