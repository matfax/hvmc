package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Health mechanism, agent side (DESIGN §4.8)
//
// Readiness is the conjunction of named checks registered by the framework
// (serving certificate valid for more than 72 h; host role: local policy
// file parsed) and by the role (vmms running, worker alive, last read
// fresh, …). The main loop evaluates them on every tick; the result drives
// grpc.health.v1 (SERVING / NOT_SERVING for "" and the role's service),
// /readyz, the readiness metrics and, through [Options.OnReadyChange], the
// service manager (sd_notify READY=1 on Linux).
//
// Liveness is the main loop itself: /healthz fails when the loop has not
// ticked within [LivenessTimeout], which also stops the systemd watchdog
// pings ([Options.OnTick]).

// LivenessTimeout is how long the main loop may go without a tick before
// /healthz fails.
const LivenessTimeout = 10 * time.Second

// CheckFunc is a readiness check. It returns nil when the check passes.
// Checks run on the main loop and must not block: they read state that the
// role keeps current elsewhere.
type CheckFunc func(ctx context.Context) error

// CheckResult is the outcome of one readiness check.
type CheckResult struct {
	Name string
	// Err is nil when the check passed.
	Err error
	// Since is when the check last changed between passing and failing.
	Since time.Time
}

// ReadinessReport is the outcome of one evaluation of all checks.
type ReadinessReport struct {
	// Ready is true when every check passed. It is false before the first
	// evaluation.
	Ready bool
	// Checks in registration order.
	Checks []CheckResult
	// EvaluatedAt is the time of the evaluation (zero before the first).
	EvaluatedAt time.Time
}

// Readiness is the registry of readiness checks.
type Readiness struct {
	clk Clock
	log *slog.Logger

	mu     sync.Mutex
	names  []string
	checks map[string]CheckFunc
	report ReadinessReport
	subs   []func(ReadinessReport)
}

// ErrDuplicateCheck is returned when a check name is registered twice.
var ErrDuplicateCheck = errors.New("readiness check already registered")

// NewReadiness returns an empty registry.
func NewReadiness(clk Clock, log *slog.Logger) *Readiness {
	return &Readiness{clk: clk, log: log, checks: map[string]CheckFunc{}}
}

// Register adds a named check. It takes part from the next evaluation on.
func (r *Readiness) Register(name string, f CheckFunc) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.checks[name]; ok {
		return fmt.Errorf("%w: %q", ErrDuplicateCheck, name)
	}
	r.names = append(r.names, name)
	r.checks[name] = f
	return nil
}

// Subscribe calls fn after every evaluation that changes the overall
// readiness, including the first one. fn runs on the evaluating goroutine.
func (r *Readiness) Subscribe(fn func(ReadinessReport)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subs = append(r.subs, fn)
}

// Report returns the result of the last evaluation.
func (r *Readiness) Report() ReadinessReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.report
	out.Checks = slices.Clone(r.report.Checks)
	return out
}

// Evaluate runs every check, records the result, logs each check that
// turned from passing to failing or back, and notifies subscribers when
// the overall readiness changed.
func (r *Readiness) Evaluate(ctx context.Context) ReadinessReport {
	r.mu.Lock()
	names := slices.Clone(r.names)
	checks := make([]CheckFunc, len(names))
	for i, n := range names {
		checks[i] = r.checks[n]
	}
	r.mu.Unlock()

	now := r.clk.Now()
	rep := ReadinessReport{Ready: true, EvaluatedAt: now, Checks: make([]CheckResult, len(names))}
	for i, n := range names {
		err := checks[i](ctx)
		rep.Checks[i] = CheckResult{Name: n, Err: err, Since: now}
		if err != nil {
			rep.Ready = false
		}
	}

	r.mu.Lock()
	prev := r.report
	r.carrySinceLocked(&rep)
	r.report = rep
	subs := slices.Clone(r.subs)
	r.mu.Unlock()

	changed := prev.EvaluatedAt.IsZero() || prev.Ready != rep.Ready
	if changed {
		r.log.Info("readiness changed", "ready", rep.Ready)
		for _, fn := range subs {
			fn(rep)
		}
	}
	return rep
}

// carrySinceLocked keeps Since of checks whose state did not change and
// logs the ones that did.
func (r *Readiness) carrySinceLocked(rep *ReadinessReport) {
	prev := make(map[string]CheckResult, len(r.report.Checks))
	for _, c := range r.report.Checks {
		prev[c.Name] = c
	}
	for i, c := range rep.Checks {
		p, seen := prev[c.Name]
		if seen && (p.Err == nil) == (c.Err == nil) {
			rep.Checks[i].Since = p.Since
			continue
		}
		if c.Err != nil {
			r.log.Warn("readiness check failing", "check", c.Name, "error", c.Err)
		} else if seen {
			r.log.Info("readiness check passing", "check", c.Name)
		}
	}
}

// Liveness tracks the main loop's ticks.
type Liveness struct {
	clk Clock

	mu   sync.Mutex
	last time.Time
}

// NewLiveness returns a tracker that fails until the first Tick.
func NewLiveness(clk Clock) *Liveness { return &Liveness{clk: clk} }

// Tick records that the main loop is alive.
func (l *Liveness) Tick() {
	now := l.clk.Now()
	l.mu.Lock()
	l.last = now
	l.mu.Unlock()
}

// Check fails when the main loop has not ticked within LivenessTimeout.
func (l *Liveness) Check() error {
	l.mu.Lock()
	last := l.last
	l.mu.Unlock()
	if last.IsZero() {
		return errors.New("main loop has not started")
	}
	if age := l.clk.Now().Sub(last); age > LivenessTimeout {
		return fmt.Errorf("main loop last ticked %s ago (limit %s)", age, LivenessTimeout)
	}
	return nil
}

// healthMux serves /healthz, /readyz and /metrics. Nothing it returns is
// secret: check names and their error texts only.
func healthMux(live *Liveness, ready *Readiness, reg *prometheus.Registry) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if err := live.Check(); err != nil {
			http.Error(w, "not live: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		rep := ready.Report()
		code := http.StatusOK
		if !rep.Ready {
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		_, _ = fmt.Fprint(w, formatReport(rep))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	return mux
}

// formatReport renders a report as /readyz prints it.
func formatReport(rep ReadinessReport) string {
	var b strings.Builder
	if rep.EvaluatedAt.IsZero() {
		b.WriteString("not evaluated yet\n")
	}
	for _, c := range rep.Checks {
		if c.Err != nil {
			fmt.Fprintf(&b, "[-] %s: %v\n", c.Name, c.Err)
		} else {
			fmt.Fprintf(&b, "[+] %s\n", c.Name)
		}
	}
	if rep.Ready {
		b.WriteString("ready\n")
	} else {
		b.WriteString("not ready\n")
	}
	return b.String()
}

// readinessCollector exports the last report as metrics.
type readinessCollector struct {
	ready *Readiness
	up    *prometheus.Desc
	check *prometheus.Desc
}

func newReadinessCollector(r *Readiness) *readinessCollector {
	return &readinessCollector{
		ready: r,
		up:    prometheus.NewDesc("hvmc_agent_ready", "1 when every readiness check passes.", nil, nil),
		check: prometheus.NewDesc("hvmc_agent_readiness_check", "1 when the readiness check passes.", []string{"check"}, nil),
	}
}

func (c *readinessCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.check
}

func (c *readinessCollector) Collect(ch chan<- prometheus.Metric) {
	rep := c.ready.Report()
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, boolValue(rep.Ready))
	for _, chk := range rep.Checks {
		ch <- prometheus.MustNewConstMetric(c.check, prometheus.GaugeValue, boolValue(chk.Err == nil), chk.Name)
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
