// Package agentclient is the coordinator's only way to talk to hvmc agents
// (DESIGN §4): typed clients for the host agent (Host), guest agents
// (Guest), certificate renewal (Certs) and grpc.health.v1 (Health), a Pool
// of mTLS connections derived from HostConfig, and the health Tracker that
// feeds agent states and observations into the ledger, keeps the host
// policy in sync and renews agent certificates (Rotator).
//
// Every client error is an *RPCError unwrapping to one of the typed errors
// of the agent error model (errors.go).
package agentclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/matfax/hvmc/api/v1alpha1"
)

// Role is an agent's role.
type Role string

// Agent roles.
const (
	RoleHost  Role = "host"
	RoleGuest Role = "guest"
)

// DefaultPort is the agents' gRPC port when HostConfig leaves it unset.
const DefaultPort int32 = 9443

// ErrUnknownAgent is returned for an agent name the Pool does not know, or
// one of the wrong role.
var ErrUnknownAgent = errors.New("agentclient: unknown agent")

// Endpoint is one agent as HostConfig declares it.
type Endpoint struct {
	// Name is spec.agents[].name for the host agent, the VM name for a
	// guest agent.
	Name string
	Role Role
	// VM is the guest agent's VM (equal to Name); empty for the host agent.
	VM string
	// DNSName, Node, Address and Port are the location inputs (DESIGN §4.7).
	DNSName string
	Node    string
	Address string
	Port    int32
	// ServerName is the name the agent's serving certificate must carry as
	// a SAN (DESIGN §4.6): the host agent's dnsName; a guest's
	// guestAgent.dnsName, else its node name. The coordinator verifies it
	// whatever address it dials.
	ServerName string
}

// Endpoints returns every agent HostConfig declares: the host agents of
// spec.agents and one guest agent per spec.vms entry.
func Endpoints(hc *v1alpha1.HostConfig) []Endpoint {
	if hc == nil {
		return nil
	}
	var out []Endpoint
	for _, a := range hc.Spec.Agents {
		if a.Role != "" && a.Role != v1alpha1.AgentRoleHost {
			continue
		}
		out = append(out, Endpoint{
			Name: a.Name, Role: RoleHost, DNSName: a.DNSName, Address: a.Address,
			Port: portOrDefault(a.Port), ServerName: a.DNSName,
		})
	}
	for _, vm := range hc.Spec.VMs {
		ep := Endpoint{Name: vm.Name, Role: RoleGuest, VM: vm.Name, Node: vm.Node, Port: DefaultPort, ServerName: vm.Node}
		if g := vm.GuestAgent; g != nil {
			ep.DNSName, ep.Address, ep.Port = g.DNSName, g.Address, portOrDefault(g.Port)
			if g.DNSName != "" {
				ep.ServerName = g.DNSName
			}
		}
		out = append(out, ep)
	}
	return out
}

func portOrDefault(p int32) int32 {
	if p == 0 {
		return DefaultPort
	}
	return p
}

// Resolver returns the address ("host:port") to dial for an agent.
type Resolver func(ctx context.Context, ep Endpoint) (string, error)

// DefaultResolver derives the address as DESIGN §4.7 describes: the address
// override if set; for a VM mapped to a node, the Node's InternalIP (read
// through r; skipped when r is nil); otherwise the dnsName.
func DefaultResolver(r client.Reader) Resolver {
	return func(ctx context.Context, ep Endpoint) (string, error) {
		port := strconv.Itoa(int(portOrDefault(ep.Port)))
		switch {
		case ep.Address != "":
			return net.JoinHostPort(ep.Address, port), nil
		case ep.Node != "" && r != nil:
			ip, err := nodeInternalIP(ctx, r, ep.Node)
			if err != nil {
				return "", err
			}
			return net.JoinHostPort(ip, port), nil
		case ep.DNSName != "":
			return net.JoinHostPort(ep.DNSName, port), nil
		default:
			return "", fmt.Errorf("agent %s: no address, node or dnsName", ep.Name)
		}
	}
}

func nodeInternalIP(ctx context.Context, r client.Reader, name string) (string, error) {
	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: name}, &node); err != nil {
		return "", fmt.Errorf("node %q: %w", name, err)
	}
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP && net.ParseIP(a.Address) != nil {
			return a.Address, nil
		}
	}
	return "", fmt.Errorf("node %q reports no InternalIP", name)
}

// Clock is the source of time of the pool (certificate verification) and
// the tracker; SystemClock in production.
type Clock interface {
	Now() time.Time
	// NewTimer returns a timer that delivers on C once d has passed.
	NewTimer(d time.Duration) Timer
}

// Timer is a pending event on a Clock.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

// SystemClock returns a Clock backed by the time package.
func SystemClock() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) NewTimer(d time.Duration) Timer { return systemTimer{time.NewTimer(d)} }

type systemTimer struct{ t *time.Timer }

func (t systemTimer) C() <-chan time.Time { return t.t.C }
func (t systemTimer) Stop() bool          { return t.t.Stop() }

// PoolOptions configures a Pool.
type PoolOptions struct {
	// TLS is the client configuration: the coordinator's client certificate
	// and the hvmc CA as RootCAs, e.g. pki.Reloader.ClientTLSConfig. Each
	// agent's connection uses a clone with ServerName set to the agent's
	// Endpoint.ServerName, so an agent is accepted only with a certificate
	// chained to the CA that names the configured agent. Nil means
	// plaintext, for in-process fake agents only.
	TLS *tls.Config
	// Clock, if set, is the time certificates are verified at.
	Clock Clock
	// Resolver derives dial addresses; nil means DefaultResolver(nil).
	Resolver Resolver
	// DialOptions are added to every connection.
	DialOptions []grpc.DialOption
}

// Pool holds one gRPC connection per agent and hands out the agent clients.
// It is safe for concurrent use.
type Pool struct {
	opts PoolOptions

	mu    sync.Mutex
	conns map[string]*agentConn
}

// NewPool returns an empty Pool; Sync adds the agents.
func NewPool(opts PoolOptions) *Pool {
	if opts.Resolver == nil {
		opts.Resolver = DefaultResolver(nil)
	}
	return &Pool{opts: opts, conns: map[string]*agentConn{}}
}

// Sync makes the pool hold exactly the given agents. A connection is
// replaced when its address or expected name changed, and closed when its
// agent is gone; replacing or closing a connection ends calls in flight on
// it. An agent whose address cannot be resolved stays in the pool without a
// connection: its calls fail with ErrUnavailable until a later Sync
// resolves it. The returned error joins every such failure.
func (p *Pool) Sync(ctx context.Context, eps []Endpoint) error {
	type resolved struct {
		ep     Endpoint
		target string
		err    error
	}
	var errs []error
	want := make(map[string]resolved, len(eps))
	for _, ep := range eps {
		if _, dup := want[ep.Name]; dup {
			errs = append(errs, fmt.Errorf("agent %s: declared twice", ep.Name))
			continue
		}
		target, err := p.opts.Resolver(ctx, ep)
		if err != nil {
			errs = append(errs, err)
		}
		want[ep.Name] = resolved{ep: ep, target: target, err: err}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, c := range p.conns {
		if _, ok := want[name]; !ok {
			c.close()
			delete(p.conns, name)
		}
	}
	for name, r := range want {
		c, ok := p.conns[name]
		if !ok {
			c = newAgentConn(name)
			p.conns[name] = c
		}
		if err := c.set(p.opts, r.ep, r.target, r.err); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close closes every connection.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, c := range p.conns {
		c.close()
		delete(p.conns, name)
	}
}

func (p *Pool) get(name string, role Role) (*agentConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.conns[name]
	if !ok || c.endpoint().Role != role {
		return nil, fmt.Errorf("%w: %s agent %q", ErrUnknownAgent, role, name)
	}
	return c, nil
}

func (p *Pool) lookup(name string) (*agentConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.conns[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownAgent, name)
	}
	return c, nil
}

// Host returns the client of the named host agent. It stays valid across
// Syncs that keep the agent.
func (p *Pool) Host(name string) (Host, error) {
	c, err := p.get(name, RoleHost)
	if err != nil {
		return nil, err
	}
	return c.host, nil
}

// Guest returns the client of the guest agent of vm.
func (p *Pool) Guest(vm string) (Guest, error) {
	c, err := p.get(vm, RoleGuest)
	if err != nil {
		return nil, err
	}
	return c.guest, nil
}

// Certs returns the certificate client of any agent.
func (p *Pool) Certs(agent string) (Certs, error) {
	c, err := p.lookup(agent)
	if err != nil {
		return nil, err
	}
	return c.certs, nil
}

// Health returns the health client of any agent.
func (p *Pool) Health(agent string) (Health, error) {
	c, err := p.lookup(agent)
	if err != nil {
		return nil, err
	}
	return c.health, nil
}

// PeerCertificate returns the leaf certificate the agent presented on the
// connection of the latest completed unary call, nil if none yet (or
// plaintext).
func (p *Pool) PeerCertificate(agent string) *x509.Certificate {
	c, err := p.lookup(agent)
	if err != nil {
		return nil
	}
	return c.peer.Load()
}

// Probe opens a fresh connection to the agent, performs one overall health
// Check on it and returns the leaf certificate presented in that new
// handshake. The pool's own connection is not touched, so calls in flight
// continue; Probe confirms that a newly installed certificate works.
func (p *Pool) Probe(ctx context.Context, agent string) (*x509.Certificate, error) {
	c, err := p.lookup(agent)
	if err != nil {
		return nil, err
	}
	ep, target, err := c.location()
	if err != nil {
		return nil, call{agent: agent, method: "Check"}.wrap(status.Error(codes.Unavailable, err.Error()))
	}
	cc, err := dial(p.opts, ep, target)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cc.Close() }()
	probe := newAgentConn(agent)
	probe.cc = cc
	if _, err := probe.health.Check(ctx, ""); err != nil {
		return nil, err
	}
	return probe.peer.Load(), nil
}

// agentConn is one agent's connection. It implements
// grpc.ClientConnInterface over whichever *grpc.ClientConn is current, so
// the clients built on it survive reconnects to a new address.
type agentConn struct {
	name string

	host   *hostClient
	guest  *guestClient
	certs  *certsClient
	health *healthClient
	peer   atomic.Pointer[x509.Certificate]

	mu     sync.RWMutex
	ep     Endpoint
	target string
	cc     *grpc.ClientConn
	err    error // why there is no connection
}

func newAgentConn(name string) *agentConn {
	c := &agentConn{name: name}
	c.host = newHostClient(name, c)
	c.guest = newGuestClient(name, c)
	c.certs = newCertsClient(name, c)
	c.health = newHealthClient(name, c)
	return c
}

func (c *agentConn) endpoint() Endpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ep
}

func (c *agentConn) location() (Endpoint, string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.target == "" {
		return c.ep, "", c.noConnErrLocked()
	}
	return c.ep, c.target, nil
}

func (c *agentConn) noConnErrLocked() error {
	if c.err != nil {
		return fmt.Errorf("not connected: %w", c.err)
	}
	return errors.New("not connected")
}

// set points the connection at target, re-dialling when the address or the
// expected name changed.
func (c *agentConn) set(opts PoolOptions, ep Endpoint, target string, resolveErr error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Keep the connection when the address does not resolve right now (the
	// last good one stays until it does) or nothing that needs a new dial
	// changed.
	if c.cc != nil && (resolveErr != nil || c.target == target && c.ep.ServerName == ep.ServerName) {
		c.ep = ep
		return nil
	}
	if c.cc != nil {
		_ = c.cc.Close()
		c.cc = nil
		c.peer.Store(nil)
	}
	c.ep, c.target, c.err = ep, target, resolveErr
	if resolveErr != nil {
		c.target = ""
		return nil // already reported by Sync
	}
	cc, err := dial(opts, ep, target)
	if err != nil {
		c.target, c.err = "", err
		return err
	}
	c.cc = cc
	return nil
}

func (c *agentConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil {
		_ = c.cc.Close()
		c.cc = nil
	}
	c.err = errors.New("removed from HostConfig")
}

func (c *agentConn) current() (*grpc.ClientConn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cc == nil {
		return nil, status.Error(codes.Unavailable, c.noConnErrLocked().Error())
	}
	return c.cc, nil
}

// Invoke implements grpc.ClientConnInterface and records the peer
// certificate.
func (c *agentConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	cc, err := c.current()
	if err != nil {
		return err
	}
	var pr peer.Peer
	err = cc.Invoke(ctx, method, args, reply, append(opts, grpc.Peer(&pr))...)
	if info, ok := pr.AuthInfo.(credentials.TLSInfo); ok && len(info.State.PeerCertificates) > 0 {
		c.peer.Store(info.State.PeerCertificates[0])
	}
	return err
}

// NewStream implements grpc.ClientConnInterface.
func (c *agentConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	cc, err := c.current()
	if err != nil {
		return nil, err
	}
	return cc.NewStream(ctx, desc, method, opts...)
}

// dial creates (without connecting) a client connection to target.
func dial(opts PoolOptions, ep Endpoint, target string) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if opts.TLS != nil {
		if ep.ServerName == "" {
			return nil, fmt.Errorf("agent %s: no dnsName or node to verify its certificate against", ep.Name)
		}
		cfg := opts.TLS.Clone()
		cfg.ServerName = ep.ServerName
		if opts.Clock != nil {
			cfg.Time = opts.Clock.Now
		}
		creds = credentials.NewTLS(cfg)
	}
	all := append([]grpc.DialOption{grpc.WithTransportCredentials(creds)}, opts.DialOptions...)
	cc, err := grpc.NewClient(target, all...)
	if err != nil {
		return nil, fmt.Errorf("agent %s: dial %s: %w", ep.Name, target, err)
	}
	return cc, nil
}
