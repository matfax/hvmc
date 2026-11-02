package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
	"github.com/matfax/hvmc/internal/policy"
)

// PolicyStore holds the host agent's active and pending write policy
// (DESIGN §4.3).
//
// The active policy is the `vms` key of agent.yaml, which only the operator
// changes. The coordinator can only propose a policy (ProposePolicy); it is
// stored as policy.pending.yaml in the state directory and becomes active
// only through [PolicyStore.Activate], which is called by `hvmc agent
// policy sync` on the host after the operator confirmed the diff. No RPC
// reaches Activate.
//
// The running agent re-reads both files on every main-loop tick
// ([PolicyStore.Reload]), so an activation by `policy sync` (a separate
// process) takes effect without a restart. If agent.yaml cannot be parsed
// the store fails closed: the active policy is the empty one (every write
// refused) and the readiness check "policy" fails until the file is fixed.
type PolicyStore struct {
	configPath  string
	pendingPath string
	log         *slog.Logger

	mu        sync.Mutex
	active    policy.Policy
	activeErr error
	pending   *policy.Policy
}

// Errors of [PolicyStore.Activate].
var (
	// ErrNoPendingPolicy means there is no proposal to activate.
	ErrNoPendingPolicy = errors.New("no pending policy")
	// ErrPendingChanged means the pending policy is not the one the
	// operator confirmed (a new proposal arrived in between).
	ErrPendingChanged = errors.New("pending policy changed since it was shown")
)

// OpenPolicyStore loads the active policy from paths.Config and the
// pending one from the state directory. Load errors are kept, not
// returned: see [PolicyStore.Check].
func OpenPolicyStore(paths Paths, log *slog.Logger) *PolicyStore {
	s := &PolicyStore{configPath: paths.Config, pendingPath: paths.PendingPolicy(), log: log}
	s.Reload()
	return s
}

// Reload re-reads the active and the pending policy and logs a change of
// either digest.
func (s *PolicyStore) Reload() {
	active, activeErr := policy.Load(s.configPath)
	if activeErr != nil {
		active = policy.Policy{}
	}
	pending, pendingErr := policy.Load(s.pendingPath)
	var pp *policy.Policy
	switch {
	case pendingErr == nil:
		pp = &pending
	case !errors.Is(pendingErr, fs.ErrNotExist):
		s.log.Warn("ignoring unreadable pending policy", "path", s.pendingPath, "error", pendingErr)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if (activeErr == nil) != (s.activeErr == nil) || active.Digest() != s.active.Digest() {
		if activeErr != nil {
			s.log.Error("active policy unreadable; refusing every write", "path", s.configPath, "error", activeErr)
		} else {
			s.log.Info("active policy loaded", "digest", active.Digest(), "vms", len(active.VMs))
		}
	}
	if digestOf(pp) != digestOf(s.pending) && pp != nil {
		s.log.Info("pending policy present; run `hvmc agent policy sync` to review it", "digest", pp.Digest())
	}
	s.active, s.activeErr, s.pending = active, activeErr, pp
}

func digestOf(p *policy.Policy) string {
	if p == nil {
		return ""
	}
	return p.Digest()
}

// Active returns the policy every write is checked against. It is the
// empty policy (no write allowed) while agent.yaml cannot be parsed.
func (s *PolicyStore) Active() policy.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// ActiveDigest returns the digest of [PolicyStore.Active], reported in
// GetHost.
func (s *PolicyStore) ActiveDigest() string { return s.Active().Digest() }

// Pending returns the pending proposal, if any.
func (s *PolicyStore) Pending() (policy.Policy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return policy.Policy{}, false
	}
	return *s.pending, true
}

// Check is the readiness check "local policy file parsed".
func (s *PolicyStore) Check(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeErr
}

// policyState is the audit view of the store.
type policyState struct {
	Active  string `json:"activeDigest"`
	Pending string `json:"pendingDigest,omitempty"`
}

func (s *PolicyStore) stateLocked() policyState {
	return policyState{Active: s.active.Digest(), Pending: digestOf(s.pending)}
}

// Propose stores p as the pending policy. A proposal equal to the active
// policy stores nothing and discards an earlier proposal. The active policy
// never changes here.
func (s *PolicyStore) Propose(p policy.Policy) (activeDigest, pendingDigest string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	activeDigest = s.active.Digest()
	if p.Digest() == activeDigest {
		if err := os.Remove(s.pendingPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return activeDigest, digestOf(s.pending), err
		}
		s.pending = nil
		return activeDigest, "", nil
	}
	if err := policy.Save(s.pendingPath, p); err != nil {
		return activeDigest, digestOf(s.pending), err
	}
	s.pending = &p
	s.log.Info("policy proposed; run `hvmc agent policy sync` to review it", "digest", p.Digest())
	return activeDigest, p.Digest(), nil
}

// ProposePolicy implements HostAgent.ProposePolicy for the host role's
// server, which delegates to it. It validates the request and stores the
// policy as pending; see [PolicyStore.Propose].
func (s *PolicyStore) ProposePolicy(ctx context.Context, req *agentv1.ProposePolicyRequest) (*agentv1.ProposePolicyResponse, error) {
	s.mu.Lock()
	SetAuditBefore(ctx, s.stateLocked())
	s.mu.Unlock()
	if req.GetPolicy() == nil {
		return nil, status.Error(codes.InvalidArgument, "policy is required")
	}
	p, err := policy.FromProto(req.GetPolicy())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if d := p.Digest(); d != req.GetDigest() {
		return nil, status.Errorf(codes.InvalidArgument, "digest mismatch: request says %q, agent computes %q", req.GetDigest(), d)
	}
	active, pending, err := s.Propose(p)
	s.mu.Lock()
	SetAuditAfter(ctx, s.stateLocked())
	s.mu.Unlock()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "storing the pending policy failed: %v", err)
	}
	return &agentv1.ProposePolicyResponse{ActiveDigest: active, PendingDigest: pending}, nil
}

// Activate makes the pending policy active after local confirmation: it is
// written into agent.yaml (other keys kept) and the pending file is
// removed. digest must be the digest of the pending policy the operator
// confirmed.
func (s *PolicyStore) Activate(digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return ErrNoPendingPolicy
	}
	p := *s.pending
	if p.Digest() != digest {
		return fmt.Errorf("%w: confirmed %s, pending is %s", ErrPendingChanged, digest, p.Digest())
	}
	if err := policy.Save(s.configPath, p); err != nil {
		return err
	}
	if err := os.Remove(s.pendingPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Warn("removing the activated pending policy failed", "error", err)
	}
	s.active, s.activeErr, s.pending = p, nil, nil
	s.log.Info("policy activated", "digest", digest)
	return nil
}
