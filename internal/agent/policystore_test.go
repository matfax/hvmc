package agent

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
	"github.com/matfax/hvmc/internal/policy"
)

func proposed() policy.Policy {
	return policy.Policy{VMs: []policy.VM{
		{Name: "windows-node-1", Min: 6 << 30, Max: 32 << 30},
		{Name: "linux-node-1", Fixed: true},
	}}
}

func propose(t *testing.T, client agentv1.HostAgentClient, req *agentv1.ProposePolicyRequest) (*agentv1.ProposePolicyResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return client.ProposePolicy(ctx, req)
}

func TestProposedPolicyNeverBecomesActive(t *testing.T) {
	e := newEnv(t, hostConfigYAML, newTestService())
	e.start()
	store := e.agent.Policy()
	activeBefore := store.ActiveDigest()
	fileBefore, err := os.ReadFile(e.paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	client := agentv1.NewHostAgentClient(e.dial(CoordinatorClientCN))

	p := proposed()
	resp, err := propose(t, client, &agentv1.ProposePolicyRequest{Policy: p.Proto(), Digest: p.Digest()})
	if err != nil {
		t.Fatalf("ProposePolicy: %v", err)
	}
	if resp.GetActiveDigest() != activeBefore || resp.GetPendingDigest() != p.Digest() {
		t.Errorf("response %v, want active %s pending %s", resp, activeBefore, p.Digest())
	}

	// Neither a tick (reload), a restart nor time activates it.
	e.tick()
	reopened := OpenPolicyStore(e.paths, testLogger(t))
	for name, s := range map[string]*PolicyStore{"running": store, "reopened": reopened} {
		checkPending(t, name, s, activeBefore, p.Digest())
	}
	if fileAfter, err := os.ReadFile(e.paths.Config); err != nil || string(fileAfter) != string(fileBefore) {
		t.Errorf("ProposePolicy changed agent.yaml (%v)", err)
	}
	host, err := client.GetHost(context.Background(), &agentv1.GetHostRequest{})
	if err != nil || host.GetHost().GetPolicyDigest() != activeBefore {
		t.Errorf("GetHost digest %q, %v; want the active %s", host.GetHost().GetPolicyDigest(), err, activeBefore)
	}
	checkLocalActivation(t, e, reopened, p.Digest())
}

func checkPending(t *testing.T, name string, s *PolicyStore, active, pending string) {
	t.Helper()
	if s.ActiveDigest() != active {
		t.Errorf("%s store: active digest changed to %s", name, s.ActiveDigest())
	}
	if got, ok := s.Pending(); !ok || got.Digest() != pending {
		t.Errorf("%s store: pending %v, %v", name, got, ok)
	}
}

// checkLocalActivation activates the pending policy from a second store,
// as `hvmc agent policy sync` does in its own process, and checks that the
// running agent picks it up on its next tick.
func checkLocalActivation(t *testing.T, e *env, local *PolicyStore, digest string) {
	t.Helper()
	store := e.agent.Policy()
	// Local confirmation, as `hvmc agent policy sync` does it in its own
	// process; the running agent picks it up on its next tick.
	if err := local.Activate("sha256:other"); !errors.Is(err, ErrPendingChanged) {
		t.Errorf("Activate with a stale digest: %v, want ErrPendingChanged", err)
	}
	if err := local.Activate(digest); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	e.tick()
	if store.ActiveDigest() != digest {
		t.Errorf("running agent's active digest %s after activation, want %s", store.ActiveDigest(), digest)
	}
	if _, ok := store.Pending(); ok || fileExists(t, e.paths.PendingPolicy()) {
		t.Error("pending policy left after activation")
	}
	cfg, err := LoadConfig(e.paths.Config)
	if err != nil || cfg.Name != "host" {
		t.Errorf("agent settings after activation: %+v, %v", cfg, err)
	}
	if err := local.Activate(digest); !errors.Is(err, ErrNoPendingPolicy) {
		t.Errorf("Activate without a proposal: %v, want ErrNoPendingPolicy", err)
	}
}

func TestProposePolicyValidation(t *testing.T) {
	e := newEnv(t, hostConfigYAML, newTestService())
	e.start()
	client := agentv1.NewHostAgentClient(e.dial(CoordinatorClientCN))
	store := e.agent.Policy()

	empty := policy.Policy{}
	invalid := &agentv1.Policy{Vms: []*agentv1.VMPolicy{{Name: "vm", MinBytes: 2, MaxBytes: 1}}}
	for name, tc := range map[string]struct {
		req  *agentv1.ProposePolicyRequest
		want codes.Code
	}{
		"missing policy":  {&agentv1.ProposePolicyRequest{Digest: empty.Digest()}, codes.InvalidArgument},
		"invalid policy":  {&agentv1.ProposePolicyRequest{Policy: invalid, Digest: "sha256:x"}, codes.InvalidArgument},
		"digest mismatch": {&agentv1.ProposePolicyRequest{Policy: proposed().Proto(), Digest: empty.Digest()}, codes.InvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := propose(t, client, tc.req); status.Code(err) != tc.want {
				t.Errorf("ProposePolicy: %v, want %v", err, tc.want)
			}
			if _, ok := store.Pending(); ok {
				t.Error("a refused proposal was stored")
			}
		})
	}

	// An explicit empty policy is valid: it manages no VM.
	resp, err := propose(t, client, &agentv1.ProposePolicyRequest{Policy: &agentv1.Policy{}, Digest: empty.Digest()})
	if err != nil {
		t.Fatalf("explicit empty policy: %v", err)
	}
	if resp.GetPendingDigest() != empty.Digest() {
		t.Errorf("pending digest %q, want the empty policy's", resp.GetPendingDigest())
	}

	// A proposal equal to the active policy discards the pending one.
	active := store.Active()
	resp, err = propose(t, client, &agentv1.ProposePolicyRequest{Policy: active.Proto(), Digest: active.Digest()})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetPendingDigest() != "" || fileExists(t, e.paths.PendingPolicy()) {
		t.Errorf("pending %q after proposing the active policy, want none", resp.GetPendingDigest())
	}
}

func TestPolicyStoreFailsClosed(t *testing.T) {
	e := newEnv(t, hostConfigYAML, nil)
	store := e.agent.Policy()
	if err := store.Check(context.Background()); err != nil {
		t.Fatalf("valid policy fails the check: %v", err)
	}
	writeTestFile(t, e.paths.Config, []byte("role: host\nvms:\n  - name: vm\n    min: 2Gi\n    max: 1Gi\n"))
	store.Reload()
	if err := store.Check(context.Background()); !errors.Is(err, policy.ErrInvalidPolicy) {
		t.Errorf("Check with an invalid policy file: %v", err)
	}
	if got := store.Active(); len(got.VMs) != 0 {
		t.Errorf("active policy %v while the file is invalid, want empty", got)
	}
	writeTestFile(t, e.paths.PendingPolicy(), []byte("garbage: ["))
	store.Reload()
	if _, ok := store.Pending(); ok {
		t.Error("unreadable pending policy reported as pending")
	}
}
