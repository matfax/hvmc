package agentclient

import (
	"context"
	"sync"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/matfax/hvmc/api/v1alpha1"
	"github.com/matfax/hvmc/internal/policy"
)

// DesiredPolicy is the policy the coordinator wants the host agent to run:
// policy.FromHostConfig, with the host's reported total as the observed
// capacity when spec.capacity is 0 (DESIGN §4.3). hostTotal ≤ 0 means the
// host has not been observed yet.
func DesiredPolicy(hc *v1alpha1.HostConfig, hostTotal int64) policy.Policy {
	if hc == nil {
		return policy.FromHostConfig(nil)
	}
	if hostTotal > 0 {
		hc = hc.DeepCopy()
		if hc.Status.ObservedHost == nil {
			hc.Status.ObservedHost = &v1alpha1.ObservedHost{}
		}
		hc.Status.ObservedHost.Capacity = resource.NewQuantity(hostTotal, resource.BinarySI)
	}
	return policy.FromHostConfig(hc)
}

// PolicyStatus is the result of one policy comparison.
type PolicyStatus struct {
	// InSync is PolicyInSync: the active digest equals the desired one.
	InSync bool
	// Desired, Active and Pending are the digests of the policy derived from
	// HostConfig and of the agent's active and pending policies.
	Desired string
	Active  string
	Pending string
	// Proposed reports that this call sent ProposePolicy.
	Proposed bool
	// Err is the error of the latest proposal of Desired, if it failed;
	// it is kept until that digest is proposed again or becomes pending.
	Err error
}

// PolicySync compares a host agent's active policy with the desired one
// and proposes the desired policy on mismatch, once per digest: not again
// while the agent reports it as pending, and not again after it was sent,
// unless the proposal failed with a retryable error. One PolicySync serves
// one host agent; it is safe for concurrent use.
type PolicySync struct {
	mu   sync.Mutex
	sent string
	err  error // of the proposal of sent
}

// Sync compares info (a fresh GetHost result) with the policy derived from
// hc and proposes it through h if needed.
func (s *PolicySync) Sync(ctx context.Context, h Host, hc *v1alpha1.HostConfig, info HostInfo) PolicyStatus {
	desired := DesiredPolicy(hc, info.Total)
	st := PolicyStatus{Desired: desired.Digest(), Active: info.PolicyDigest, Pending: info.PendingPolicyDigest}
	st.InSync = st.Active == st.Desired
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case st.InSync:
		return st
	case st.Pending == st.Desired:
		s.sent, s.err = st.Desired, nil
		return st
	case s.sent == st.Desired:
		st.Err = s.err
		return st
	}
	st.Proposed = true
	st.Err = h.ProposePolicy(ctx, desired)
	if st.Err == nil || !Retryable(st.Err) {
		s.sent, s.err = st.Desired, st.Err
	}
	return st
}
