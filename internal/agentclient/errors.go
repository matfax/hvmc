package agentclient

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// Typed errors of the agent API, mapped from the gRPC status codes of the
// error model (proto/hvmc/agent/v1/common.proto, DESIGN §4.2). Every error
// returned by a client method is an *RPCError that unwraps to exactly one of
// these (or to context.Canceled); match them with errors.Is. The status
// message is for humans and is never parsed.
var (
	// ErrFixedVM (FAILED_PRECONDITION on SetStartup or SetDynamicLimits):
	// the VM's state does not allow the write — a fixed VM, the wrong memory
	// mode for the call, or a Dynamic Memory direction violation. Not
	// retryable.
	ErrFixedVM = errors.New("agentclient: VM does not allow this write")
	// ErrPolicyDenied (PERMISSION_DENIED): the host agent's active local
	// policy denies the write. Not retryable until the operator activates a
	// new policy on the host.
	ErrPolicyDenied = errors.New("agentclient: denied by the host policy")
	// ErrHostOutOfMemory (RESOURCE_EXHAUSTED): the host lacks free memory for
	// the grow. Retryable once memory frees up.
	ErrHostOutOfMemory = errors.New("agentclient: host out of memory")
	// ErrShrinkRefused (ABORTED): the guest refused (part of) a shrink. The
	// VM may be partially shrunk; re-read it, retry at the midpoint.
	ErrShrinkRefused = errors.New("agentclient: guest refused the shrink")
	// ErrUnavailable (UNAVAILABLE): the agent cannot be reached, or it cannot
	// reach its data source. Retryable with backoff.
	ErrUnavailable = errors.New("agentclient: agent unavailable")
	// ErrVMMSDown (UNAVAILABLE from the host agent): the Hyper-V management
	// service is down, the PowerShell worker is restarting, or the host agent
	// is unreachable; the codes do not tell these apart. It wraps
	// ErrUnavailable.
	ErrVMMSDown = fmt.Errorf("%w: Hyper-V management service down or host agent unreachable", ErrUnavailable)
	// ErrDeadlineExceeded (DEADLINE_EXCEEDED): the call did not finish in
	// time. The outcome of a write is unknown; re-read before retrying.
	ErrDeadlineExceeded = errors.New("agentclient: deadline exceeded")
	// ErrNotFound (NOT_FOUND): the named VM does not exist on the host.
	ErrNotFound = errors.New("agentclient: VM not found")
	// ErrInvalidArgument (INVALID_ARGUMENT): the request is malformed, e.g. a
	// misaligned size, a digest mismatch or an unusable certificate chain.
	ErrInvalidArgument = errors.New("agentclient: invalid argument")
	// ErrFailedPrecondition (FAILED_PRECONDITION outside VM writes), e.g.
	// InstallCertificate without a matching pending key.
	ErrFailedPrecondition = errors.New("agentclient: failed precondition")
	// ErrUnauthenticated (UNAUTHENTICATED): the agent does not accept the
	// coordinator's client certificate CN.
	ErrUnauthenticated = errors.New("agentclient: client not allowed by the agent")
	// ErrUnimplemented (UNIMPLEMENTED): the agent role does not serve the RPC.
	ErrUnimplemented = errors.New("agentclient: not served by this agent")
	// ErrInternal (INTERNAL and any other code): an unexpected agent-side
	// failure. Retryable with backoff.
	ErrInternal = errors.New("agentclient: agent internal error")
)

// RPCError is an agent call that failed.
type RPCError struct {
	// Agent is the agent's name (HostConfig).
	Agent string
	// Method is the RPC, e.g. "SetStartup".
	Method string
	// Code is the gRPC status code.
	Code codes.Code
	// Kind is the typed error the code maps to.
	Kind error
	// Result is the ResizeResult the host agent attached after a failed write
	// (ABORTED, DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED), if any. For logging;
	// callers still re-read the VM.
	Result *ResizeResult
	// Message is the status message, for humans.
	Message string
}

// Error implements error.
func (e *RPCError) Error() string {
	return fmt.Sprintf("agent %s: %s: %s (%s)", e.Agent, e.Method, e.Message, e.Code)
}

// Unwrap returns the typed error.
func (e *RPCError) Unwrap() error { return e.Kind }

// Retryable reports whether a failed call may succeed when repeated
// unchanged: UNAVAILABLE, DEADLINE_EXCEEDED (after re-reading), INTERNAL and
// RESOURCE_EXHAUSTED. A refused shrink (ErrShrinkRefused) has its own retry
// rule and is not reported retryable here.
func Retryable(err error) bool {
	for _, k := range []error{ErrUnavailable, ErrDeadlineExceeded, ErrInternal, ErrHostOutOfMemory} {
		if errors.Is(err, k) {
			return true
		}
	}
	return false
}

// ResultOf returns the ResizeResult attached to a failed write, if any.
func ResultOf(err error) (ResizeResult, bool) {
	var e *RPCError
	if errors.As(err, &e) && e.Result != nil {
		return *e.Result, true
	}
	return ResizeResult{}, false
}

// call identifies an RPC for error mapping.
type call struct {
	agent  string
	method string
	// host marks host agent calls (UNAVAILABLE → ErrVMMSDown).
	host bool
	// write marks VM writes (FAILED_PRECONDITION → ErrFixedVM).
	write bool
}

// wrap turns a gRPC error into an *RPCError; nil stays nil.
func (c call) wrap(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		st = status.FromContextError(err)
	}
	e := &RPCError{Agent: c.agent, Method: c.method, Code: st.Code(), Message: st.Message(), Kind: c.kind(st.Code())}
	for _, d := range st.Details() {
		if r, ok := d.(*agentv1.ResizeResult); ok {
			res := resizeResultFromProto(r)
			e.Result = &res
		}
	}
	return e
}

// codeKinds maps the codes whose meaning does not depend on the call.
var codeKinds = map[codes.Code]error{
	codes.Canceled:           context.Canceled,
	codes.DeadlineExceeded:   ErrDeadlineExceeded,
	codes.InvalidArgument:    ErrInvalidArgument,
	codes.NotFound:           ErrNotFound,
	codes.PermissionDenied:   ErrPolicyDenied,
	codes.Unauthenticated:    ErrUnauthenticated,
	codes.ResourceExhausted:  ErrHostOutOfMemory,
	codes.Aborted:            ErrShrinkRefused,
	codes.Unimplemented:      ErrUnimplemented,
	codes.FailedPrecondition: ErrFailedPrecondition,
	codes.Unavailable:        ErrUnavailable,
}

func (c call) kind(code codes.Code) error {
	switch {
	case code == codes.FailedPrecondition && c.write:
		return ErrFixedVM
	case code == codes.Unavailable && c.host:
		return ErrVMMSDown
	}
	if k, ok := codeKinds[code]; ok {
		return k
	}
	return ErrInternal
}
