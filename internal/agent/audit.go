package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// WriteMethods are the agent API's write RPCs. Every call to one of them,
// successful or not, produces an audit entry (DESIGN §4.5): the client CN,
// the request, the state before and after, and the result.
var WriteMethods = []string{
	agentv1.HostAgent_SetStartup_FullMethodName,
	agentv1.HostAgent_SetDynamicLimits_FullMethodName,
	agentv1.HostAgent_ProposePolicy_FullMethodName,
	agentv1.CertificateService_RotateCertificate_FullMethodName,
	agentv1.CertificateService_InstallCertificate_FullMethodName,
}

// AuditEntry is one line of the audit log.
type AuditEntry struct {
	Time     time.Time       `json:"time"`
	Agent    string          `json:"agent,omitempty"`
	ClientCN string          `json:"clientCN"`
	Method   string          `json:"method"`
	Request  json.RawMessage `json:"request,omitempty"`
	Before   json.RawMessage `json:"before,omitempty"`
	After    json.RawMessage `json:"after,omitempty"`
	// Code is the gRPC status code name of the result ("OK" on success).
	Code  string `json:"code"`
	Error string `json:"error,omitempty"`
}

// Audit records every write RPC as a JSON line in the audit log and as a
// log record. Handlers report the state they changed with
// [SetAuditBefore] and [SetAuditAfter]; the interceptor writes the entry
// when the handler returns, so a write is audited even if its handler
// reports nothing.
type Audit struct {
	agent  string
	clk    Clock
	log    *slog.Logger
	writes map[string]bool

	mu sync.Mutex
	w  io.Writer
}

// NewAudit returns an audit log writing JSON lines to w (nil: log records
// only).
func NewAudit(w io.Writer, agent string, clk Clock, log *slog.Logger) *Audit {
	writes := make(map[string]bool, len(WriteMethods))
	for _, m := range WriteMethods {
		writes[m] = true
	}
	return &Audit{agent: agent, clk: clk, log: log, writes: writes, w: w}
}

type auditKey struct{}

// auditRecord collects what a handler reports about one write.
type auditRecord struct {
	mu            sync.Mutex
	before, after any
}

// SetAuditBefore records the state a write RPC is about to change. It is a
// no-op outside an audited call.
func SetAuditBefore(ctx context.Context, v any) {
	if r, ok := ctx.Value(auditKey{}).(*auditRecord); ok {
		r.mu.Lock()
		r.before = v
		r.mu.Unlock()
	}
}

// SetAuditAfter records the state after a write RPC. It is a no-op outside
// an audited call.
func SetAuditAfter(ctx context.Context, v any) {
	if r, ok := ctx.Value(auditKey{}).(*auditRecord); ok {
		r.mu.Lock()
		r.after = v
		r.mu.Unlock()
	}
}

// UnaryInterceptor audits the write methods and passes every other call
// through. It runs after the client CN check, so refused clients are
// logged by that check, not here.
func (a *Audit) UnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !a.writes[info.FullMethod] {
		return handler(ctx, req)
	}
	rec := &auditRecord{}
	resp, err := handler(context.WithValue(ctx, auditKey{}, rec), req)
	rec.mu.Lock()
	before, after := rec.before, rec.after
	rec.mu.Unlock()
	a.Record(AuditEntry{
		ClientCN: ClientCN(ctx),
		Method:   info.FullMethod,
		Request:  marshalAudit(req),
		Before:   marshalAudit(before),
		After:    marshalAudit(after),
		Code:     status.Code(err).String(),
		Error:    errorText(err),
	})
	return resp, err
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	if s, ok := status.FromError(err); ok {
		return s.Message()
	}
	return err.Error()
}

// Record writes one entry. The time and agent name are filled in.
func (a *Audit) Record(e AuditEntry) {
	e.Time = a.clk.Now().UTC()
	e.Agent = a.agent
	line, err := json.Marshal(e)
	if err != nil {
		a.log.Error("audit entry not encodable", "method", e.Method, "error", err)
		return
	}
	a.log.Info("write",
		"method", e.Method, "client", e.ClientCN, "code", e.Code, "error", e.Error,
		"request", string(e.Request), "before", string(e.Before), "after", string(e.After))
	if a.w == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.w.Write(append(line, '\n')); err != nil {
		a.log.Error("writing the audit log failed", "method", e.Method, "error", err)
	}
}

// marshalAudit encodes v for an entry: protobuf messages as protojson,
// everything else as JSON, nil as nothing.
func marshalAudit(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	var out []byte
	var err error
	if m, ok := v.(proto.Message); ok {
		out, err = protojson.MarshalOptions{EmitUnpopulated: false}.Marshal(m)
	} else {
		out, err = json.Marshal(v)
	}
	if err != nil {
		out, _ = json.Marshal(map[string]string{"unencodable": err.Error()})
	}
	return out
}
