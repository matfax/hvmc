package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

func readAudit(t *testing.T, path string) []AuditEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []AuditEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("audit line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func TestAuditEntriesForWrites(t *testing.T) {
	e := newEnv(t, hostConfigYAML, newTestService())
	e.start()
	conn := e.dial(CoordinatorClientCN)
	host := agentv1.NewHostAgentClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Reads and refused callers leave no audit entry.
	_, err1 := host.GetHost(ctx, &agentv1.GetHostRequest{})
	_, err2 := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err := errors.Join(err1, err2); err != nil {
		t.Fatal(err)
	}
	_, _ = agentv1.NewHostAgentClient(e.dial("intruder")).SetStartup(ctx, &agentv1.SetStartupRequest{VmName: "vm", StartupBytes: 1})

	p := proposed()
	_, err1 = host.SetStartup(ctx, &agentv1.SetStartupRequest{VmName: "windows-node-1", StartupBytes: 8 << 30})
	_, failed := host.SetStartup(ctx, &agentv1.SetStartupRequest{VmName: "windows-node-1"})
	_, err2 = host.ProposePolicy(ctx, &agentv1.ProposePolicyRequest{Policy: p.Proto(), Digest: p.Digest()})
	_, err3 := agentv1.NewCertificateServiceClient(conn).RotateCertificate(ctx, &agentv1.RotateCertificateRequest{})
	if err := errors.Join(err1, err2, err3); err != nil || failed == nil {
		t.Fatalf("writes: %v; SetStartup with 0 bytes: %v", err, failed)
	}

	entries := readAudit(t, e.paths.AuditLog())
	if len(entries) != 4 {
		t.Fatalf("%d audit entries, want 4: %+v", len(entries), entries)
	}
	for _, en := range entries {
		if en.ClientCN != CoordinatorClientCN || en.Agent != "host" || !en.Time.Equal(t0) {
			t.Errorf("entry %+v: want client %s, agent host, time %v", en, CoordinatorClientCN, t0)
		}
	}
	checkSetStartupEntries(t, entries[0], entries[1])
	checkProposeEntry(t, entries[2], p.Digest())
	checkRotateEntry(t, entries[3])
}

func checkSetStartupEntries(t *testing.T, ok, failed AuditEntry) {
	t.Helper()
	if ok.Method != agentv1.HostAgent_SetStartup_FullMethodName || ok.Code != "OK" ||
		!strings.Contains(string(ok.Request), `"startupBytes":"8589934592"`) ||
		string(ok.Before) != `{"startupBytes":4294967296}` || string(ok.After) != `{"startupBytes":8589934592}` {
		t.Errorf("successful write entry: %s %s request %s before %s after %s", ok.Method, ok.Code, ok.Request, ok.Before, ok.After)
	}
	if failed.Code != "InvalidArgument" || failed.Error == "" || failed.After != nil {
		t.Errorf("failed write entry: %+v", failed)
	}
}

func checkProposeEntry(t *testing.T, en AuditEntry, digest string) {
	t.Helper()
	var before, after policyState
	if err := errors.Join(json.Unmarshal(en.Before, &before), json.Unmarshal(en.After, &after)); err != nil {
		t.Fatal(err)
	}
	if en.Method != agentv1.HostAgent_ProposePolicy_FullMethodName || before.Pending != "" ||
		after.Pending != digest || after.Active != before.Active {
		t.Errorf("ProposePolicy entry: before %+v after %+v", before, after)
	}
}

func checkRotateEntry(t *testing.T, en AuditEntry) {
	t.Helper()
	var before, after certSummary
	if err := errors.Join(json.Unmarshal(en.Before, &before), json.Unmarshal(en.After, &after)); err != nil {
		t.Fatal(err)
	}
	if en.Method != agentv1.CertificateService_RotateCertificate_FullMethodName || before.PendingKey || !after.PendingKey {
		t.Errorf("RotateCertificate entry: before %+v after %+v", before, after)
	}
}

func TestAuditRecordLogs(t *testing.T) {
	var buf bytes.Buffer
	a := NewAudit(nil, "guest-1", newTestClock(), slog.New(slog.NewJSONHandler(&buf, nil)))
	a.Record(AuditEntry{ClientCN: "c", Method: "/m", Code: "OK", Before: marshalAudit(map[string]int{"x": 1})})
	if !strings.Contains(buf.String(), `"msg":"write"`) || !strings.Contains(buf.String(), `"before":"{\"x\":1}"`) {
		t.Errorf("log record %s lacks the write", buf.String())
	}
	if got := marshalAudit(func() {}); !strings.Contains(string(got), "unencodable") {
		t.Errorf("unencodable value: %s", got)
	}
	if marshalAudit(nil) != nil {
		t.Error("nil value encoded")
	}
	SetAuditBefore(context.Background(), 1) // no-op outside a call
}
