package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

// testNow is the wall clock of every test run.
var testNow = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// runCLI runs hvmc with args at testNow.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return runCLIEnv(t, env{now: func() time.Time { return testNow }}, args...)
}

func runCLIEnv(t *testing.T, e env, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = execute(e, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestStubs(t *testing.T) {
	for _, path := range []string{
		"serve",
		"agent install", "agent uninstall", "agent status", "agent policy sync",
		"check",
		"test run", "test list", "test logs",
		"token create",
	} {
		t.Run(path, func(t *testing.T) {
			code, out, errOut := runCLI(t, strings.Fields(path)...)
			if code != ExitFailure {
				t.Errorf("exit code = %d, want %d", code, ExitFailure)
			}
			if out != "" {
				t.Errorf("stdout = %q, want nothing", out)
			}
			if want := "Error: hvmc " + path + ": not implemented yet\n"; errOut != want {
				t.Errorf("stderr = %q, want %q", errOut, want)
			}
		})
	}
}

func TestStubFlags(t *testing.T) {
	code, _, errOut := runCLI(t, "agent", "install", "--role", "host", "--enroll", "https://hvmc.example.com/v1/enroll",
		"--token", "t", "--ca-sha256", "00")
	if code != ExitFailure || !strings.Contains(errOut, "not implemented yet") {
		t.Errorf("agent install with flags: code %d, stderr %q", code, errOut)
	}
}

func TestUsage(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		wantErr string
	}{
		{args: nil, wantErr: "hvmc needs a subcommand"},
		{args: []string{"bogus"}, wantErr: `unknown command "bogus" for "hvmc"`},
		{args: []string{"agent"}, wantErr: "hvmc agent needs a subcommand"},
		{args: []string{"agent", "bogus"}, wantErr: `unknown command "bogus" for "hvmc agent"`},
		{args: []string{"agent", "policy"}, wantErr: "hvmc agent policy needs a subcommand"},
		{args: []string{"ca"}, wantErr: "hvmc ca needs a subcommand"},
		{args: []string{"version", "extra"}, wantErr: "takes no arguments"},
		{args: []string{"serve", "--bogus"}, wantErr: "unknown flag: --bogus"},
		{args: []string{"plan"}, wantErr: "--filename (-f) is required"},
		{args: []string{"plan", "-f", "x.yaml", "-o", "yaml"}, wantErr: `--output "yaml"`},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			code, out, errOut := runCLI(t, tc.args...)
			if code != ExitUsage {
				t.Errorf("exit code = %d, want %d", code, ExitUsage)
			}
			if out != "" {
				t.Errorf("stdout = %q, want nothing", out)
			}
			if !strings.Contains(errOut, tc.wantErr) || !strings.Contains(errOut, "Usage:") {
				t.Errorf("stderr = %q, want %q and the usage", errOut, tc.wantErr)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		code, out, errOut := runCLI(t, args...)
		if code != ExitOK || out != "hvmc dev\n" || errOut != "" {
			t.Errorf("%v: code %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
}

func TestHelp(t *testing.T) {
	code, out, _ := runCLI(t, "--help")
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	for _, cmd := range []string{"agent", "ca", "check", "plan", "serve", "test", "token", "version"} {
		if !strings.Contains(out, "\n  "+cmd+" ") {
			t.Errorf("help does not list %s:\n%s", cmd, out)
		}
	}
	if strings.Contains(out, "completion") {
		t.Errorf("help lists the completion command:\n%s", out)
	}
}

func TestPlanGolden(t *testing.T) {
	dir := filepath.Join("testdata", "plan")
	hc := filepath.Join(dir, "hostconfig.yaml")
	for _, scenario := range []string{"idle", "pool-blocked", "frozen"} {
		for _, output := range []string{"text", "json"} {
			ext := map[string]string{"text": ".txt", "json": ".json"}[output]
			t.Run(scenario+"/"+output, func(t *testing.T) {
				code, out, errOut := runCLI(t, "plan", "-f", hc, "--scenario", filepath.Join(dir, scenario+".yaml"), "-o", output)
				if code != ExitOK {
					t.Fatalf("exit code = %d, stderr %q", code, errOut)
				}
				golden(t, filepath.Join(dir, scenario+ext), out)
			})
		}
	}
}

// golden compares got with the file at path, or rewrites it with -update.
func golden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if diff := cmp.Diff(string(want), got); diff != "" {
		t.Errorf("%s differs (-want +got; go test -update rewrites it):\n%s", path, diff)
	}
}

func TestPlanDerivedScenario(t *testing.T) {
	hc := writeFile(t, "hostconfig.yaml", `spec:
  capacity: 32Gi
  vms:
    - {name: linux-node-1, guestOS: linux, mode: fixed, base: 3Gi}
    - {name: vm-a, guestOS: windows, mode: static, base: 4Gi, margin: 1Gi}
    - {name: vm-dm, guestOS: windows, mode: dynamic, base: 2Gi, policy: {min: 2Gi, max: 8Gi}}
`)
	code, out, errOut := runCLI(t, "plan", "-f", hc)
	if code != ExitOK {
		t.Fatalf("exit code = %d, stderr %q", code, errOut)
	}
	// Every VM at its floor: linux-node-1 5Gi, vm-a 5Gi, vm-dm 4Gi with
	// maximum 8Gi. Free 32 - 14 = 18Gi; committed 5 + 5 + 8 = 18Gi; pool
	// min(32 - 4 - 18, 18 - 4) = 10Gi.
	for _, want := range []string{
		"frozen      no",
		"pool        10Gi",
		"linux-node-1  fixed    Ready  5Gi       3Gi   5Gi    0         5Gi        0",
		"vm-dm         dynamic  Ready  4Gi       2Gi   4Gi    0         8Gi        0",
		"no pending requests",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestPlanErrors(t *testing.T) {
	hc := filepath.Join("testdata", "plan", "hostconfig.yaml")
	notExist := notExistMessage(t, "testdata/plan/missing.yaml")
	for _, tc := range []struct {
		name     string
		hc       string
		scenario string
		wantErr  string
	}{
		{name: "missing HostConfig", hc: "testdata/plan/missing.yaml", wantErr: notExist},
		{name: "invalid HostConfig", hc: writeFile(t, "bad.yaml", "spec:\n  vms:\n    - {name: vm-a, guestOS: linux, mode: static, base: 1Gi}\n"), wantErr: "linux guests must use mode fixed"},
		{name: "no capacity without scenario", hc: hc, wantErr: "spec.capacity is 0"},
		{name: "missing scenario", hc: hc, scenario: "testdata/plan/missing.yaml", wantErr: notExist},
		{name: "unknown scenario field", hc: hc, scenario: writeFile(t, "s1.yaml", "host: {name: h, total: 8Gi}\nrequest: []\n"), wantErr: "unknown field"},
		{name: "invalid scenario", hc: hc, scenario: writeFile(t, "s2.yaml", "host: {name: h}\n"), wantErr: "host.total must be positive"},
		{name: "pod without candidates", hc: hc, scenario: writeFile(t, "s3.yaml", "host: {name: h, total: 8Gi}\nrequests:\n  - {kind: Pod, bytes: 1Gi}\n"), wantErr: "request request-1: kind Pod needs vm or candidateVMs"},
		{name: "candidates on external", hc: hc, scenario: writeFile(t, "s4.yaml", "host: {name: h, total: 8Gi}\nrequests:\n  - {vm: vm-a, candidateVMs: [vm-a], bytes: 1Gi}\n"), wantErr: "candidateVMs are only for kind Pod"},
		{name: "unmanaged VM", hc: hc, scenario: writeFile(t, "s5.yaml", "host: {name: h, total: 8Gi}\nrequests:\n  - {name: r, vm: vm-x, bytes: 1Gi}\n"), wantErr: "request r: ledger: unknown VM: vm-x"},
		{name: "invalid request", hc: hc, scenario: writeFile(t, "s6.yaml", "host: {name: h, total: 8Gi}\nrequests:\n  - {kind: Lease, vm: vm-a, bytes: 1Gi}\n"), wantErr: `kind "Lease"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"plan", "-f", tc.hc}
			if tc.scenario != "" {
				args = append(args, "--scenario", tc.scenario)
			}
			code, out, errOut := runCLI(t, args...)
			if code != ExitFailure {
				t.Errorf("exit code = %d, want %d", code, ExitFailure)
			}
			if out != "" {
				t.Errorf("stdout = %q, want nothing", out)
			}
			if !strings.Contains(errOut, tc.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", errOut, tc.wantErr)
			}
		})
	}
}

func TestPlanNotes(t *testing.T) {
	sc := writeFile(t, "scenario.yaml", `host: {name: hyperv-1, total: 64Gi, vmmsDown: true}
vms:
  - {name: vm-a, startup: 8Gi}
guests:
  - {name: vm-a, vm: vm-a, os: windows, used: 3Gi, sourceDown: true}
`)
	code, out, errOut := runCLI(t, "plan", "-f", filepath.Join("testdata", "plan", "hostconfig.yaml"), "--scenario", sc)
	if code != ExitOK {
		t.Fatalf("exit code = %d, stderr %q", code, errOut)
	}
	for _, want := range []string{
		"host agent  Degraded",
		"frozen      yes",
		"\nNotes\n  hyperv-1: GetHost: Unavailable: ",
		"  hyperv-1: ListVMs: Unavailable: ",
		"  vm-a: GetMemory: Unavailable: memory source could not be read\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestErrNotImplemented(t *testing.T) {
	cmd := newServeCommand()
	if err := cmd.RunE(cmd, nil); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("serve: error = %v, want ErrNotImplemented", err)
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanJSONFields(t *testing.T) {
	dir := filepath.Join("testdata", "plan")
	code, out, errOut := runCLI(t, "plan", "-f", filepath.Join(dir, "hostconfig.yaml"),
		"--scenario", filepath.Join(dir, "pool-blocked.yaml"), "-o", "json")
	if code != ExitOK {
		t.Fatalf("exit code = %d, stderr %q", code, errOut)
	}
	var got struct {
		Host struct {
			PoolBytes int64 `json:"poolBytes"`
		} `json:"host"`
		Queue []struct {
			ID            string `json:"id"`
			BlockingCause string `json:"blockingCause"`
		} `json:"queue"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Host.PoolBytes != 6<<30 {
		t.Errorf("host.poolBytes = %d, want 6Gi", got.Host.PoolBytes)
	}
	causes := map[string]string{}
	for _, r := range got.Queue {
		causes[r.ID] = r.BlockingCause
	}
	want := map[string]string{
		"request-6": "", "request-1": "", "request-2": "PoolShort",
		"request-3": "", "request-4": "", "request-5": "Queued",
	}
	if diff := cmp.Diff(want, causes); diff != "" {
		t.Errorf("blockingCause by request (-want +got):\n%s", diff)
	}
}

// notExistMessage returns the operating system's own text for opening a
// missing file ("no such file or directory" on Unix, "The system cannot find
// the file specified." on Windows).
func notExistMessage(t *testing.T, path string) string {
	t.Helper()
	_, err := os.Stat(path)
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("os.Stat(%q) = %v, want a not-exist PathError", path, err)
	}
	return pathErr.Err.Error()
}
