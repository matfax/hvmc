package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/matfax/hvmc/internal/policy"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig([]byte(`
role: host
listen: 0.0.0.0:9443
health: 0.0.0.0:9090
allowedClients: ["hvmc-coordinator"]
vms:
  - name: linux-node-1
    fixed: true
`))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Role: RoleHost, Listen: "0.0.0.0:9443", Health: "0.0.0.0:9090", AllowedClients: []string{"hvmc-coordinator"}}
	if diff := cmp.Diff(want, c); diff != "" {
		t.Errorf("config (-want +got):\n%s", diff)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	c, err := ParseConfig([]byte("role: guest\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Role: RoleGuest, Listen: DefaultListen, Health: DefaultHealth, AllowedClients: []string{CoordinatorClientCN}}
	if diff := cmp.Diff(want, c); diff != "" {
		t.Errorf("defaults (-want +got):\n%s", diff)
	}
	if !c.Allows(CoordinatorClientCN) || c.Allows("other") {
		t.Error("Allows does not follow allowedClients")
	}
}

func TestParseConfigErrors(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown key":      "role: host\nlisten: :9443\nlsiten: :1\n",
		"bad role":         "role: coordinator\n",
		"missing role":     "listen: :9443\n",
		"bad listen":       "role: host\nlisten: 9443\n",
		"bad health":       "role: guest\nhealth: localhost\n",
		"empty client":     "role: guest\nallowedClients: [\"\"]\n",
		"not a mapping":    "- role: host\n",
		"duplicate key":    "role: host\nrole: guest\n",
		"firewall unknown": "role: host\nfirewall: {remote: []}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(doc)); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("ParseConfig: %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if _, err := LoadConfig(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v, want ErrNotExist", err)
	}
	writeTestFile(t, path, []byte("role: nope\n"))
	if _, err := LoadConfig(path); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("invalid file: %v", err)
	}
}

func TestMergeConfigFileKeepsPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	writeTestFile(t, path, []byte("role: host\nlisten: 0.0.0.0:1\nvms:\n  - name: vm-1\n    min: 1Gi\n    max: 2Gi\n"))
	before, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c := Config{Name: "host", Role: RoleHost, Listen: "0.0.0.0:9443", Health: DefaultHealth, AllowedClients: []string{"hvmc-coordinator"}}
	if err := MergeConfigFile(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(c, got); diff != "" {
		t.Errorf("merged settings (-want +got):\n%s", diff)
	}
	after, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Digest() != before.Digest() {
		t.Error("merging settings changed the active policy")
	}
}

func TestMergeConfigFileNewHostIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := MergeConfigFile(path, Config{Role: RoleHost}); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path)
	if err != nil {
		t.Fatalf("new host config has no loadable policy: %v", err)
	}
	if len(p.VMs) != 0 {
		t.Errorf("new host policy %v, want empty", p)
	}

	guest := filepath.Join(t.TempDir(), "agent.yaml")
	if err := MergeConfigFile(guest, Config{Role: RoleGuest}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(guest); err == nil {
		t.Error("guest config got a vms key")
	}
	if st, err := os.Stat(guest); err != nil {
		t.Fatal(err)
	} else if !isWindows() && st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", st.Mode().Perm())
	}
}

func TestMergeConfigFileRejectsNonMapping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	writeTestFile(t, path, []byte("- a\n"))
	if err := MergeConfigFile(path, Config{Role: RoleGuest}); err == nil {
		t.Error("merged into a YAML list")
	}
}

func TestDefaultPaths(t *testing.T) {
	linux := defaultPaths("linux", func(string) string { return "" })
	if diff := cmp.Diff(Paths{Config: "/etc/hvmc/agent.yaml", State: "/var/lib/hvmc"}, linux); diff != "" {
		t.Errorf("linux (-want +got):\n%s", diff)
	}
	env := map[string]string{"ProgramData": `D:\Data`}
	win := defaultPaths("windows", func(k string) string { return env[k] })
	want := Paths{Config: `D:\Data\hvmc\agent.yaml`, State: `D:\Data\hvmc`, Logs: `D:\Data\hvmc\logs`}
	if diff := cmp.Diff(want, win); diff != "" {
		t.Errorf("windows (-want +got):\n%s", diff)
	}
	if got := defaultPaths("windows", func(string) string { return "" }).State; got != `C:\ProgramData\hvmc` {
		t.Errorf("windows without ProgramData: %q", got)
	}
	if DefaultPaths().Config == "" {
		t.Error("DefaultPaths has no config path")
	}
}
