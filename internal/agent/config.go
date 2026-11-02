package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/matfax/hvmc/internal/pki"
)

// Local configuration (DESIGN §4.3, §4.5)
//
// An agent reads its settings from one YAML file, agent.yaml:
//
//	name: host                            # agent name from enrollment (logs only)
//	role: host                            # host | guest
//	listen: 0.0.0.0:9443                  # mTLS gRPC
//	health: 0.0.0.0:9090                  # plain HTTP: /healthz, /readyz, /metrics
//	allowedClients: ["hvmc-coordinator"]  # client certificate CNs
//	firewall:
//	  remoteAddresses: []                 # used by `hvmc agent install`
//	vms: [...]                            # host role: the active write policy
//
// The `vms` key is the host's active write policy and is read by
// internal/policy, not by [ParseConfig]. Every other key is strict: an
// unknown key is an error, so a typo cannot silently weaken the settings.
//
// Keys, certificates, the pending policy and the audit log live in the
// state directory ([Paths]), because the configuration directory is
// read-only to the running service on both platforms.

// Role is the role an agent was installed with.
type Role string

// Agent roles.
const (
	// RoleHost is the agent on the Hyper-V host.
	RoleHost Role = "host"
	// RoleGuest is the agent inside a managed VM.
	RoleGuest Role = "guest"
)

// Defaults of the local configuration.
const (
	DefaultListen = "0.0.0.0:9443"
	DefaultHealth = "0.0.0.0:9090"
	// CoordinatorClientCN is the CN of the coordinator's client certificate
	// and the default of allowedClients.
	CoordinatorClientCN = pki.CoordinatorCommonName
)

// ErrInvalidConfig is returned (wrapped) for an agent.yaml that cannot be
// decoded or violates the rules of [Config.Validate].
var ErrInvalidConfig = errors.New("invalid agent configuration")

// Config is the agent's local configuration.
type Config struct {
	// Name is the agent's name in HostConfig, as returned by enrollment.
	// It only labels logs and audit entries.
	Name string `json:"name,omitempty"`
	// Role is host or guest.
	Role Role `json:"role"`
	// Listen is the host:port of the mTLS gRPC server.
	Listen string `json:"listen,omitempty"`
	// Health is the host:port of the plain-HTTP health server.
	Health string `json:"health,omitempty"`
	// AllowedClients lists the client certificate CNs that may call the
	// agent. Empty means [CoordinatorClientCN].
	AllowedClients []string `json:"allowedClients,omitempty"`
	// Firewall narrows the firewall rules written by `hvmc agent install`.
	Firewall *FirewallConfig `json:"firewall,omitempty"`
}

// FirewallConfig holds the optional firewall settings (DESIGN §4.5).
type FirewallConfig struct {
	// RemoteAddresses limits the rules for the listen and health ports to
	// these sources. Empty allows any source (the port is protected by mTLS).
	RemoteAddresses []string `json:"remoteAddresses,omitempty"`
}

// configFile is the strict shape of agent.yaml: Config plus the policy key,
// which belongs to internal/policy.
type configFile struct {
	Config
	VMs json.RawMessage `json:"vms,omitempty"`
}

// ParseConfig decodes agent.yaml, applies the defaults and validates the
// result. The `vms` key is accepted and ignored.
func ParseConfig(data []byte) (Config, error) {
	j, err := yaml.YAMLToJSONStrict(data)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	var f configFile
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	c := f.Config
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// LoadConfig reads and parses the configuration file at path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is the agent's own configuration file.
	if err != nil {
		return Config{}, err
	}
	c, err := ParseConfig(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.Health == "" {
		c.Health = DefaultHealth
	}
	if len(c.AllowedClients) == 0 {
		c.AllowedClients = []string{CoordinatorClientCN}
	}
}

// Validate checks the role, both addresses and allowedClients. It expects
// the defaults to be applied.
func (c Config) Validate() error {
	var errs []error
	if c.Role != RoleHost && c.Role != RoleGuest {
		errs = append(errs, fmt.Errorf("role %q, want %q or %q", c.Role, RoleHost, RoleGuest))
	}
	for _, a := range []struct{ key, addr string }{{"listen", c.Listen}, {"health", c.Health}} {
		if _, _, err := net.SplitHostPort(a.addr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a.key, err))
		}
	}
	for i, cn := range c.AllowedClients {
		if strings.TrimSpace(cn) == "" {
			errs = append(errs, fmt.Errorf("allowedClients[%d] is empty", i))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrInvalidConfig, errors.Join(errs...))
}

// Allows reports whether a client certificate CN is in allowedClients.
func (c Config) Allows(cn string) bool { return slices.Contains(c.AllowedClients, cn) }

// MergeConfigFile writes c into the configuration file at path, keeping
// the keys c does not set (the host's `vms` policy in particular). A new
// file of a host agent gets `vms: []`, the empty policy that allows no
// write, so the agent starts read-only until the operator activates a
// policy. Keys and comments are rewritten in sorted order; the file is
// replaced atomically with mode 0600.
func MergeConfigFile(path string, c Config) error {
	top := map[string]any{}
	old, err := os.ReadFile(path) //nolint:gosec // G304: the path is the agent's own configuration file.
	switch {
	case err == nil:
		if err := yaml.Unmarshal(old, &top); err != nil {
			return fmt.Errorf("%s: existing file is not a YAML mapping: %w", path, err)
		}
		if top == nil {
			top = map[string]any{}
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	j, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var set map[string]any
	if err := json.Unmarshal(j, &set); err != nil {
		return err
	}
	for k, v := range set {
		top[k] = v
	}
	if _, ok := top["vms"]; !ok && c.Role == RoleHost {
		top["vms"] = []any{}
	}
	out, err := yaml.Marshal(top)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, out, 0o600)
}

// Paths locates the agent's files.
type Paths struct {
	// Config is agent.yaml.
	Config string
	// State holds keys, certificates, the pending policy and the audit log.
	State string
	// Logs holds the rotating log files on Windows; empty on Linux, where
	// the agent logs to stderr (journald).
	Logs string
}

// File names inside the state directory.
const (
	caFile              = "ca.crt"
	servingFile         = "serving.pem"
	previousServingFile = "serving.previous.pem"
	pendingPolicyFile   = "policy.pending.yaml"
	auditFile           = "audit.log"
)

// DefaultPaths returns the platform's locations (DESIGN §4.5): on Linux
// /etc/hvmc/agent.yaml and /var/lib/hvmc; on Windows agent.yaml, keys and
// state in %ProgramData%\hvmc and logs in %ProgramData%\hvmc\logs.
func DefaultPaths() Paths {
	return defaultPaths(runtime.GOOS, os.Getenv)
}

func defaultPaths(goos string, getenv func(string) string) Paths {
	if goos == "windows" {
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		dir := base + `\hvmc`
		return Paths{Config: dir + `\agent.yaml`, State: dir, Logs: dir + `\logs`}
	}
	return Paths{Config: "/etc/hvmc/agent.yaml", State: "/var/lib/hvmc"}
}

// CA is the hvmc CA certificate pinned at enrollment (PEM).
func (p Paths) CA() string { return filepath.Join(p.State, caFile) }

// Serving is the serving key and certificate chain (one PEM file, so both
// change in one rename).
func (p Paths) Serving() string { return filepath.Join(p.State, servingFile) }

// PreviousServing is the last confirmed serving pair while a newly
// installed one waits for its first successful handshake.
func (p Paths) PreviousServing() string { return filepath.Join(p.State, previousServingFile) }

// PendingPolicy is the policy proposed by the coordinator, waiting for
// local confirmation.
func (p Paths) PendingPolicy() string { return filepath.Join(p.State, pendingPolicyFile) }

// AuditLog is the JSON-lines audit log of every write.
func (p Paths) AuditLog() string { return filepath.Join(p.State, auditFile) }

// writeFileAtomic replaces path with data: temporary file in the same
// directory, sync, chmod, rename.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
