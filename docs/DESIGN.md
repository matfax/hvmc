# hvmc — design

This document specifies hvmc: what it does, how its parts work together and what it requires from the platforms it runs on. Sections marked **DEFERRED** are intentionally out of scope for now. **One `helm install` deploys and wires everything that lives in Kubernetes** (§11): coordinator, its own scheduler, admission webhook, Services, agent service entries, certificates, Ingress and NetworkPolicies. The coordinator is the only container. Nothing on the control plane is modified and no manual Kubernetes wiring is needed. Every agent runs natively as a system service — systemd on Linux, a Windows service on Windows — and needs no container runtime; each machine takes one self-installing command (§4.5), printed by the chart's NOTES.txt. No node or kubelet configuration is required (§10).

## 0. One-paragraph summary

hvmc (Hyper-V Memory Coordinator) is a Go service running in Kubernetes that owns a single RAM ledger for all VMs on one Hyper-V host and hands out *memory leases*. Two front doors: a dedicated scheduler (`hvmc-scheduler`, upstream kube-scheduler shipped by the chart, with hvmc as its **extender** for filter/prioritize/bind) for pods that request the extended resource `hvmc.fax.fyi/ram` — an admission webhook routes those pods to it automatically — and an **HTTP facade** (`/v1/leases`) for clients outside Kubernetes, for example a container orchestrator on a Windows VM that runs Docker. The coordinator never shells into anything: it talks gRPC over mutual TLS to **agents** — one **host agent** (Windows service on the Hyper-V host, the only component that touches Hyper-V) and one **guest agent** per managed VM (systemd service on Linux, Windows service on Windows; never a container). A lease is granted only when the target VM has headroom or the shared host pool can cover it; a Windows VM is grown *before* the slot is handed out and the growth is verified inside the guest (Linux VMs are fixed-size and admission-only, §1); otherwise the request waits in a single priority-FIFO queue shared by pods and facade clients. A reconciler keeps every managed VM's free memory inside a hysteresis band around a fixed, absolute margin (default 2 GiB, no percentages). Agents are registered as Kubernetes service entries (EndpointSlices) whose readiness is driven by a health mechanism that also gates the ledger. A web **dashboard** shows scheduling and health live and runs **active tests** that exercise the real production path — test pods through the scheduling chain, probe resizes on a disposable VM — on demand or on a schedule (§15).

## 1. Platform facts

- Hyper-V host: Windows Server with the Hyper-V role (runtime memory resize requires 2016 or later) and PowerShell 7 (`pwsh`) installed.
- Cluster: any conformant Kubernetes ≥ 1.30 (admission webhook `matchConditions`). hvmc runs its own scheduler instance in-cluster, so the cluster's default scheduler and control plane are never touched.
- Managed VMs, all on the one Hyper-V host: Linux Kubernetes nodes, Windows Kubernetes nodes, and Windows VMs outside Kubernetes that are served through the facade. Hyper-V VM names may differ from Kubernetes node names, so the mapping is explicit configuration.
- Hyper-V memory: static-memory VMs can be grown at runtime on any guest; shrunk at runtime only with Windows guests; Linux guests shrink only on reboot. Dynamic Memory (DM) balloons guests on its own and offers no target-setting API (runtime levers: raise `MaximumBytes`, lower `MinimumBytes`, `Priority`, `Buffer`). A failed shrink may still change the configured `StartupBytes`.
- Kubelet (verified through 1.36) never re-reads machine info: it is cached once in `NewMainKubelet`, and `node.status.capacity`/`allocatable` are recomputed from that copy on every status sync until kubelet restarts. KEP-3953 (Node Resource Hot Plug) would change this but is not in any release through 1.36.
- Linux consequence: with the default `enforceNodeAllocatable: [pods]`, the container manager writes the `kubepods` cgroup `memory.max` once at startup as `capacity − kubeReserved − systemReserved` (the eviction threshold is subtracted only from reported allocatable, not from the cgroup), and the QoS-level cgroups are refreshed from the same boot-time number. After a hot-add the pods' aggregate footprint hits the old ceiling and the kernel OOM-kills inside `kubepods`; eviction never gets a vote. **Therefore Linux VMs that are Kubernetes nodes are never resized at runtime** (§3.1 `mode: fixed`), which costs nothing extra because Linux guests cannot shrink anyway.
- Windows consequence: none that matters. Windows has no cgroup hierarchy (per-container job-object limits only), stale `capacity` is irrelevant because the webhook normalizes `requests.memory` (§7.1), and Windows eviction computes `memory.available` live from the OS commit limit − committed (`GetPerformanceInfo()`), not from cached capacity. The commit limit includes the page file, so Windows eviction thresholds act on commit charge, not physical RAM.
- Extended resources are not overcommittable: the API server requires them in `limits`, and `requests`, if set, must equal `limits`. Kubelet admission ignores extended resources that are absent from node allocatable (it assumes a scheduler extender manages them), so no node-status patching is needed.
- When `limits.memory` is set and `requests.memory` is not, `requests.memory` defaults to the limit. The in-tree `NodeResourcesFit` filter runs before extenders.
- PowerShell remoting over SSH does not support JEA, and no mature Go PSRP client exists; this is why hvmc uses its own agents instead of SSH or WinRM.

## 2. Repository and artifacts

- Repo: `github.com/matfax/hvmc` (Go module path identical). License MIT.
- Binary: `hvmc`, single binary, subcommands:
  - `serve` — the coordinator.
  - `agent run|install|uninstall|enroll|status` — host or guest agent (`--role host|guest`); `install`/`uninstall` register and remove the agent as a native system service (Windows service or systemd unit, §4.5). No separate installer.
  - `plan` — dry-run ledger from a HostConfig file against the fake host.
  - `check` — end-to-end connectivity, identity, health and policy check (reads HostConfig status through the caller's kubeconfig).
  - `test run|list|logs` — create a `TestRun` for a built-in active test (§15.4), list runs, show a run's steps and measurements; equivalent to the dashboard's test controls.
  - `ca export` — print the CA certificate and its SHA-256 fingerprint.
  - `token create --agent <name>` — re-issue a bootstrap token for an agent (the coordinator creates the first one automatically, §4.6).
- Scheduler image: upstream `registry.k8s.io/kube-scheduler`, tag derived by the chart from the cluster's version (`.Capabilities.KubeVersion`, distribution suffix stripped), overridable. No custom scheduler build.
- Coordinator image: `docker.io/matfax/hvmc:<semver>` and `:latest` (published from the first release on), `linux/amd64` only, built with `ko` (distroless static base, non-root, `-trimpath`, version from tag). It is the only image hvmc builds.
- Agent binaries (plain `go build`, `CGO_ENABLED=0`): `hvmc_<ver>_linux_amd64.tar.gz` and `hvmc_<ver>_windows_amd64.zip`, attached to the GitHub Release with SHA-256 checksums and cosign blob signatures. The same `hvmc` binary is coordinator and agent; agents just run `hvmc agent`.
- Chart: `charts/hvmc/` in the repo, installed from a checkout (`helm install hvmc ./charts/hvmc`); chart version = app version. Publishing to `oci://ghcr.io/matfax/charts/hvmc` is **DEFERRED**.
- Toolchain: `k8s.io/*` modules at the newest Kubernetes minor at project start (v0.37.x; controller-runtime v0.25), the controller-runtime release built against them, and the Go version those modules require (the `go` directive follows them). kubebuilder v4 layout. Code generation: controller-gen (CRDs, deepcopy, RBAC) and buf only; generated code is committed. Dependencies are fixed in §2.1.

```
cmd/hvmc/                 main, cobra subcommands
api/v1alpha1/             HostConfig, MemoryLease types
proto/hvmc/agent/v1/      host.proto, guest.proto, cert.proto, policy.proto, common.proto
internal/ledger/          pure budget math + queue + state machine (no I/O, ≥ 95 % covered)
internal/grant/           grant executor: reserve → resize → verify → commit, shrink path, dispatcher (§3.2)
internal/leases/          MemoryLease store: the only code that creates/updates MemoryLease objects
internal/policy/          canonical host-policy model, digest and diff (agent and coordinator)
internal/serve/           coordinator process: manager, leader election, listeners
internal/cli/             subcommand implementations
internal/agentapi/        generated gRPC code
internal/agent/host/      host agent: pwsh worker, local policy, Hyper-V ops
internal/agent/guest/     guest agent: Linux /proc/meminfo, Windows counters
internal/agent/svc/       service integration: Windows SCM + Event Log + firewall; systemd unit + sd_notify/watchdog
internal/agentclient/     coordinator-side clients, health tracker, EndpointSlice writer
internal/pki/             internal CA, enrollment, rotation
internal/extender/        HTTP handlers for filter / prioritize / bind
internal/webhook/         mutating admission for hvmc pods (§7.1)
internal/facade/          HTTP facade /v1/leases (+ auth)
internal/reconcile/       per-VM hysteresis loop
internal/controllers/     MemoryLease controller (CRD ↔ ledger), HostConfig controller, pod watcher
internal/fake/            fake host + guest agents (in-process gRPC), used by unit and envtest
charts/hvmc/
pkg/facadeclient/         Go client for the facade (the only public package)
examples/                 PowerShell facade client, orchestrator contract
test/e2e/                 kind-based end-to-end tests
internal/selftest/        active tests (§15.4): test catalog, TestRun/TestSchedule controllers
internal/dashboard/       web dashboard (§15): handlers, templates, SSE, rolling history, embedded assets
config/samples/           example CRs
docs/                     DESIGN.md (this file), install (chart, Hyper-V host, guest agents, facade clients), operations runbook
hack/                     e2e scripts
.github/workflows/        ci.yaml, release.yaml
```

### 2.1 Dependencies

Anything not listed here needs a reason in the PR that adds it. Prefer the standard library where it is equally clear.

**Coordinator**

| Purpose | Library |
|---|---|
| Controllers, leader election, webhook server, metrics endpoint, envtest | `sigs.k8s.io/controller-runtime` (+ `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`) |
| CRD, deepcopy, RBAC generation | `sigs.k8s.io/controller-tools` (controller-gen) |
| Extender wire types | `k8s.io/kube-scheduler/extender/v1` |
| Effective pod request (init, sidecar, overhead rules) | `k8s.io/component-helpers/resource` (`PodRequests`) — never reimplemented |
| Quantities (`4Gi`), also in agent config | `k8s.io/apimachinery/pkg/api/resource` |
| Facade HTTP | stdlib `net/http` (method/path patterns), no framework |
| Internal CA, CSRs, bootstrap tokens | stdlib `crypto/x509`, `crypto/ecdsa`, `crypto/rand`; no PKI library, no cert-manager |
| Metrics | `github.com/prometheus/client_golang` (controller-runtime registry; agents use their own registry for `/metrics` on the health port, §4.8) |
| Logging | stdlib `log/slog`, bridged to controller-runtime's `logr` via `logr.FromSlogHandler`; token redaction with a `ReplaceAttr` |
| Dashboard | stdlib `html/template`, `embed`, `net/http` (server-sent events); one vendored, pinned htmx file (0BSD) as a static asset — no JavaScript build step and no additional Go dependency |

**Shared (coordinator and agents)**

| Purpose | Library |
|---|---|
| Agent API | `google.golang.org/grpc`, `google.golang.org/protobuf`, `google.golang.org/grpc/health` (`grpc.health.v1`) |
| CLI | `github.com/spf13/cobra` |
| Config files | `sigs.k8s.io/yaml` |
| Collection helpers (sums, filters, group-bys in the ledger) | `github.com/samber/lo`, only where stdlib `slices`/`maps` is clumsier |

**Windows agent**

| Purpose | Library |
|---|---|
| Service runtime, install/remove, recovery actions | `golang.org/x/sys/windows/svc`, `golang.org/x/sys/windows/svc/mgr` |
| Event Log | `golang.org/x/sys/windows/svc/eventlog`, wrapped in a small hvmc slog handler |
| Log fan-out (Event Log + rotating file in `C:\ProgramData\hvmc\logs`) | `github.com/samber/slog-multi` (`Fanout`) |
| ACLs on `C:\ProgramData\hvmc` | `golang.org/x/sys/windows` (SDDL, `SetNamedSecurityInfo`) |
| Service account → *Hyper-V Administrators* | `NetLocalGroupAddMembers` via `golang.org/x/sys/windows` lazy DLL |
| Guest memory (total, available) | `GlobalMemoryStatusEx` via `golang.org/x/sys/windows`; no WMI, no perf-counter library |
| Hyper-V control (host role) | stdlib `os/exec` + `encoding/json` driving the pwsh worker (§4.2) |
| Firewall rules | built-in `New-NetFirewallRule` / `Remove-NetFirewallRule` via `os/exec` |

**Linux agent**

| Purpose | Library |
|---|---|
| Readiness and watchdog (`READY=1`, `WATCHDOG=1`) | `github.com/coreos/go-systemd/v22/daemon` |
| Unit install, enable, start, daemon-reload | `github.com/coreos/go-systemd/v22/dbus` (typed errors instead of parsing `systemctl` output) |
| `/proc/meminfo` | stdlib parsing (two fields) |
| `ufw` rules (only if active) | `os/exec` |
| Logging | stdlib `log/slog` to stderr (captured by journald) |

**Testing**

| Purpose | Library / tool |
|---|---|
| Unit and table tests | stdlib `testing` + `github.com/google/go-cmp` |
| Ledger property tests (with shrinking) | `pgregory.net/rapid` |
| Controller tests | controller-runtime `envtest`, stdlib `testing` (no Ginkgo/Gomega) |
| Chart | `helm lint`, golden files from `helm template`, `ct` + kind |

**Build and release tooling:** `ko`, `buf`, `golangci-lint`, `cosign`, controller-gen, `setup-envtest`, Dependabot.

**Deliberately not used:** `golang.org/x/crypto/ssh`, `masterzen/winrm`, `microsoft/wmi`, GoReleaser, cert-manager, Ginkgo/Gomega, HTTP frameworks, `samber/do` (controller-runtime's Manager owns lifecycle), `samber/mo` (all APIs touched are `(T, error)`), `samber/oops` (errors map to gRPC status codes and condition reasons), `samber/hot`, `samber/ro`, `samber/slog-formatter`.

## 3. Ledger (core model)

All quantities in bytes (`resource.Quantity` at the API edge, `int64` inside).

### 3.1 Quantities

```
assigned(vm)    = host agent's MemoryAssigned for vm (all VMs on the host, unmanaged included, read-only)
base(vm)        = configured: what the VM needs with zero leases (OS + kubelet/containerd or Docker daemon)
margin(vm)      = configured absolute value, default 2Gi (per VM or global); NEVER a percentage; counted once per VM
leased(vm)      = Σ bytes of leases on vm in phase Reserved|Resizing|Granted
used(vm)        = guest agent's total − available (when fresh, §4.4)
effBase(vm)     = max(base(vm), used(vm) − leased(vm))       lease workloads are capped at their lease, so
                                                             used − leased is a lower bound on non-lease usage
floor(vm)       = effBase(vm) + leased(vm) + margin(vm)      assigned must never go below
headroom(vm)    = assigned(vm) − floor(vm)                   may be negative
committed(vm)   = managed fixed:   assigned(vm)                    (never resized; leases are admission-only within it)
                  managed static:  max(assigned(vm), floor(vm))
                  managed DM:      dmAccounting=maximum → MaximumBytes; =assigned → max(assigned, floor)
                  unmanaged:       static → assigned; DM → MaximumBytes (always worst case)
pool            = min( capacity − reserve − Σ committed(vm),  hostFree − reserve )
delta(r, vm)    = quantize_up(r.bytes − max(headroom(vm), 0), step)    0 if headroom covers the request
fits(r, vm)     = delta(r, vm) == 0  OR  pool ≥ delta(r, vm)
```

`capacity` defaults to the host's physical memory as reported by the host agent; `reserve` is `HostConfig.spec.reserve` / chart value `hostConfig.reserve`, default `4Gi`, configurable (e.g. `8Gi`). The `hostFree` term absorbs per-VM worker-process overhead that `MemoryAssigned` does not include. Reconciler grows reserve pool exactly like leases (an internal reservation with `owner.kind: Reconciler`), so `committed` covers every in-flight change. VM modes: `fixed` (static memory, size set at boot, never changed by hvmc; required for Linux guests), `static` (static memory, runtime resize; Windows guests only), `dynamic` (Hyper-V Dynamic Memory; Windows guests only, §4.2). HostConfig validation rejects any other combination. For a `fixed` VM, `fits` reduces to `headroom(vm) ≥ r.bytes`. Linux nodes should therefore boot at the ceiling their workloads need.

`step` default `256Mi`; all targets are quantized to it (Hyper-V requires 2 MiB alignment; 256Mi satisfies it).

Memory of an issued grow stays in `committed` (and is treated as already taken from `hostFree`) until the next host observation reports it, also after a rollback or release of that request, so two reservations never draw the same bytes.

Overcommit knobs: none.

### 3.2 Locking

One ledger mutex guards only in-memory state; **no I/O under it**. Every state change follows reserve → act → commit:

1. Under the mutex: check `fits`, move the request to `Reserved` (it now counts in `leased` and therefore in `committed` and `pool`).
2. Outside the mutex, holding the per-VM operation lock: call the host agent, then the guest agent for verification.
3. Under the mutex: commit (`Granted`) or roll back (`Failed`, reservation released).

Filter/prioritize therefore never wait on I/O. The per-VM lock serializes resizes of one VM; resizes of different VMs proceed in parallel.

This sequence exists exactly once, in the **grant executor** (`internal/grant`), and every requester uses it: extender bind (§7.3), the facade (§8), the reconciler (§9) and the active tests (§15.4). The executor also owns the shrink path (reserve shrink → `SetStartup` lower → midpoint retry, max 3 → re-read `MemoryAssigned`/`MemoryStartup` and repair, §3.5) and a **dispatcher** that serves non-pod requests in queue order as soon as they are grantable. Pod requests are granted only from bind, because the scheduler chooses their node.

### 3.3 Lease state machine

`Pending → Reserved → Resizing → Granted → Released`, plus `Failed` (from Pending on deadline, from Reserved/Resizing on error). `Resizing` = resize issued, waiting for guest verification. `Granted` only after verification (§4.4).

### 3.4 Queue

One queue for all requesters (pods, facade clients, reconciler grows), ordered by `priorityClass` (int, default 0, higher first) then arrival time. Pods get their queue position at their **first filter call** (§7), not at bind.

Grant rule (starvation-free, no backfill in v1): requests are evaluated in queue order, each as if every earlier request had been granted, so earlier requests use up the pool and their VMs' headroom first. A request that does not fit waits, and while it waits it **locks** its candidate VMs: no later request may take headroom on them. If at least one of its candidates is resizable (`static` or `dynamic`), it also locks the **pool**: no later request may draw from it (`delta > 0`). A waiting request whose candidates are all `fixed` cannot use the pool and therefore does not lock it. Requests that wait because of an earlier lock lock their own candidates the same way. Pod requests have the candidate VMs of their filter's node list; facade requests have exactly one. Reconciler grows for running workloads are queued at `priorityClass = +∞` when `reconciler.priorityOverQueue: true` (default), i.e. running workloads win over waiting ones.

Waiting is explicit state, not a timeout; a request carries an optional `deadline` after which it turns `Failed(Timeout)`.

### 3.5 Persistence and recovery

MemoryLease objects are the single source of truth (the facade and the extender both create them). On start (and on leader takeover) the ledger is rebuilt from MemoryLeases plus fresh host-agent and guest-agent data, before any front door reports ready:

- `Granted`: checked per VM, oldest grant first, against the static bound `base + Σ leased` (the configured `base`, not `effBase`, and no margin — a VM under normal load, with free memory below its margin, keeps its leases). A lease that still fits under `assigned` is kept; one that does not is `Failed(Lost)` + event; never silently re-grow. Without fresh VM data, Granted leases are kept.
- `Reserved` / `Resizing`: re-read `assigned`. If it covers the lease's floor, re-run guest verification → `Granted`; otherwise drop back to `Pending` at its original queue position.
- `Pending`: re-enqueue at original position (`status.enqueuedAt`).

After any shrink attempt (success or error) re-read both `MemoryAssigned` and `MemoryStartup`; if `MemoryStartup` changed although assignment did not, restore `MemoryStartup` to the assigned value and emit an event.

## 4. Agents

### 4.1 Roles

| Role | Where | Runs as | Talks to |
|---|---|---|---|
| host | Hyper-V host, Windows service `hvmc-agent` | virtual account `NT SERVICE\hvmc-agent`, member of *Hyper-V Administrators* | local Hyper-V (pwsh worker) |
| guest (Linux VM) | systemd service `hvmc-agent.service` | `DynamicUser=yes`, no capabilities | `/proc/meminfo` |
| guest (Windows VM, node or not) | Windows service `hvmc-agent` | virtual account `NT SERVICE\hvmc-agent` | `GlobalMemoryStatusEx` |

Agents are servers; the coordinator (leader only) is the client. Traffic: coordinator → each agent's gRPC port; each agent → the enrollment endpoint once (§4.6); the facade client → the facade. The chart creates every in-cluster piece of that path (Services, Ingress, NetworkPolicies, §11).

### 4.2 Host agent API (`hvmc.agent.v1.HostAgent`)

```proto
rpc GetHost(GetHostRequest) returns (Host);                  // total, free, agent version, policy digest
rpc ListVMs(ListVMsRequest) returns (ListVMsResponse);       // name, id, state, assigned, startup, dm{enabled,min,max,buffer,priority}, observed_at
rpc WatchVMs(WatchVMsRequest) returns (stream VMSnapshot);   // full snapshot on connect, then on change (local poll 2 s)
rpc SetStartup(SetStartupRequest) returns (ResizeResult);    // static VMs; result carries assigned/startup before & after
rpc SetDynamicLimits(SetDynamicLimitsRequest) returns (ResizeResult); // DM VMs; max only raises, min only lowers
rpc ProposePolicy(ProposePolicyRequest) returns (ProposePolicyResponse); // stores a pending policy only, §4.3
rpc GetDiagnostics(GetDiagnosticsRequest) returns (GetDiagnosticsResponse); // anonymised record of raw cmdlet errors, §15.4
rpc RotateCertificate(...) / InstallCertificate(...)         // §4.6
```

Implementation: the agent supervises one long-lived `pwsh -NoLogo -NoProfile -NonInteractive` worker process with the Hyper-V module loaded once, speaking length-prefixed JSON over stdin/stdout; requests are serialized, each with a timeout (default 30 s); a hung or crashed worker is killed and restarted. Cmdlets used: `Get-VM`, `Get-VMMemory`, `Set-VMMemory`, `Get-CimInstance Win32_OperatingSystem`. All JSON produced with explicit `Select-Object` projections, enums stringified, `ConvertTo-Json -AsArray -Compress -Depth 4`. Errors map to typed gRPC status codes (`FailedPrecondition` for writes to a `fixed` VM, `ResourceExhausted` for host out of memory, `Aborted` for guest refused shrink, `Unavailable` for VMMS down).

Resize semantics:
Writes apply to Windows VMs in `static` or `dynamic` mode only; `fixed` VMs are read-only to the agent.
- Static grow: `Set-VMMemory -VMName X -StartupBytes N` while running.
- Static shrink: same cmdlet with lower N. On `Aborted`, the coordinator retries at the midpoint between N and the current assignment, at most 3 attempts; never fails the reconciler on it.
- `fixed` VM: any write refused by the agent (`FailedPrecondition`).
- DM VM: `SetDynamicLimits` only; the agent rejects lowering max or raising min.

### 4.3 Host-side policy (defence in depth)

The host agent enforces its own policy from a **local** file `C:\ProgramData\hvmc\agent.yaml` (ACL: Administrators + the service account, read-only for the latter). The initial content comes with the enrollment response (§4.6) and is confirmed by the operator at install time (§4.5). Afterwards the active policy is never changed remotely: the coordinator may only **propose** a new policy (RPC `ProposePolicy`, stored as pending in `policy.pending.yaml` in the agent's state directory, because the service cannot write `agent.yaml`), and `hvmc agent policy sync`, run on the host, shows the diff between active and proposed and activates it after local confirmation. So a compromised coordinator or a stolen client certificate can only do what this file allows:

```yaml
role: host
listen: 0.0.0.0:9443
health: 0.0.0.0:9090
allowedClients: ["hvmc-coordinator"]      # certificate CN
vms:
  - name: linux-node-1
    fixed: true                           # read-only
  - name: windows-node-1
    min: 6Gi
    max: 24Gi
  - name: docker-host-1
    min: 4Gi
    max: 32Gi
```

Reads (`ListVMs`, `WatchVMs`) cover all VMs (the pool needs them); writes are allowed only for listed VMs within `[min, max]`. The policy derived from HostConfig (`internal/policy`) lists every managed VM: `fixed` VMs read-only; `static`/`dynamic` VMs with a `policy` writable within `[policy.min, policy.max]`; `static`/`dynamic` VMs without a `policy` (admission-only, probe VMs) writable within `[base, capacity − reserve]`, where capacity is `spec.capacity` or, when that is 0, the capacity the coordinator has observed (unbounded only until the host has been observed once — the first observation therefore produces a new proposal). Operators who want tighter bounds without the reconciler give the VM a `policy` with `grow: false, shrink: false`. Lease grows on a VM never exceed its policy maximum, because the agent refuses them. `GetHost` returns the canonical digest of the active policy (`internal/policy`, the same function the coordinator uses); a mismatch with the digest of the policy derived from HostConfig sets `PolicyInSync=False` and the coordinator proposes the derived policy.

The running agent re-reads `agent.yaml` and the pending file on every main-loop tick (§4.8), so an activation by `policy sync` (a separate process) takes effect without a restart. If `agent.yaml` cannot be parsed, the agent fails closed: the active policy is the empty one (every write refused) and the readiness check *local policy file parsed* fails. `ProposePolicy` refuses a request without a policy (`INVALID_ARGUMENT`); an explicit empty policy is valid and manages no VM.

Besides `vms`, `agent.yaml` holds `name` (the agent's HostConfig name, for logs and audit entries) and `firewall.remoteAddresses` (§4.5). Unknown keys are an error. `listen` and `health` default to `0.0.0.0:9443` and `0.0.0.0:9090`, `allowedClients` to `["hvmc-coordinator"]`.

### 4.4 Guest agent API (`hvmc.agent.v1.GuestAgent`) and verification

```proto
rpc GetMemory(GetMemoryRequest) returns (GuestMemory);   // total, available, observed_at; Windows: commit_limit, commit_available
rpc WatchMemory(WatchMemoryRequest) returns (stream GuestMemory);  // every 5 s and on change
```

- Linux: `MemTotal`, `MemAvailable` from `/proc/meminfo`.
- Windows: `GlobalMemoryStatusEx` — total physical (`ullTotalPhys`), available (`ullAvailPhys`), commit limit (`ullTotalPageFile`) and available commit (`ullAvailPageFile`). The commit figures feed the page-file check (§10).
- `used = total − available`.

Grow verification after `SetStartup`: on first contact the coordinator records `offset(vm) = assigned − guest total` (firmware/kernel reservations). Verified when `guest total ≥ new assigned − offset − step/2`. (Only Windows VMs are ever resized, so there is no Linux hot-add onlining to check.) Timeout 60 s (configurable); on timeout the lease fails and the reservation rolls back; the memory stays assigned and is reused or shrunk later.

Data freshness: every value carries `observed_at`; values older than `staleAfter` (default 30 s) are treated as missing.

### 4.5 Service entry on the machine (self-installing)

The agent installs and removes itself; there is no MSI, package or container. One command per machine, run as Administrator / root (the chart's NOTES.txt prints it per agent with every value filled in):
```
hvmc agent install --role host|guest --agent <name> --enroll <enrollment URL> --token <bootstrap token> --ca-sha256 <fp>
```
Common to both platforms:
- Copies its own binary to the system location, enrolls (§4.6), fetches the agent's settings from HostConfig and writes the local config. For the host role this includes the write policy (§4.3), shown to the operator for confirmation before it is written.
- Idempotent: re-running `install` with a newer binary upgrades in place (stop → replace binary → start → wait for ready), keeping config and keys. `uninstall` reverses everything; `status` prints service state, health checks and certificate expiry.
- Logs every lifecycle event, health transition and write operation (writes include client CN and before/after values). Every call of a write RPC (`SetStartup`, `SetDynamicLimits`, `ProposePolicy`, `RotateCertificate`, `InstallCertificate`), successful or not, is also appended as one JSON line to `audit.log` in the state directory: time, agent, client CN, method, request, state before and after, gRPC status code. The file rotates at 10 MiB and keeps 5 generations.
- State directory (`C:\ProgramData\hvmc\`, `/var/lib/hvmc/`): `ca.crt` (the CA pinned at enrollment), `serving.pem` (key and certificate chain in one file, so both change with one rename), `serving.previous.pem` (only while a new certificate is unconfirmed, §4.6), `policy.pending.yaml` (§4.3), `audit.log`. `hvmc agent run` and `enroll` take `--config` and `--state-dir` to override the platform defaults.
- The gRPC port is protected by mTLS, so firewall rules allow any source by default; `firewall.remoteAddresses` optionally narrows them.

Windows (the Hyper-V host and Windows guests):
- Binary `C:\Program Files\hvmc\hvmc.exe`, config and keys in `C:\ProgramData\hvmc\` (ACL: Administrators + the service account).
- Service `hvmc-agent` (display name *Hyper-V Memory Coordinator Agent*), *Automatic (Delayed Start)*, account `NT SERVICE\hvmc-agent`; host role adds a dependency on `vmms` and adds the virtual account to *Hyper-V Administrators*.
- Recovery actions: restart after 5 s, 30 s, 60 s; reset after 1 day; actions also for stops with errors.
- Windows Event Log source `hvmc-agent`; Windows Firewall rules for the `listen` and `health` ports.
- Implements SCM stop/shutdown/preshutdown cleanly (drains in-flight requests up to 20 s) via `golang.org/x/sys/windows/svc`.

Linux (systemd-based distributions; CI tests on Ubuntu LTS):
- Binary `/usr/local/bin/hvmc`, config `/etc/hvmc/agent.yaml`, keys in `/var/lib/hvmc/` (`ConfigurationDirectory=`, `StateDirectory=`).
- Unit `/etc/systemd/system/hvmc-agent.service`: `Type=notify` (READY=1 after readiness checks pass), `WatchdogSec=30s` (WATCHDOG=1 from the main loop), `Restart=on-failure`, `RestartSec=5s`, `DynamicUser=yes`, `CapabilityBoundingSet=` (empty), `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute=yes`; `systemctl enable --now`.
- Logs to journald (`journalctl -u hvmc-agent`). If `ufw` is active, adds allow rules for the two ports; otherwise touches no firewall.
- Stops cleanly on SIGTERM (same 20 s drain).

### 4.6 Identity: internal CA, enrollment, rotation

- The coordinator owns a CA: Secret `hvmc-ca` (generated on first start if absent, or provided via `pki.existingCASecret`), ECDSA P-256, 10-year validity. `hvmc ca export` prints it with its SHA-256 fingerprint.
- Leaf certificates: 30 days, renewed at 2/3 of lifetime. Coordinator client cert CN `hvmc-coordinator`. Serving certs for the extender and the webhook with their Service DNS names as SANs (derived, no values). Agent server certs with the agent's DNS name, plus for VMs mapped to a node the node name and its `InternalIP` (the address the coordinator dials, §4.7). The enrollment response also returns the agent's settings derived from HostConfig (and, for the host role, the proposed policy) for `hvmc agent install` to write. All coordinator certificates (client, extender, webhook) are renewed in place without restart. The CA certificate is published in ConfigMap `hvmc-ca-bundle` (mounted by `hvmc-scheduler`) and injected as `caBundle` into the MutatingWebhookConfiguration by the coordinator.
- **Every agent** enrolls once: `hvmc agent enroll --role host|guest --agent <name> --enroll <enrollment URL> --token <bootstrap> --ca-sha256 <fp>` (the same flags as `hvmc agent install`, §4.5; the URL is the full endpoint, e.g. `https://hvmc.example.com/v1/enroll`). The agent generates its key locally (key never leaves the machine), sends a CSR plus a single-use bootstrap token, and pins the CA by fingerprint. The coordinator creates a bootstrap token Secret `hvmc-bootstrap-<agent>` automatically for every declared agent that is not enrolled yet, with the token in data key `token` (valid 24 h, re-created on expiry until enrollment; `hvmc token create` re-issues on demand). `<agent>` is the agent's name: `spec.agents[].name` for the host agent, the VM name for a guest agent. HostConfig validation requires both to be DNS-1123 labels (`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, at most 63 characters), so they are used in object names without normalization. The coordinator signs only SANs listed for that agent in HostConfig.
- The enrollment endpoint carries bootstrap tokens, so it is exposed outside the cluster only over TLS (§8).
- **Enrollment wire format** (types in `internal/pki/enrollwire.go`, shared by the agent's client and the coordinator's handler): `POST /v1/enroll` with `Authorization: Bearer <bootstrap token>` and a JSON body `{agent, role, csr}` — the agent name, `host` or `guest`, and a PEM PKCS #10 CSR signed by the agent's new ECDSA P-256 key. Only the CSR's key is used; subject and SANs come from HostConfig. Success is `200` with `{certificate, caCertificate, settings, policy}`: the PEM serving certificate (leaf first, then any intermediates), the PEM CA certificate, `settings` `{port, healthPort, allowedClients}` (0 or empty mean the defaults 9443, 9090 and `hvmc-coordinator`), and for the host role the proposed policy in the canonical form of `internal/policy`. A refusal is a JSON `{error}` body with `400` (malformed request or CSR, unknown role), `401` (missing, wrong, expired or used token), `403` (role or certificate not allowed for this agent) or `404` (no such agent in HostConfig).
- **Enrollment trust**: the URL must be `https`, and redirects are never followed. The endpoint's TLS certificate is verified the standard way against the system roots: the endpoint is the Ingress or a TLS-terminating load balancer (§8), never served with an hvmc CA certificate, so an Ingress with a private CA needs that CA in the machine's trust store. Nothing in the response is used before `caCertificate` matches `--ca-sha256`; the leaf must then chain to that CA as a serving certificate and carry the agent's key. `hvmc agent enroll` stores the certificate, the CA and the settings, and stores a host's policy as **pending** only: it becomes active through `hvmc agent policy sync` or the confirmation in `hvmc agent install`. A new host `agent.yaml` starts with the empty policy (`vms: []`, no writes allowed).
- **Renewal** is coordinator-driven over the existing mTLS channel: `RotateCertificate` (agent creates a new key and returns a CSR) → coordinator signs → `InstallCertificate` (agent swaps atomically, keeps the old pair until the next successful handshake). The first handshake with the new certificate that completes with a verified client certificate confirms it and discards the old pair. If instead a client refuses the new certificate (it answers the handshake with a TLS alert), the agent rolls back to the old pair while that one is still valid. A failure while storing the new pair leaves the old one active (`INTERNAL`). The pending key of `RotateCertificate` lives in memory only; after a restart the coordinator rotates again. No agent → coordinator path is needed after enrollment.
- Agents accept only client certs chained to the CA (TLS 1.3, checked in the handshake) with a CN in `allowedClients` (checked per call: `UNAUTHENTICATED` otherwise, for every service including health). The coordinator accepts only agent certs chained to the CA whose SAN matches the configured agent.

### 4.7 Service entries in Kubernetes

Every agent is addressable in-cluster under a stable name, and its endpoint readiness reflects its health:
- The coordinator manages a selectorless Service plus EndpointSlice per agent (`hvmc-host-agent`, `hvmc-guest-<vm>`), label `endpointslice.kubernetes.io/managed-by: hvmc.fax.fyi`, `addressType: IPv4`, ports `grpc` 9443 and `metrics` 9090, endpoint `conditions.ready/serving` set from the health tracker (§4.8). Addresses are derived and kept current by the coordinator: for a VM mapped to a node, the Node's `InternalIP`; otherwise resolved from the agent's `dnsName`; `address` is an optional override.
- A `ServiceMonitor` (when `metrics.serviceMonitor.enabled`) scrapes the `metrics` port of every Service in the release namespace labelled `hvmc.fax.fyi/metrics=true`: the chart's `hvmc-metrics` (coordinator) and every agent Service, which the coordinator labels that way.

### 4.8 Health mechanism

Agent side:
- gRPC `grpc.health.v1.Health` (`Check` + `Watch`) on the mTLS port, per service (`hvmc.agent.v1.HostAgent` / `GuestAgent`) and overall.
- Plain HTTP on the health port (no secrets exposed): `/healthz` (liveness: main loop ticked within 10 s), `/readyz` (all readiness checks pass; the body lists each check), `/metrics` (`hvmc_agent_ready`, `hvmc_agent_readiness_check{check}`, `hvmc_agent_info{version,role,name}`, `hvmc_agent_serving_cert_not_after_seconds`, host role `hvmc_agent_policy_pending`, plus Go and process metrics).
- Main loop: ticks every 5 s; each tick records liveness, re-reads the host policy (§4.3), evaluates the readiness checks and pings the service manager's watchdog. Readiness checks only read state the role keeps current, so they never block; a hung check hangs the loop, which `/healthz` and the watchdog then report.
- Stop (SIGTERM, SCM stop/shutdown/preshutdown): every health status turns `NOT_SERVING`, open streams (`Health.Watch`, `WatchVMs`, `WatchMemory`) end, the server stops accepting connections and waits up to 20 s for in-flight calls, then closes what is left.
- Readiness checks, host role: `vmms` service running; pwsh worker alive; last successful `Get-VM` within 2× poll interval; local policy file parsed; serving cert valid for > 72 h. Guest role: last successful memory read within 2× poll interval; cert valid.
- Service-manager integration: on Linux, readiness is reported with `sd_notify(READY=1)` and liveness with the systemd watchdog, so a hung main loop is restarted by systemd. On Windows, a hung main loop or a pwsh worker that fails to restart 5 times in 5 minutes makes the agent exit non-zero so SCM recovery restarts it. The reason is logged (journald / Event Log).

Coordinator side (leader):
- Health tracker per agent: keeps a `Health.Watch` stream open and additionally calls `Check` every 5 s with a 2 s deadline. States: `Ready`, `Degraded` (reachable but NOT_SERVING, or data stale), `Unreachable` (3 consecutive failures). Transitions emit Kubernetes events and update `HostConfig.status.agents[]` conditions (`Ready`, `CertificateValid`, `PolicyInSync`, with `lastTransitionTime`, `lastSeen`, version), the agent's EndpointSlice conditions, and metrics `hvmc_agent_up`, `hvmc_agent_state`, `hvmc_agent_cert_expiry_seconds`.
- Gating (nothing is ever revoked because an agent is unhealthy):
  - Host agent not `Ready` → the ledger freezes: filter fails all nodes with `hvmc: host agent <state>`, binds fail fast, facade requests stay `Pending`, reconciler pauses. Granted leases stay granted.
  - Guest agent for a VM not `Ready` → that VM is `Unknown`: grants with `delta == 0` (no resize) are still allowed; grants needing a resize on that VM are held (verification impossible); the reconciler leaves the VM alone.
- The coordinator's own readiness does **not** depend on agent health (the extender must keep answering with reasons).

## 5. CRDs (`hvmc.fax.fyi/v1alpha1`, cluster-scoped)

Secrets referenced by cluster-scoped objects live in the release namespace. The chart renders HostConfig from `values.hostConfig` into ConfigMap `hvmc-hostconfig`, and the coordinator applies it (§11). VM and agent names are DNS-1123 labels (§4.6).

**HostConfig** (singleton named `default`):
```yaml
spec:
  capacity: 0                 # 0 = read from host agent
  reserve: 4Gi                # default 4Gi, configurable
  defaultMargin: 2Gi
  step: 256Mi
  dmAccounting: maximum       # maximum | assigned (managed DM VMs)
  staleAfter: 30s
  agents:
    - name: host
      role: host
      dnsName: hyperv-01.example.com
      # address: optional override; otherwise resolved from dnsName
      port: 9443
  vms:                        # every VM the ledger manages; unmanaged VMs are still read for the pool
    - name: linux-node-1      # Hyper-V name
      node: linux-node-1      # Kubernetes node name (enables the extender; agent address = node InternalIP)
      guestOS: linux          # linux | windows
      mode: fixed             # fixed | static | dynamic; linux → fixed only (§3.1)
      base: 3Gi
      margin: 2Gi             # optional, overrides defaultMargin
    - name: windows-node-1
      node: windows-node-1
      guestOS: windows
      mode: static
      base: 4Gi
      testing:                # optional opt-in for active tests on this VM/node (§15.4)
        enabled: true
        maxBytes: 1Gi         # cap for any single test request [1Gi]
      policy:                 # optional, static/dynamic only; without it the VM is admission-only (no reconciler)
        min: 6Gi
        max: 24Gi
        grow: true
        shrink: true
        shrinkHysteresis: 1Gi # shrink only when free > margin + this
        dwell: 5m             # ...for this long
        cooldown: 60s         # min time between resizes of this VM
    - name: docker-host-1     # no node: facade-only target
      guestOS: windows
      mode: static
      base: 3Gi
      guestAgent: { dnsName: docker-host-1.example.com, port: 9443 }
    - name: probe-1           # disposable VM for the probe-resize active test (§15.4); never carries workloads
      guestOS: windows
      mode: static
      base: 2Gi
      probe: true
      guestAgent: { dnsName: probe-1.example.com, port: 9443 }
status:
  observedHost: { capacity, free, pool, observedAt }
  agents: [{ name, state, version, lastSeen, certExpiry, conditions }]
  vms: [{ name, assigned, startup, floor, headroom, leased, used, available, state, conditions }]
  conditions: [Ready, LedgerFrozen]
```
Status is written only on change, rate-limited to once per 10 s.

**MemoryLease**:
```yaml
spec:
  vm: docker-host-1               # facade/probe: required; pods: set once at bind from the chosen node (immutable once set)
  candidateVMs: [...]             # pods: from the filter node list (queue rule §3.4)
  bytes: 6Gi
  priorityClass: 0
  owner: { kind: Pod|External|Reconciler|Probe, namespace, name, uid }   # Pod leases are owner-referenced to the pod
  client: orchestrator            # External: facade client name
  idempotencyKey: ...             # External
  ttl: 2h                         # External only; renewed by heartbeat
  deadline: 2026-11-01T12:00:00Z  # optional: fail if not granted by then
status:
  phase: Pending|Reserved|Resizing|Granted|Released|Failed
  reason, message, enqueuedAt, grantedAt, expiresAt, assignedBefore, assignedAfter
```

MemoryLease objects are created and updated only through the lease store (`internal/leases`), used by the extender, the facade, the reconciler and the probe; the MemoryLease controller handles watch-driven transitions (release, TTL, deadline). `spec` is immutable except `ttl`, `deadline`, `candidateVMs` (while `Pending`) and a one-time set of `vm`.

For pods, `bytes` = the pod's effective request for `hvmc.fax.fyi/ram`, computed as Kubernetes does: max(Σ app containers + Σ restartable init containers, largest regular init container) + pod overhead.

## 6. HA and front-door placement

- Coordinator Deployment with 2 replicas and leader election (`coordination.k8s.io` Lease). Only the leader holds the ledger, talks to agents and writes status.
- Pod readiness means "process up and serving" on every replica, so the webhook works everywhere and the Deployment is Available (`helm --atomic` works). Leader-only routing uses a label instead: after taking leadership **and** completing the ledger rebuild (§3.5), the leader labels its own pod `hvmc.fax.fyi/leader=true`; the `hvmc-extender`, `hvmc-facade` and `hvmc-dashboard` Services select that label. A replica that loses leadership exits (controller-runtime default), so a stale label cannot outlive it. Failover gap ≈ lease duration (15 s); during it `hvmc-scheduler` cannot reach the extender and, because `ignorable: false`, hvmc pods simply wait.
- The admission webhook needs no ledger and is served by **every** replica (separate Service without leader gating), so pod creation never depends on a failover.
- Process interface the chart relies on: `hvmc serve --leader-elect=true --http-bind-address=:8080 --metrics-bind-address=:9090 --health-probe-bind-address=:8081`, plus `--hostconfig-configmap=hvmc-hostconfig` unless `hostConfig.existing` (§11) and `--existing-ca-secret=<name>` when `pki.existingCASecret` is set (§4.6). The pod's name and namespace come from the downward API as `POD_NAME` and `POD_NAMESPACE`; the leader patches the label onto that pod. Probes use the health port `:8081`: liveness `/healthz`, readiness `/readyz` ("process up and serving", above).
- `hvmc-scheduler` Deployment: 2 replicas, its own leader election Lease.
- PodDisruptionBudgets `maxUnavailable: 1` for both.

## 7. Scheduling

### 7.1 Routing pods to hvmc (admission webhook)

Pod authors only add the extended resource to `limits`. A MutatingWebhookConfiguration (shipped by the chart, served by the coordinator on `:9444`) matches pod CREATE with a CEL `matchCondition` — `object.spec.containers` or `initContainers` has a `limits` entry for `hvmc.fax.fyi/ram` — so no other pod ever reaches the webhook. `failurePolicy: Fail`, so an hvmc pod can never be scheduled past the ledger. It:
- sets `schedulerName: hvmc-scheduler` (rejects a pod that explicitly names another non-default scheduler);
- sets `requests.memory` of each container (regular or init) that carries a `hvmc.fax.fyi/ram` limit to `podDefaults.memoryRequest` [64Mi]; other containers are left alone. By admission time Kubernetes has already defaulted `requests.memory` to `limits.memory`, which would make the in-tree `NodeResourcesFit` filter reject nodes that are about to be grown; for hvmc pods the lease is the memory reservation, so the request is normalized always;
- adds `limits.memory` = the container's `hvmc.fax.fyi/ram` limit when `limits.memory` is unset, so the container is capped at its lease. A pod submitted with only the RAM limit is BestEffort; after the webhook it is Burstable;
- annotates `hvmc.fax.fyi/managed: "true"`.

Pod contract (README):
```yaml
resources:
  limits:
    hvmc.fax.fyi/ram: 6Gi    # the only required field; everything else is set by the webhook
```

### 7.2 hvmc-scheduler (shipped by the chart)

An upstream kube-scheduler Deployment with one profile, rendered by the chart into a ConfigMap; it runs in-cluster with its own ServiceAccount (bound to `system:kube-scheduler`, `system:volume-scheduler`, and `extension-apiserver-authentication-reader` in `kube-system`, plus a Role in the release namespace granting `coordination.k8s.io` `leases` `create`, and `get`/`update` on `resourceNames: [hvmc-scheduler]` — `system:kube-scheduler` only covers the lease named `kube-scheduler`, so without this Role the scheduler never becomes leader), so it uses in-cluster config and resolves cluster DNS:
```yaml
apiVersion: kubescheduler.config.k8s.io/v1
kind: KubeSchedulerConfiguration
leaderElection:
  leaderElect: true
  resourceName: hvmc-scheduler
  resourceNamespace: {{ .Release.Namespace }}
profiles:
  - schedulerName: hvmc-scheduler
extenders:
  - urlPrefix: https://hvmc-extender.{{ .Release.Namespace }}.svc:8443/scheduler
    filterVerb: filter
    prioritizeVerb: prioritize
    bindVerb: bind
    weight: 1
    enableHTTPS: true
    tlsConfig: { caFile: /etc/hvmc/ca/ca.crt }   # ConfigMap hvmc-ca-bundle
    httpTimeout: 120s        # bind includes resize + verify
    nodeCacheCapable: true
    ignorable: false
    managedResources:
      - name: hvmc.fax.fyi/ram
        ignoredByScheduler: true
```
Known property of running a second scheduler: its cache does not see the default scheduler's in-flight decisions, so a CPU-tight node can occasionally reject an hvmc pod at kubelet admission. The pod then fails, the MemoryLease controller releases its lease, and the owning controller recreates it. hvmc pods' memory is not affected (the ledger is authoritative).

### 7.3 Extender behaviour

Served by the coordinator on `:8443` (TLS from the internal CA). Only `hvmc-scheduler` calls it, and only for pods that request the resource; hvmc's own pods never do, so there is no bootstrap dependency.
- **Filter**: on the first call for a pod UID, create its MemoryLease in `Pending` (queue position = now; owner reference to the pod). For each candidate node mapped to a managed VM, evaluate `fits` under the queue rule (§3.4) without reserving. Nodes with no VM mapping fail for these pods. The `FailedNodes[node]` reason is a **fixed string per cause** — `hvmc: node not managed`, `hvmc: waiting for memory on this VM`, `hvmc: waiting for host pool`, `hvmc: queued behind earlier requests`, `hvmc: host agent unavailable`, `hvmc: guest agent unavailable`. Every change of the text rewrites the pod's `PodScheduled` condition, which requeues the pod immediately and defeats backoff (a counter in the text was measured at ~55 filter calls/s). Queue position, needed bytes, headroom and pool go to the MemoryLease status, rate-limited Events and the dashboard (§15.2) instead.
- **Filter cost**: any cluster event requeues every waiting hvmc pod, so filter is a read-only ledger evaluation: no agent calls, no API writes after the first call for a pod (MemoryLease creation is idempotent), and a call-rate metric `hvmc_extender_filter_calls_total`.
- **Prioritize**: 0–10, prefer `delta == 0` (no resize), then larger headroom.
- **Bind**: Pending → Reserved (VM = chosen node's VM) → resize if `delta > 0` → verify → Granted → `POST pods/<name>/binding` → return. Any failure: lease back to `Pending` (keeps queue position) for retryable errors, `Failed` otherwise; return an error so the scheduler retries. Bind runs in the scheduler's asynchronous binding cycle, so a slow resize does not block other scheduling.
- **Requeue nudge**: when capacity frees up and a waiting pod lease becomes grantable, the coordinator patches the pod's annotation `hvmc.fax.fyi/queue-generation`, so the scheduler re-evaluates it at once instead of leaving it in the unschedulable queue until an unrelated cluster event or the 5-minute flush. The `requeue` active test (§15.4) and the e2e test assert < 1 s from release to the next filter call.
- **Release**: the MemoryLease controller marks a pod lease `Released` when the pod object is deleted or reaches `Succeeded|Failed` — not when `deletionTimestamp` is set, because containers keep running through the grace period. Owner references make GC the backstop.

## 8. HTTP facade (clients outside Kubernetes)

Coordinator `:8080`, exposed by the chart (Ingress, or a `LoadBalancer` Service, §11). The same listener serves `/v1/enroll` for one-time agent enrollment (§4.6). `:8080` is plain HTTP inside the cluster; TLS terminates at the Ingress (`facade.ingress.tls`) or at a TLS-terminating load balancer (provider annotations on `facade.service`). Enrollment carries bootstrap tokens and the facade bearer tokens, so both are exposed only over TLS; NOTES.txt warns when the chart's exposure is plain HTTP. Auth: bearer token on **every** endpoint including `GET /v1/vms` (Secret `facade.existingTokenSecret`, entries name → token; the name becomes the lease `client`); TokenReview-based auth is a later addition.

```
POST   /v1/leases                 {vm, bytes, priorityClass?, ttl?, deadline?}  → 202 {id, phase, queuePosition}
GET    /v1/leases/{id}?wait=30s   long-poll until phase changes or timeout       → 200 {id, phase, reason, queuePosition, expiresAt}
POST   /v1/leases/{id}/heartbeat  extends expiresAt by ttl                       → 204
DELETE /v1/leases/{id}            → Released                                      → 204
GET    /v1/vms                    read-only ledger view                           → 200
GET    /healthz /readyz           on the health port :8081, not :8080 (probes; unauthenticated, no data);  /metrics on :9090 (cluster-internal only)
```
A facade lease is a MemoryLease with `owner.kind: External`; expiry (no heartbeat within ttl) releases it. Idempotency: `client` + `Idempotency-Key` header.

Client contract, using a container orchestrator on a Docker VM as the example (documented, not implemented here): request → wait for Granted → `docker run --memory=<bytes>` → on container exit DELETE; heartbeat every ≤ ttl/3. The token must live only in the orchestrator's context (service account / credential store), never in the containers it starts: containers share the VM's source IP, so network filtering cannot distinguish them from the orchestrator.

## 9. Reconciler

Per `static` or `dynamic` VM with a `policy` (Windows guests; `fixed` VMs have no reconciler), on every guest-memory update:
```
free      = guest available                (from the guest agent, not assigned − used)
target    = used + margin
grow  if free < margin                     → enqueue Reconciler request for
                                              min(max, quantize_up(assigned + (margin − free) + step))
shrink if free > margin + shrinkHysteresis for ≥ dwell AND shrink allowed AND now − lastResize ≥ cooldown
                                           → assign max(min, floor, quantize_up(assigned − (free − margin)))
```
Rules: never below `floor`; grows go through the ledger queue (§3.4) like every other request; Windows shrink retry per §4.2; pool short → event + metric, the request waits in the queue. DM VMs: the reconciler only sets `MaximumBytes = policy.max` and `MinimumBytes = policy.min` once (via `SetDynamicLimits`); everything else is Hyper-V's.

## 10. Node requirements

None. No kubelet or node configuration is required on any node, which keeps the whole in-cluster part inside the Helm chart:
- Linux nodes are `fixed` (§3.1), so kubelet's boot-time capacity, the `kubepods` cgroup limit and eviction all stay truthful for the VM's whole life. Size the VM at the ceiling its workloads need before boot; changing it is a planned reboot outside hvmc.
- Windows nodes are resized at runtime safely for the reasons in §1 (no cgroup ceiling, live eviction signal, webhook-normalized requests). The install doc notes that Windows eviction thresholds act on commit charge, so the page-file size matters.
- `hvmc check` warns when a Linux VM mapped to a node is not `fixed` (validation already rejects it in HostConfig) and when a Windows node's page file is disabled (commit limit = RAM, eviction becomes tighter than expected).

## 11. Helm chart (`charts/hvmc/`)

The chart is the complete in-cluster application: `helm install` (and `helm uninstall`) creates (and removes) everything below; `--atomic` works because readiness reflects real state. Nothing is configured by hand in Kubernetes afterwards.

Templates:
- CRDs as regular templates (not `crds/`), so `helm upgrade` updates them and `helm uninstall` removes them with all CRs; value `crds.keep` [false] adds `helm.sh/resource-policy: keep` for operators who want them retained. `make manifests` copies the generated CRDs into the chart, so the two never drift.
- HostConfig `default` is rendered from `values.hostConfig`, but not as a HostConfig template: Helm builds every object of a release before it creates any, so a custom resource whose CRD is a template of the same release fails the first install ("ensure CRDs are installed first"); a hook would not help either (hooks are created, never updated, and recreating HostConfig would garbage-collect everything owned by it). The chart therefore ships the complete HostConfig manifest in ConfigMap `hvmc-hostconfig` (key `hostconfig.yaml`), and the coordinator server-side applies it (field manager `hvmc-chart`) on start and whenever the ConfigMap changes; apply errors surface as events and in the logs, and `values.schema.json` catches most of them at `helm install`. HostConfig has no owner reference to the ConfigMap, so with `crds.keep` it survives uninstall like the CRDs. With `hostConfig.existing: true` the chart renders no ConfigMap and the operator manages HostConfig `default` directly (kubectl, GitOps); the coordinator then only reads it.
- Cleanup: every object the coordinator creates at runtime (agent Services/EndpointSlices, `hvmc-ca`, bootstrap Secrets, `hvmc-ca-bundle`, MemoryLeases without a pod owner) carries an owner reference to HostConfig `default`, so uninstall leaves nothing behind. Reinstalling therefore creates a new CA and agents re-enroll (documented).
- Coordinator: Deployment, ServiceAccount, ClusterRole/Binding (pods get/list/watch/patch; pods/binding create; nodes get/list/watch; services, endpointslices, secrets, configmaps in the release namespace; mutatingwebhookconfigurations get/patch (own object, caBundle); events create/patch; coordination leases; hvmc.fax.fyi/*), PodDisruptionBudget. Rules a namespace suffices for (the four resources above, leases, and pods while they only serve the leader label) are a Role in the release namespace; events are cluster-wide because events about cluster-scoped objects are recorded in `default`.
- `hvmc-scheduler`: Deployment, ConfigMap (§7.2), ServiceAccount + bindings, leader-lease Role + RoleBinding (§7.2), PodDisruptionBudget.
- Dashboard and active tests (§15): `hvmc-dashboard` Service (leader), Ingress path `/ui` on the facade Ingress, `TestRun`/`TestSchedule` CRDs, the namespace `hvmc-tests` with a Role/RoleBinding letting the coordinator create and delete pods there, and a NetworkPolicy that admits dashboard traffic only from the ingress controller (the auth proxy's identity headers are trusted only on that path).
- MutatingWebhookConfiguration (§7.1), webhook Service (all replicas).
- Services: `hvmc-extender` (leader), `hvmc-facade` (leader; ClusterIP or LoadBalancer), `hvmc-webhook` (all), `hvmc-metrics`. Selectorless agent Services/EndpointSlices are created by the coordinator from HostConfig (§4.7).
- Ingress for facade + enrollment (`/v1/leases`, `/v1/vms`, `/v1/enroll`), TLS from a values-named Secret or cert-manager annotations.
- NetworkPolicies, all derived from the chart's own objects: `hvmc-scheduler` → extender; any → webhook port (API server source varies by distribution); ingress controller namespace (value, default: any) → facade; coordinator egress → API server, DNS, agent gRPC port; (agents are outside the cluster; their exposure is the mTLS port, §4.5).
- ServiceMonitor (optional), selecting Services labelled `hvmc.fax.fyi/metrics=true` (§4.7).
- Secret for facade tokens when given in values (document ESO/OpenBao as the preferred source).
- NOTES.txt: for every declared agent (host and every VM), the exact download + `hvmc agent install` command for its platform (enrollment URL, `kubectl` one-liner reading the bootstrap token, CA fingerprint), plus `kubectl get hostconfig default` to watch agents become Ready.

Values (defaults in brackets): `image.repository/tag`, `replicas` [2], `crds.keep` [false], `hostConfig` [incl. `existing` false, `reserve` 4Gi, `defaultMargin` 2Gi], `pki.existingCASecret`, `scheduler.{enabled [true], image.tag [from cluster version], replicas [2], resources}`, `webhook.{failurePolicy [Fail]}`, `podDefaults.memoryRequest` [64Mi], `facade.{enabled [true], service.type [ClusterIP], ingress.{enabled [true], host, className, annotations, tls}, existingTokenSecret, tokens}`, `dashboard.{enabled [true], auth.{userHeader [X-Forwarded-User], groupsHeader [X-Forwarded-Groups], testerGroups [] }}`, `selftest.{namespace [hvmc-tests], images.{pause, consumer}}`, `networkPolicy.{enabled [true], ingressControllerNamespaceSelector}`, `metrics.serviceMonitor.enabled` [false], `resources`, `nodeSelector`, `tolerations`, `affinity`, `devFakeAgents` [false] (coordinator runs in-process fake agents; used by CI).

`helm lint`, `helm template` golden tests, `ct lint` and `ct install` (kind cluster, `devFakeAgents: true`: install, schedule a pod with the resource through the webhook and `hvmc-scheduler`, assert Granted, uninstall clean) in CI. Publishing the chart is **DEFERRED** (§12).

## 12. CI/CD (`.github/workflows`)

- `ci.yaml` on PR/push:
  - Linux: `golangci-lint`, `buf lint` + `buf breaking` against the default branch, `go test ./... -race` (ledger ≥ 95 % coverage gate), envtest for controllers (`setup-envtest`), `helm lint` + golden tests + `ct lint` + `ct install` on kind (§11), `ko build --push=false` (linux/amd64), `GOOS=windows go build` of the agent.
  - Windows (`windows-2025` runner): `go test ./internal/agent/...` including the pwsh-worker protocol tests against a mock Hyper-V module (PowerShell functions named `Get-VM`/`Set-VMMemory` with scripted behaviour: grow, refused shrink, VMMS down, hang), and SCM install/upgrade/uninstall round-trip.
  - Linux agent service (`ubuntu-latest` runner, real systemd): install/upgrade/uninstall round-trip, `Type=notify` readiness, watchdog restart of a deliberately hung agent.
- `release.yaml` on tag `v*` (set up for the first release): `ko build --platform=linux/amd64` → Docker Hub, agent archives (`linux_amd64.tar.gz`, `windows_amd64.zip`) + checksums, cosign keyless signing of the image and the archives, GitHub Release with GitHub's auto-generated notes.
- **DEFERRED**: Helm release workflow (`helm package --version ${TAG#v} --app-version ${TAG#v}`, `helm push` to `oci://ghcr.io/matfax/charts`, chart signing) and the changelog tool choice.
- Dependabot for Go modules and Actions; Actions pinned by SHA.

## 13. Milestones (each ends green in CI and tagged)

1. **v0.1.0 foundation**: repo, CRDs with validation, ledger with queue and property tests, proto definitions, host policy package, fake agents, `hvmc plan`, CI on Linux and Windows.
2. **v0.2.0 agents**: host and guest agents with self-install/upgrade/uninstall (Windows service, systemd), internal CA, enrollment and rotation, health mechanism, agent service entries, coordinator process with leader label and HostConfig status, chart base with enrollment exposure, `hvmc check`.
3. **v0.3.0 grants and scheduling**: lease store and MemoryLease controller, grant executor (grow, shrink, dispatcher), admission webhook, extender, `hvmc-scheduler` in the chart, kind e2e.
4. **v0.4.0 dashboard and active tests**: dashboard with scheduling and health monitors, trusted-proxy auth, `TestRun`/`TestSchedule`, the `agents`, `scheduling`, `requeue` and `probe-resize` tests, `hvmc test`, diagnostics export.
5. **v0.5.0 facade**: `/v1/leases`, token auth, TTL/heartbeat, Ingress paths, Go and PowerShell clients, `facade` test.
6. **v0.6.0 reconciler**: hysteresis decisions for Windows VMs, executed through the grant executor; DM limits; `reconciler` test.
7. **v1.0.0 release**: release pipeline, image on Docker Hub, agent archives on GitHub Releases, chart installable from the repo, docs (install, Hyper-V host setup, guest agent setup, dashboard and active tests, operations runbook, design), `config/samples/`, hardening and soak test.

## 14. Testing matrix

- Unit: ledger property tests (pool never negative; `Σ committed ≤ capacity − reserve`; FIFO order within a class; the head of the queue is never overtaken by a pool-drawing or same-VM request; rollback restores state exactly; no I/O while the ledger mutex is held — enforced by a test harness that fails if the fake agent is called under the lock), hysteresis (table-driven over time), quantization, effective pod request computation, offset-based verification.
- Agent: pwsh worker protocol (mock Hyper-V module on the Windows runner), local policy enforcement (out-of-range, unlisted VM, write to `fixed` VM), health check transitions, certificate rotation with rollback.
- envtest: webhook mutations (scheduler name, request normalization, untouched non-hvmc pods); MemoryLease lifecycle with fake agents; pod deletion → Released (not on deletionTimestamp); coordinator restart and leader failover → ledger rebuilt identically, including Reserved/Resizing recovery; agent Unreachable → ledger frozen, nothing revoked; EndpointSlice conditions follow health.
- Dashboard: handler tests for every view and action, SSE stream, trusted-header handling (missing user header rejected, test actions refused without a tester group), Content-Security-Policy headers; `TestRun`/`TestSchedule` controllers in envtest with fake agents, including cleanup on deletion and refusal while frozen.
- Real Hyper-V behaviour is verified in running installations by the active tests (§15.4) — not by scripts on contributors' machines. Their results are visible in the dashboard and as `TestRun` status; the diagnostics export (§15.4) feeds real error shapes into the Windows CI mock.

## 15. Dashboard and active testing

The coordinator serves a web dashboard for operators: what the ledger and the scheduling chain are doing, how healthy every component is, and **active tests** that exercise the real production path in the running installation, on demand or on a schedule. An installation proves itself instead of relying on one-off manual experiments.

### 15.1 Serving and access

- Served by the coordinator on `:8090` under `/ui/`, behind the leader label like the facade (§6) because only the leader holds the ledger; exposed through the chart's Ingress (path `/ui`).
- Server-rendered HTML (`html/template`) with one vendored htmx file and a stylesheet embedded via `go:embed`; no JavaScript build step. Live views update through server-sent events (`/ui/events`). Strict Content-Security-Policy (`default-src 'self'`, no inline script).
- **Authentication is delegated to an auth proxy** in front of the dashboard (an Ingress auth middleware, oauth2-proxy or similar). The coordinator trusts the identity headers `dashboard.auth.userHeader` and `dashboard.auth.groupsHeader` and rejects requests without a user. The dashboard port accepts traffic only from the ingress controller (NetworkPolicy), so the headers cannot be set by anything else in the cluster.
- **Authorization:** every authenticated user can view. Starting, cancelling and scheduling tests requires membership in one of `dashboard.auth.testerGroups`; when the list is empty (default), test controls are hidden and the API refuses them. Every action is recorded as a Kubernetes Event naming the user.
- The same actions are available without the dashboard: `TestRun`/`TestSchedule` objects created with kubectl (Kubernetes RBAC applies), or `hvmc test run`, which creates them.

### 15.2 Scheduling monitor

- **Host:** capacity, reserve, Σ committed, pool, host free memory, frozen state.
- **Per VM:** assigned, floor, headroom, leased, used, available, mode, policy bounds, agent state.
- **Queue** in order: request, kind, priority, position, bytes, candidate VMs, and the blocking cause (the same fixed cause strings as the extender's filter reasons, §7.3) with the numbers behind it.
- **Lease timeline:** phase transitions with timestamps and the durations of reserve → resize → verify → grant.
- **Scheduling activity:** extender filter/prioritize/bind call rates and latencies, webhook decisions, requeue nudges.
- **Rolling history** kept in memory on the leader (6 h at 10 s resolution, lost on failover): pool, queue length, grant latency, call rates. Long-term history is Prometheus' job through the metrics endpoint; the dashboard does not query Prometheus.

### 15.3 Health monitor

- **Per agent:** state (Ready/Degraded/Unreachable), last seen, version, certificate expiry, readiness checks, `PolicyInSync` with the diff of a pending proposal (§4.3).
- **Coordinator and chain:** leader, replicas, rebuild status, HostConfig conditions; reachability of `hvmc-scheduler`, extender and webhook.
- **History** of condition transitions from HostConfig status and Events.

### 15.4 Active tests

Tests live in `internal/selftest`; each is a named sequence of steps with measurements, findings and a verdict (`Passed`, `Failed`, `Aborted`).

| Test | Exercises | Measures |
|---|---|---|
| `agents` | every agent: reachability, certificate chain and expiry, policy digest, health | round-trip time per agent, findings |
| `scheduling` | a test pod requesting `hvmc.fax.fyi/ram` (default 256Mi) on an opted-in node: webhook → `hvmc-scheduler` → extender → grow and guest verification when needed → Running → delete → Released | latency of every hop, whether a resize happened |
| `requeue` | fills an opted-in VM's headroom with one test pod, queues a second, deletes the first | release → next filter call (target < 1 s, §7.3) and → Running |
| `probe-resize` | a `Probe` lease on a VM with `probe: true`: grow one step, verify in the guest, shrink back, then a shrink below what the guest can release | cmdlet durations, time to guest visibility, error classes, `MemoryStartup` drift and its repair (§3.5) |
| `facade` | an External lease through the facade with a test token | grant latency, heartbeat, release |
| `reconciler` | a load pod on an opted-in Windows node VM with a policy pushes free memory below the margin, then stops | time to grow, time to shrink after dwell, band respected |

Test pods use upstream images only — `registry.k8s.io/pause` and `registry.k8s.io/e2e-test-images/resource-consumer`, both multi-arch including Windows — configurable in the chart values.

Safety:
- Tests touch only what is opted in through HostConfig: `vms[].testing.enabled` (scheduling, requeue, reconciler) and `probe: true` (probe-resize). Every test request is capped at `vms[].testing.maxBytes` [1Gi].
- Test requests are queued at the lowest priority class, so they never get ahead of real requests.
- One active test per VM at a time. A test that has to wait for the pool waits like any request and is aborted after its timeout [10m].
- No test starts while the ledger is frozen or the target's agent is not Ready; the run is recorded as `Aborted` with the reason.
- Test pods run in the namespace `hvmc-tests`, are owned by their `TestRun` and have `activeDeadlineSeconds`; deleting a `TestRun` removes everything it created.

**Diagnostics export:** the host agent keeps a bounded, anonymised record of the raw cmdlet errors it has seen (error id, exception type and message, assigned/startup memory before and after; VM names replaced by placeholders) and returns it through `HostAgent.GetDiagnostics`. The dashboard downloads it as a JSON bundle in the fixture format of the Windows CI mock (§12), so real-world error shapes reach the tests without a manual script.

### 15.5 API objects

- `TestRun` (`hvmc.fax.fyi/v1alpha1`, cluster-scoped): `spec.test`, `spec.target` (`vm` and/or `node`), `spec.parameters` (e.g. `bytes`), `spec.timeout`; `status.phase` (`Pending|Running|Passed|Failed|Aborted`), steps with timestamps, measurements, findings, `startedBy`.
- `TestSchedule` (cluster-scoped): `spec.template` (a `TestRun` spec), `spec.interval` (e.g. `6h`, with jitter), `spec.historyLimit` [10]; creates `TestRun`s it owns and prunes old ones.
- HostConfig gains `vms[].testing.{enabled, maxBytes}` (§5).
- Only the leader executes runs; both objects carry owner references to HostConfig `default` so uninstall removes them (§11).

## 16. Non-goals (v1)

No percentage margins. No SSH or WinRM transport. No scheduling gates. No changes to the cluster's default scheduler or control plane. No custom scheduler build (upstream kube-scheduler + extender; a framework-plugin build is a later option using the same ledger). No multi-host (the agent API is per host, so multi-host is an additive change later). No DM target control (impossible). No runtime resizing of Linux VMs (§1). No automatic reboot-based resizing of Linux VMs (`hvmc vm reboot-when-idle` is a later candidate). Chart publishing and changelog tooling are **DEFERRED**.
