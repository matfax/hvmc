// envtest runs in the Linux CI job only (DESIGN §12); controller-runtime's
// envtest process package does not build for Windows.

//go:build !windows

package agentclient_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/matfax/hvmc/api/v1alpha1"
	"github.com/matfax/hvmc/internal/agentclient"
	"github.com/matfax/hvmc/internal/fake"
	"github.com/matfax/hvmc/internal/ledger"
)

// k8sClient and restConfig talk to the envtest API server started by
// TestMain; nil when KUBEBUILDER_ASSETS is not set.
var (
	k8sClient  client.Client
	restConfig *rest.Config
	k8sScheme  = k8sruntime.NewScheme()
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		return m.Run() // envtest tests skip or fail in requireEnvtest
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "start envtest: %v\n", err)
		return 1
	}
	defer func() {
		if err := env.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "stop envtest: %v\n", err)
		}
	}()
	if err := clientgoscheme.AddToScheme(k8sScheme); err != nil {
		fmt.Fprintf(os.Stderr, "scheme: %v\n", err)
		return 1
	}
	if err := v1alpha1.AddToScheme(k8sScheme); err != nil {
		fmt.Fprintf(os.Stderr, "scheme: %v\n", err)
		return 1
	}
	k8sClient, err = client.New(cfg, client.Options{Scheme: k8sScheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		return 1
	}
	restConfig = cfg
	return m.Run()
}

// requireEnvtest skips the test when no envtest binaries are available,
// except in CI (CI=true), where envtest is mandatory; `make test` provides
// the binaries.
func requireEnvtest(t *testing.T) {
	t.Helper()
	if k8sClient != nil {
		return
	}
	if os.Getenv("CI") == "true" {
		t.Fatal("envtest binaries missing (KUBEBUILDER_ASSETS unset) in CI")
	}
	t.Skip("KUBEBUILDER_ASSETS unset; run `make test`")
}

// teeSink sends events to several sinks.
type teeSink []agentclient.EventEmitter

func (s teeSink) Emit(e agentclient.Event) {
	for _, x := range s {
		x.Emit(e)
	}
}

// TestEnvtestAgents runs the acceptance scenarios against an API server: a
// guest agent addressed through its Node's InternalIP and verified against
// the node name, Kubernetes events on the HostConfig for every transition,
// rotation with SANs read from the Node, the policy proposal, and ledger
// gating when agents go down.
func TestEnvtestAgents(t *testing.T) {
	requireEnvtest(t)
	ctx := t.Context()

	createNode(t, "node-1", "127.0.0.1")

	e := newEnv(t,
		func(c *envConfig) { c.reader = k8sClient; c.guestNode = "node-1" },
		withScenario(func(sc *fake.Scenario) { sc.Guests[0].Certificate = &fake.CertSpec{FailInstall: 1} }))
	hc := e.hc.DeepCopy()
	must(t, k8sClient.Create(ctx, hc))
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), hc) }) // t.Context() is done in Cleanup

	sink := teeSink{e.events, apiEventSink(t, hc)}
	rot := &agentclient.Rotator{CA: e.ca, Reader: k8sClient, Events: sink}
	tr := e.tracker(func(o *agentclient.TrackerOptions) { o.Events = sink })

	tr.Poll(ctx)
	e.wantState(tr, "host", ledger.AgentReady)
	e.wantState(tr, "vm-a", ledger.AgentReady) // dialled at the Node's InternalIP, verified as node-1
	if off, ok := tr.Offset("vm-a"); !ok || off != 256*mib {
		t.Errorf("offset(vm-a) = %d, %v", off, ok)
	}
	if n := e.sim.CallCount("host", "ProposePolicy"); n != 1 {
		t.Errorf("ProposePolicy called %d times", n)
	}

	// Rotation: the failing install keeps the old pair, the retry installs a
	// certificate whose SANs come from HostConfig and the Node.
	_, err := rot.Rotate(ctx, e.hc, "vm-a", e.certs("vm-a"))
	wantErr(t, err, agentclient.ErrInternal)
	cert, err := rot.Rotate(ctx, e.hc, "vm-a", e.certs("vm-a"))
	must(t, err)
	if !slices.Equal(cert.DNSNames, []string{"node-1"}) || len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("rotated certificate names %v %v", cert.DNSNames, cert.IPAddresses)
	}
	served, err := e.pool.Probe(ctx, "vm-a")
	must(t, err)
	if served.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("agent serves serial %v, want %v", served.SerialNumber, cert.SerialNumber)
	}

	e.grant("ext-a")
	e.stop("host")
	for range 3 {
		tr.Poll(ctx)
	}
	e.wantState(tr, "host", ledger.AgentUnreachable)
	if !e.led.Snapshot().Frozen {
		t.Error("ledger not frozen")
	}
	e.wantGranted()

	e.stop("vm-a")
	for range 3 {
		tr.Poll(ctx)
	}
	if vm := e.vmA(); vm.State != ledger.VMUnknown {
		t.Errorf("vm-a state = %s", vm.State)
	}
	e.wantGranted()

	wantAPIEvents(t,
		agentclient.ReasonAgentReady, agentclient.ReasonAgentUnreachable, agentclient.ReasonPolicyProposed,
		agentclient.ReasonPolicyOutOfSync, agentclient.ReasonCertificateRotated, agentclient.ReasonCertificateRotationFailed)
}

// createNode creates a Node reporting ip as its InternalIP.
func createNode(t *testing.T, name, ip string) {
	t.Helper()
	ctx := t.Context()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	must(t, k8sClient.Create(ctx, node))
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), node) })
	node.Status.Addresses = []corev1.NodeAddress{
		{Type: corev1.NodeHostName, Address: name},
		{Type: corev1.NodeInternalIP, Address: ip},
	}
	must(t, k8sClient.Status().Update(ctx, node))
}

// apiEventSink records events through an events.k8s.io broadcaster to the
// API server, regarding obj, as the coordinator does.
func apiEventSink(t *testing.T, obj k8sruntime.Object) agentclient.EventEmitter {
	t.Helper()
	cs, err := kubernetes.NewForConfig(restConfig)
	must(t, err)
	b := events.NewBroadcaster(&events.EventSinkImpl{Interface: cs.EventsV1()})
	b.StartRecordingToSink(t.Context().Done())
	t.Cleanup(b.Shutdown)
	return agentclient.NewRecorderEmitter(b.NewRecorder(k8sScheme, "hvmc-coordinator"), obj)
}

// wantAPIEvents waits until the API server has an event regarding the
// HostConfig for every reason.
func wantAPIEvents(t *testing.T, reasons ...string) {
	t.Helper()
	eventually(t, "the events reach the API server", func() bool {
		var list eventsv1.EventList
		if err := k8sClient.List(t.Context(), &list, client.InNamespace(metav1.NamespaceDefault)); err != nil {
			return false
		}
		seen := map[string]bool{}
		for _, ev := range list.Items {
			if ev.Regarding.Kind == "HostConfig" && ev.Regarding.Name == v1alpha1.HostConfigName && ev.ReportingController == "hvmc-coordinator" {
				seen[ev.Reason] = true
			}
		}
		return !slices.ContainsFunc(reasons, func(r string) bool { return !seen[r] })
	})
}
