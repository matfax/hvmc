package agentclient

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/matfax/hvmc/api/v1alpha1"
	"github.com/matfax/hvmc/internal/pki"
)

// Event reasons of certificate rotation.
const (
	ReasonCertificateRotated        = "CertificateRotated"
	ReasonCertificateRotationFailed = "CertificateRotationFailed"
)

// RotationDue reports whether cert has reached its renewal point (two thirds
// of its lifetime, DESIGN §4.6) at now.
func RotationDue(cert *x509.Certificate, now time.Time) bool {
	return cert != nil && !now.Before(pki.RenewAt(cert))
}

// Rotator renews agent serving certificates over the existing mTLS channel
// (DESIGN §4.6): RotateCertificate → sign the CSR → InstallCertificate.
type Rotator struct {
	// CA signs the agents' CSRs.
	CA *pki.CA
	// Reader reads Nodes for the SANs of node-mapped guest agents; nil is
	// enough when no VM has a node.
	Reader client.Reader
	// Events receives CertificateRotated / CertificateRotationFailed; nil
	// discards them.
	Events EventEmitter
}

// Rotate renews the named agent's certificate through c. The CSR only
// contributes its key: subject and SANs come from HostConfig
// (pki.AgentIdentity). On any failure the agent keeps its current pair, a
// Warning event is emitted and the error returned; the caller retries later.
// It returns the installed leaf.
func (r *Rotator) Rotate(ctx context.Context, hc *v1alpha1.HostConfig, agent string, c Certs) (*x509.Certificate, error) {
	cert, err := r.rotate(ctx, hc, agent, c)
	if err != nil {
		r.emit(Event{
			Agent: agent, Type: corev1.EventTypeWarning, Reason: ReasonCertificateRotationFailed,
			Action: "RotateCertificate", Message: err.Error(),
		})
		return nil, err
	}
	r.emit(Event{
		Agent: agent, Type: corev1.EventTypeNormal, Reason: ReasonCertificateRotated, Action: "RotateCertificate",
		Message: fmt.Sprintf("installed certificate %s valid until %s", cert.SerialNumber.Text(16), cert.NotAfter.UTC().Format(time.RFC3339)),
	})
	return cert, nil
}

func (r *Rotator) rotate(ctx context.Context, hc *v1alpha1.HostConfig, agent string, c Certs) (*x509.Certificate, error) {
	if r.CA == nil {
		return nil, errors.New("rotate certificate: no CA")
	}
	if hc == nil {
		return nil, errors.New("rotate certificate: no HostConfig")
	}
	reader := r.Reader
	if reader == nil {
		reader = noReader{}
	}
	id, err := pki.AgentIdentity(ctx, reader, hc, agent)
	if err != nil {
		return nil, fmt.Errorf("rotate certificate: %w", err)
	}
	csr, err := c.RotateCertificate(ctx)
	if err != nil {
		return nil, err
	}
	cert, err := r.CA.SignCSR(csr, id)
	if err != nil {
		return nil, fmt.Errorf("rotate certificate: sign: %w", err)
	}
	if err := c.InstallCertificate(ctx, [][]byte{cert.Raw, r.CA.Certificate().Raw}); err != nil {
		return nil, err
	}
	return cert, nil
}

func (r *Rotator) emit(e Event) {
	if r.Events != nil {
		r.Events.Emit(e)
	}
}

// noReader stands in for a missing client.Reader.
type noReader struct{}

var errNoReader = errors.New("no Kubernetes reader configured to read Nodes")

func (noReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errNoReader
}

func (noReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errNoReader
}
