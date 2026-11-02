package agentclient

import (
	"context"

	"google.golang.org/grpc"

	agentv1 "github.com/matfax/hvmc/internal/agentapi/hvmc/agent/v1"
)

// Certs is the certificate renewal API every agent serves (DESIGN §4.6).
// Errors are *RPCError (errors.go).
type Certs interface {
	// RotateCertificate makes the agent create a new pending key and
	// returns a CSR (DER) for it.
	RotateCertificate(ctx context.Context) (csrDER []byte, err error)
	// InstallCertificate installs the chain (leaf first, DER) for the
	// pending key. On failure the agent keeps its current pair.
	InstallCertificate(ctx context.Context, certChainDER [][]byte) error
}

// certsClient implements Certs over gRPC.
type certsClient struct {
	agent string
	c     agentv1.CertificateServiceClient
}

func newCertsClient(agent string, cc grpc.ClientConnInterface) *certsClient {
	return &certsClient{agent: agent, c: agentv1.NewCertificateServiceClient(cc)}
}

// RotateCertificate implements Certs.
func (c *certsClient) RotateCertificate(ctx context.Context) ([]byte, error) {
	resp, err := c.c.RotateCertificate(ctx, &agentv1.RotateCertificateRequest{})
	if err != nil {
		return nil, call{agent: c.agent, method: "RotateCertificate"}.wrap(err)
	}
	return resp.GetCsrDer(), nil
}

// InstallCertificate implements Certs.
func (c *certsClient) InstallCertificate(ctx context.Context, certChainDER [][]byte) error {
	_, err := c.c.InstallCertificate(ctx, &agentv1.InstallCertificateRequest{CertificateChainDer: certChainDER})
	return call{agent: c.agent, method: "InstallCertificate"}.wrap(err)
}
