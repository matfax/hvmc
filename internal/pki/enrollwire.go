package pki

// Enrollment wire format (DESIGN §4.6)
//
// An agent enrolls once with one HTTPS request to the coordinator's
// enrollment endpoint (`/v1/enroll` on :8080, exposed over TLS by the
// chart):
//
//	POST /v1/enroll
//	Authorization: Bearer <bootstrap token>
//	Content-Type: application/json
//
//	{"agent": "host", "role": "host", "csr": "-----BEGIN CERTIFICATE REQUEST-----\n..."}
//
// The CSR is signed with a fresh ECDSA P-256 key that never leaves the
// agent. Only its public key is used ([CA.SignCSR]): the certificate's
// subject and SANs come from HostConfig. A successful response is
//
//	200 OK
//	Content-Type: application/json
//
//	{
//	  "certificate": "-----BEGIN CERTIFICATE-----\n<leaf>...<intermediates>",
//	  "caCertificate": "-----BEGIN CERTIFICATE-----\n...",
//	  "settings": {"port": 9443, "healthPort": 9090, "allowedClients": ["hvmc-coordinator"]},
//	  "policy": "vms:\n- ..."
//	}
//
// Every other response carries [EnrollErrorResponse] and one of these
// status codes:
//
//   - 400 Bad Request: malformed body, unknown role, CSR that does not
//     parse or is not signed by an ECDSA P-256 key.
//   - 401 Unauthorized: missing, wrong, expired or already used token.
//   - 403 Forbidden: the token is valid but the agent may not have this
//     role or the certificate it would need.
//   - 404 Not Found: no agent of that name is declared in HostConfig.
//
// The agent trusts nothing in a response before the CA certificate's
// SHA-256 fingerprint ([Fingerprint]) equals the pinned `--ca-sha256`;
// it then requires the leaf to chain to that CA as a serving certificate
// and to carry its own public key.

// EnrollPath is the path of the enrollment endpoint.
const EnrollPath = "/v1/enroll"

// Agent roles in an enrollment request.
const (
	EnrollRoleHost  = "host"
	EnrollRoleGuest = "guest"
)

// EnrollRequest is the JSON body of an enrollment request. The bootstrap
// token travels in the Authorization header, not in the body.
type EnrollRequest struct {
	// Agent is the agent's name: spec.agents[].name for the host agent,
	// the VM name for a guest agent (a DNS-1123 label).
	Agent string `json:"agent"`
	// Role is EnrollRoleHost or EnrollRoleGuest; it must match the agent's
	// declaration in HostConfig.
	Role string `json:"role"`
	// CSR is the PEM-encoded PKCS #10 certificate signing request.
	CSR string `json:"csr"`
}

// EnrollResponse is the JSON body of a successful enrollment.
type EnrollResponse struct {
	// Certificate is the agent's serving certificate in PEM, leaf first,
	// followed by any intermediates.
	Certificate string `json:"certificate"`
	// CACertificate is the hvmc CA certificate in PEM.
	CACertificate string `json:"caCertificate"`
	// Settings are the agent's local settings derived from HostConfig.
	Settings AgentSettings `json:"settings"`
	// Policy is the host role's proposed write policy in the canonical
	// form of internal/policy (Policy.Canonical); empty for guests.
	Policy string `json:"policy,omitempty"`
}

// AgentSettings are the parts of the agent's local configuration
// (agent.yaml) that come from HostConfig.
type AgentSettings struct {
	// Port is the agent's gRPC port (spec.agents[].port or
	// spec.vms[].guestAgent.port). 0 means the default, 9443.
	Port int32 `json:"port,omitempty"`
	// HealthPort is the plain-HTTP health and metrics port. 0 means the
	// default, 9090.
	HealthPort int32 `json:"healthPort,omitempty"`
	// AllowedClients are the client certificate CNs the agent accepts.
	// Empty means [CoordinatorCommonName] only.
	AllowedClients []string `json:"allowedClients,omitempty"`
}

// EnrollErrorResponse is the JSON body of a refused enrollment.
type EnrollErrorResponse struct {
	// Error is a short human-readable reason. It never contains the token.
	Error string `json:"error"`
}
