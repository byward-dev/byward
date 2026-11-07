package entra

// The app's credential kinds (ADR-0012 §5): byward takes exactly one. init entra creates a secret
// or a certificate; a federated token comes from outside (GitHub Actions, AKS workload identity).
const (
	CredentialSecret      = "secret"
	CredentialFederated   = "federated"
	CredentialCertificate = "certificate"
)
