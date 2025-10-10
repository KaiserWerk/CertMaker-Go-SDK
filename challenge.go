package certmaker

import (
	"context"
)

type Challenge interface {
	// Type returns the challenge type, e.g., "http-01" or "dns-01".
	Type() string
	// Setup prepares the challenge for solving, e.g., by starting a server returning the token
	// or creating DNS records.
	Setup(context.Context) error
	// Solve notifies the CertMaker instance that the challenge is ready to be validated.
	Solve(context.Context) (*CertificateResponse, error)
}
