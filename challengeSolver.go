package certmaker

import (
	"context"
	"net/http"
)

type ChallengeSolver interface {
	CanSolve(challengeType string) bool
	// Setup prepares the challenge for solving, e.g., by starting a server returning the token
	// or creating DNS records.
	Setup(ctx context.Context, token string, domains []string) error
	// Solve notifies the CertMaker instance that the challenge is ready to be validated. It can also be
	// used for cleanup after the challenge is solved.
	Solve(ctx context.Context, instanceURL, challengeID string, setHeader func(*http.Request)) (*CertificateResponse, error)
}
