package certmaker

import (
	"context"
	"net/http"
)

type ChallengeSolver interface {
	// SolveChallenges is called when the CertMaker instance requires challenges to be solved.
	// The implementation should solve the challenges and call c.SolveChallenge for each challenge.
	SolveChallenges(c *Client, challenges []Challenge) error
}

type Challenge interface {
	Type() string
	Setup(context.Context) error
	Solve(*http.Client) error
}
