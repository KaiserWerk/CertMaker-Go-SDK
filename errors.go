package certmaker

import "errors"

var (
	ErrStillValid           = errors.New("certmaker-sdk: the certificate is still valid")
	ErrMissingSetup         = errors.New("certmaker-sdk: missing setup")
	ErrNoPreferredChallenge = errors.New("certmaker-sdk: no preferred challenge selected")
	ErrNoChallengeIssued    = errors.New("certmaker-sdk: server did not offer any challenge to solve")
	ErrNoDomainsProvided    = errors.New("certmaker-sdk: no domains specified in SimpleRequest, cannot solve challenge")
)
