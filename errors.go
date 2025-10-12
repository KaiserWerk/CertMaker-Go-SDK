package certmaker

import "errors"

var (
	ErrUnauthorized      = errors.New("certmaker-sdk: HTTP request unauthorized - invalid API key or token")
	ErrBadRequest        = errors.New("certmaker-sdk: HTTP request bad - malformed request or invalid data")
	ErrStillValid        = errors.New("certmaker-sdk: the certificate is still valid")
	ErrMissingSetup      = errors.New("certmaker-sdk: missing setup")
	ErrNoChallengeIssued = errors.New("certmaker-sdk: server did not offer any challenge to solve")
	ErrNoDomainsProvided = errors.New("certmaker-sdk: no domains specified in SimpleRequest, cannot solve challenge")
)
