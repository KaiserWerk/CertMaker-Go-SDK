package certmaker

import "errors"

var (
	ErrStillValid   = errors.New("certmaker-sdk: the certificate is still valid")
	ErrMissingSetup = errors.New("certmaker-sdk: missing setup")
)
