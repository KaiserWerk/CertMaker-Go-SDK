package certmaker

import "errors"

var ErrStillValid = errors.New("the certificate is still valid")
var ErrMissingSetup = errors.New("missing setup: call SetupWithSimpleRequest or SetupWithCSR before using GetCertificateFunc")
