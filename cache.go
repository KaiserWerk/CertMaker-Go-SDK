package certmaker

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// Cache defines the interface for certificate and key storage.
type Cache interface {
	HasCertificate() bool
	HasPrivateKey() bool
	HasRootCertificate() bool

	SetCertificate(data []byte) error
	SetPrivateKey(data []byte) error
	SetRootCertificate(data []byte) error

	CertificatePath() (string, error)
	PrivateKeyPath() (string, error)
	RootCertificatePath() (string, error)

	CertificateBytes() ([]byte, error)
	PrivateKeyBytes() ([]byte, error)
	RootCertificateBytes() ([]byte, error)

	// TLSCertificate loads and returns the cached certifcate from the Cache as a tls.Certificate.
	TLSCertificate() (*tls.Certificate, error)
	// RootCertificate loads and returns the root certificate from the Cache as a parsed *x509.Certificate.
	RootCertificate() (*x509.Certificate, error)

	// Valid returns nil if the certificate in *MemoryCache is found to be valid.
	// The following checks are performed:
	//   - is the certificate present
	//   - is the certificate expired
	//
	// If strictmode is enabled, *Client additionally sends an OCSP request to check revocation status.
	//
	// If any of the checks fail, an error is returned.
	Valid(client *Client, minValidity time.Duration) error
	// Clear removes the Cache's certificate, private key, and, if parameter removeRootCert is true, the root certificate as well.
	// This is a destructive operation and cannot be undone.
	Clear(removeRootCert bool) error
}
