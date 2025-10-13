package certmaker

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// Cache defines the interface for certificate and key storage.
type Cache interface {
	SetDir(dir string) error

	HasCertificate() bool
	HasRootCertificate() bool
	HasPrivateKey() bool

	CertificatePath() string
	PrivateKeyPath() string
	RootCertificatePath() string

	CertificateBytes() ([]byte, error)
	PrivateKeyBytes() ([]byte, error)
	RootCertificateBytes() ([]byte, error)

	TLSCertificate() (*tls.Certificate, error)
	RootCertificate() (*x509.Certificate, error)

	CopyPrivateKeyFromFile(src string) error

	Valid(client *Client, minValidity time.Duration) error
	Clear(removeRootCert bool) error
}

// Ensure FileCache implements the Cache interface.
var _ Cache = (*FileCache)(nil)
