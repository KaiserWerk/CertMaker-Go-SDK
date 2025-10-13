package certmaker

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

type MemoryCache struct {
	dir              string
	certificate      []byte
	privateKey       []byte
	rootCertificate  []byte
	tlsCertificate   *tls.Certificate
	rootCertInstance *x509.Certificate
}

func (m *MemoryCache) SetDir(dir string) error {
	m.dir = dir
	return nil
}

func (m *MemoryCache) HasCertificate() bool {
	return len(m.certificate) > 0
}

func (m *MemoryCache) HasRootCertificate() bool {
	return len(m.rootCertificate) > 0
}

func (m *MemoryCache) HasPrivateKey() bool {
	return len(m.privateKey) > 0
}

func (m *MemoryCache) CertificatePath() string {
	return ""
}

func (m *MemoryCache) PrivateKeyPath() string {
	return ""
}

func (m *MemoryCache) RootCertificatePath() string {
	return ""
}

func (m *MemoryCache) CertificateBytes() ([]byte, error) {
	if len(m.certificate) == 0 {
		return nil, errors.New("certificate not found in memory cache")
	}
	return m.certificate, nil
}

func (m *MemoryCache) PrivateKeyBytes() ([]byte, error) {
	if len(m.privateKey) == 0 {
		return nil, errors.New("private key not found in memory cache")
	}
	return m.privateKey, nil
}

func (m *MemoryCache) RootCertificateBytes() ([]byte, error) {
	if len(m.rootCertificate) == 0 {
		return nil, errors.New("root certificate not found in memory cache")
	}
	return m.rootCertificate, nil
}

func (m *MemoryCache) TLSCertificate() (*tls.Certificate, error) {
	if m.tlsCertificate == nil {
		return nil, errors.New("TLS certificate not found in memory cache")
	}
	return m.tlsCertificate, nil
}

func (m *MemoryCache) RootCertificate() (*x509.Certificate, error) {
	if m.rootCertInstance == nil {
		return nil, errors.New("root certificate instance not found in memory cache")
	}
	return m.rootCertInstance, nil
}

func (m *MemoryCache) CopyPrivateKeyFromFile(src string) error {
	return errors.New("CopyPrivateKeyFromFile is not supported in memory cache")
}

func (m *MemoryCache) Valid(client *Client, minValidity time.Duration) error {
	// Implement validation logic if needed
	return nil
}

func (m *MemoryCache) Clear(removeRootCert bool) error {
	m.certificate = nil
	m.privateKey = nil
	m.tlsCertificate = nil
	if removeRootCert {
		m.rootCertificate = nil
		m.rootCertInstance = nil
	}
	return nil
}
