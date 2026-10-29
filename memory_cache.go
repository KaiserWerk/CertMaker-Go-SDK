package certmaker

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

type MemoryCache struct {
	certificate      []byte
	privateKey       []byte
	rootCertificate  []byte
	tlsCertificate   *tls.Certificate
	rootCertInstance *x509.Certificate
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{}
}

// Ensure MemoryCache implements the Cache interface.
var _ Cache = (*MemoryCache)(nil)

// SetDir is a no-op for MemoryCache as it does not use a directory.
func (m *MemoryCache) SetDir(dir string) error {
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

// CertificatePath returns an empty string as MemoryCache does not have a file path for the certificate.
func (m *MemoryCache) CertificatePath() string {
	return ""
}

// PrivateKeyPath returns an empty string as MemoryCache does not have a file path for the private key.
func (m *MemoryCache) PrivateKeyPath() string {
	return ""
}

// RootCertificatePath returns an empty string as MemoryCache does not have a file path for the root certificate.
func (m *MemoryCache) RootCertificatePath() string {
	return ""
}

func (m *MemoryCache) CertificateBytes() ([]byte, error) {
	if len(m.certificate) == 0 {
		return nil, ErrNoCertificate
	}
	return m.certificate, nil
}

func (m *MemoryCache) PrivateKeyBytes() ([]byte, error) {
	if len(m.privateKey) == 0 {
		return nil, ErrNoPrivateKey
	}
	return m.privateKey, nil
}

func (m *MemoryCache) RootCertificateBytes() ([]byte, error) {
	if len(m.rootCertificate) == 0 {
		return nil, ErrNoRootCertificate
	}
	return m.rootCertificate, nil
}

func (m *MemoryCache) TLSCertificate() (*tls.Certificate, error) {
	if !m.HasCertificate() {
		return nil, ErrNoCertificate
	}
	if !m.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}
	cert, err := tls.X509KeyPair(m.certificate, m.privateKey)

	return &cert, err
}

func (m *MemoryCache) RootCertificate() (*x509.Certificate, error) {
	if !m.HasRootCertificate() {
		return nil, ErrNoRootCertificate
	}

	block, _ := pem.Decode(m.rootCertificate)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// CopyPrivateKeyFromFile retrieves a raw copy of a private key from the supplied file.
func (m *MemoryCache) CopyPrivateKeyFromFile(src string) error {
	cont, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("CopyPrivateKeyFromFile: could not read source private key file: %w", err)
	}
	m.privateKey = cont
	return nil
}

// Valid returns nil if the certificate in *MemoryCache is found to be valid.
// The following checks are performed:
//   - is the certificate expired
//
// If strictmode is enabled, *Client additionally sends an OCSP request to check revocation status.
//
// If any of the checks fail, an error is returned.
func (m *MemoryCache) Valid(client *Client, minValidity time.Duration) error {
	if !m.HasCertificate() {
		return ErrNoCertificate
	}

	block, _ := pem.Decode(m.certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("could not parse certificate: %w", err)
	}

	diff := time.Until(cert.NotAfter)
	if diff < minValidity {
		return fmt.Errorf("certificate is about to expire")
	}

	if client.strictMode {
		fmt.Println("strict mode enabled; checking revocation status...")
		if !m.HasRootCertificate() {
			err = client.DownloadRootCertificate(m)
			if err != nil {
				return fmt.Errorf("could not download root cert: %w", err)
			}
		}

		rootCert, err := m.RootCertificate()
		if err != nil {
			return fmt.Errorf("could not get root certificate: %w", err)
		}
		ocspReq, err := ocsp.CreateRequest(cert, rootCert, &ocsp.RequestOptions{
			Hash: crypto.SHA512,
		})
		if err != nil {
			return fmt.Errorf("could not create OCSP request: %w", err)
		}
		req, err := http.NewRequest(http.MethodPost, client.baseUrl+ocspStatusPath, bytes.NewBuffer(ocspReq))
		if err != nil {
			return fmt.Errorf("could not create HTTP request: %w", err)
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")
		resp, err := client.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("could not send HTTP request: %w", err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		_, err = io.Copy(&b, resp.Body)
		if err != nil {
			return fmt.Errorf("could not read HTTP response body: %w", err)
		}
		ocspResp, err := ocsp.ParseResponse(b.Bytes(), rootCert)
		if err != nil {
			return fmt.Errorf("could not parse OCSP response: %w", err)
		}
		if ocspResp.Status != ocsp.Good && ocspResp.Status != ocsp.Unknown {
			return fmt.Errorf("status is neither good nor unknown: %d", ocspResp.Status)
		}
	}

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
