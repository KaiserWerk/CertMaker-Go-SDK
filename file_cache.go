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
	"path/filepath"
	"time"

	"golang.org/x/crypto/ocsp"
)

// FileCache represents a local directory and file paths for certificates and private keys.
type FileCache struct {
	CacheDir                string
	PrivateKeyFilename      string
	CertificateFilename     string
	RootCertificateFilename string
}

// Ensure FileCache implements the Cache interface.
var _ Cache = (*FileCache)(nil)

// NewFileCache returns a *FileCache with default values:
//   - CacheDir = ".certs"
//   - CertificateFilename = "cert.pem"
//   - PrivateKeyFilename = "key.pem"
//   - RootCertificateFilename = "root-cert.pem"
//
// If dir is empty, the current working directory is used.
//
// The cache directory is created relative to the supplied directory.
// The private key file contains the PEM-encoded private key.
// The certificate file contains the PEM-encoded certificate (leaf).
// The certificate file may contain a full chain, starting with the leaf certificate.
//
// Values may be modified after creation, but they should not be modified after first use.
func NewFileCache(dir string) (*FileCache, error) {
	if dir == "" {
		dir = "."
	}
	cache := FileCache{}
	baseDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	cache.CacheDir = filepath.Join(baseDir, ".certs")
	err = os.MkdirAll(cache.CacheDir, 0700)
	if err != nil {
		return nil, err
	}

	cache.CertificateFilename = "cert.pem"
	cache.PrivateKeyFilename = "key.pem"
	cache.RootCertificateFilename = "root-cert.pem"

	return &cache, nil
}

func (c *FileCache) HasCertificate() bool {
	p, _ := c.CertificatePath()
	return fileExists(p)
}
func (c *FileCache) HasPrivateKey() bool {
	p, _ := c.PrivateKeyPath()
	return fileExists(p)
}
func (c *FileCache) HasRootCertificate() bool {
	p, _ := c.RootCertificatePath()
	return fileExists(p)
}

func (c *FileCache) SetCertificate(data []byte) error {
	p, _ := c.CertificatePath()
	err := os.WriteFile(p, data, 0o600)
	if err != nil {
		return fmt.Errorf("SetCertificate: could not write certificate file: %w", err)
	}
	return nil
}
func (c *FileCache) SetPrivateKey(data []byte) error {
	p, _ := c.PrivateKeyPath()
	err := os.WriteFile(p, data, 0o600)
	if err != nil {
		return fmt.Errorf("SetPrivateKey: could not write private key file: %w", err)
	}
	return nil
}
func (c *FileCache) SetRootCertificate(data []byte) error {
	p, _ := c.RootCertificatePath()
	err := os.WriteFile(p, data, 0o755)
	if err != nil {
		return fmt.Errorf("SetRootCertificate: could not write root certificate file: %w", err)
	}
	return nil
}

// CertificatePath returns the absolute path to the Cache's certificate file.
func (c *FileCache) CertificatePath() (string, error) {
	return filepath.Join(c.CacheDir, c.CertificateFilename), nil
}

// PrivateKeyPath returns the absolute path to the Cache's private key file.
func (c *FileCache) PrivateKeyPath() (string, error) {
	return filepath.Join(c.CacheDir, c.PrivateKeyFilename), nil
}

// RootCertificatePath returns the absolute path to the Cache's root certificate file.
func (c *FileCache) RootCertificatePath() (string, error) {
	return filepath.Join(c.CacheDir, c.RootCertificateFilename), nil
}

func (c *FileCache) CertificateBytes() ([]byte, error) {
	if !c.HasCertificate() {
		return nil, fmt.Errorf("certificate file does not exist")
	}
	p, _ := c.CertificatePath()
	cont, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("could not read certificate file: %w", err)
	}
	return cont, nil
}

func (c *FileCache) PrivateKeyBytes() ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, fmt.Errorf("private key file does not exist")
	}
	p, _ := c.PrivateKeyPath()
	cont, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file: %w", err)
	}
	return cont, nil
}
func (c *FileCache) RootCertificateBytes() ([]byte, error) {
	if !c.HasRootCertificate() {
		return nil, fmt.Errorf("root certificate file does not exist")
	}
	p, _ := c.RootCertificatePath()
	cont, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("could not read root certificate file: %w", err)
	}
	return cont, nil
}

func (c *FileCache) TLSCertificate() (*tls.Certificate, error) {
	pkPath, _ := c.PrivateKeyPath()
	if !fileExists(pkPath) {
		return nil, fmt.Errorf("private key file missing")
	}

	certPath, _ := c.CertificatePath()
	if !fileExists(certPath) {
		return nil, fmt.Errorf("certificate file missing")
	}

	tlsCert, err := tls.LoadX509KeyPair(certPath, pkPath)

	return &tlsCert, err
}

func (c *FileCache) RootCertificate() (*x509.Certificate, error) {
	if !c.HasRootCertificate() {
		return nil, fmt.Errorf("root certificate file does not exist")
	}

	p, _ := c.RootCertificatePath()
	cont, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(cont)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Valid returns nil if the certificate in *FileCache is found to be valid.
// The following checks are performed:
//   - does the file exist
//   - is the certificate expired
//
// If strictmode is enabled, *Client additionally checks whether the certificate is revoked via OCSP request.
//
// If any of the checks fail, an error is returned.
func (c *FileCache) Valid(client *Client, minValidity time.Duration) error {
	certPath, _ := c.CertificatePath()
	if !fileExists(certPath) {
		return fmt.Errorf("certificate file missing")
	}

	cont, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("could not read certificate file: %w", err)
	}

	block, _ := pem.Decode(cont)
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
		if !c.HasRootCertificate() {
			err = client.DownloadRootCertificate(c)
			if err != nil {
				return fmt.Errorf("could not download root cert: %w", err)
			}
		}

		rootCert, err := c.RootCertificate()
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

func (c *FileCache) Clear(removeRootCert bool) error {
	// remove the certificate file
	if c.HasCertificate() {
		p, _ := c.CertificatePath()
		err := os.Remove(p)
		if err != nil {
			return fmt.Errorf("could not remove certificate file: %w", err)
		}
	}
	// remove the private key file
	if c.HasPrivateKey() {
		p, _ := c.PrivateKeyPath()
		err := os.Remove(p)
		if err != nil {
			return fmt.Errorf("could not remove private key file: %w", err)
		}
	}

	// remove the root certificate file if it exists
	if c.HasRootCertificate() && removeRootCert {
		p, _ := c.RootCertificatePath()
		err := os.Remove(p)
		if err != nil {
			return fmt.Errorf("could not remove root certificate file: %w", err)
		}
	}

	return nil
}
