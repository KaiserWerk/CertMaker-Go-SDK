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

// NewCache returns a *FileCache with default values:
//   - CacheDir = ".certs"
//   - CertificateFilename = "cert.pem"
//   - PrivateKeyFilename = "key.pem"
//   - RootCertificateFilename = "root-cert.pem"
//
// The cache directory is created relative to the current working directory.
// The private key file contains the PEM-encoded private key.
// The certificate file contains the PEM-encoded certificate (leaf).
// The certificate file may contain a full chain, starting with the leaf certificate.
//
// Values may be modified after creation, but they should not be modified after first use.
func NewCache() (*FileCache, error) {
	cache := FileCache{}
	baseDir, err := filepath.Abs(".")
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

// SetDir sets the directory where the cache files are stored.
// The directory is created if it does not exist.
func (c *FileCache) SetDir(dir string) error {
	baseDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	err = os.MkdirAll(baseDir, 0700)
	if err != nil {
		return err
	}
	c.CacheDir = baseDir
	return nil
}

// CertificatePath returns the absolute path to the Cache's certificate file.
func (c *FileCache) CertificatePath() string {
	return filepath.Join(c.CacheDir, c.CertificateFilename)
}

// PrivateKeyPath returns the absolute path to the Cache's private key file.
func (c *FileCache) PrivateKeyPath() string {
	return filepath.Join(c.CacheDir, c.PrivateKeyFilename)
}

// RootCertificatePath returns the absolute path to the Cache's root certificate file.
func (c *FileCache) RootCertificatePath() string {
	return filepath.Join(c.CacheDir, c.RootCertificateFilename)
}

// TLSCertificate loads and returns a tls.Certificate from the Cache's certificate and private key files.
func (c *FileCache) TLSCertificate() (*tls.Certificate, error) {
	if !fileExists(c.PrivateKeyPath()) {
		return nil, fmt.Errorf("private key file missing")
	}

	if !fileExists(c.CertificatePath()) {
		return nil, fmt.Errorf("certificate file missing")
	}

	tlsCert, err := tls.LoadX509KeyPair(c.CertificatePath(), c.PrivateKeyPath())
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

// RootCertificate loads and returns the root certificate from the Cache's root certificate file.
func (c *FileCache) RootCertificate() (*x509.Certificate, error) {
	if !c.hasRootCertificate() {
		return nil, fmt.Errorf("root certificate file does not exist")
	}

	cont, err := os.ReadFile(c.RootCertificatePath())
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
func (c *FileCache) Valid(client *Client) error {
	if !fileExists(c.CertificatePath()) {
		return fmt.Errorf("certificate file missing")
	}

	cont, err := os.ReadFile(c.CertificatePath())
	if err != nil {
		return fmt.Errorf("could not read certificate file: %w", err)
	}

	block, _ := pem.Decode(cont)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("could not parse certificate: %w", err)
	}

	diff := time.Until(cert.NotAfter)
	if diff.Hours() < minCertValidityHours {
		return fmt.Errorf("certificate is about to expire")
	}

	if client.strictMode {
		fmt.Println("strict mode enabled; checking revocation status...")
		if !c.hasRootCertificate() {
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
			return fmt.Errorf("status is neither good nor unknown!")
		}
	}

	return nil
}

func (c *FileCache) hasRootCertificate() bool {
	return fileExists(c.RootCertificatePath())
}
