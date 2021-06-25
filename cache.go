package certmaker

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"time"
)

// Cache represents local directory and file paths for certificates and private keys
type Cache struct {
	CacheDir            string
	PrivateKeyFilename  string
	CertificateFilename string
}

// NewCache returns a *Cache with default values: CacheDir is `.certs`,
// CertificateFilename is `cert.pem,` PrivateKeyFilename is `key.pem`
func NewCache() (*Cache, error) {
	cache := Cache{}
	baseDir, err := filepath.Abs(".")
	if err != nil {
		return nil, err
	}
	cache.CacheDir = filepath.Join(baseDir, ".certs")
	cache.CertificateFilename = "cert.pem"
	cache.PrivateKeyFilename = "key.pem"

	return &cache, nil
}

// GetCertificatePath returns the full path the Cache's certificate file
func (c *Cache) GetCertificatePath() string {
	return filepath.Join(c.CacheDir, c.CertificateFilename)
}

// GetPrivateKeyPath returns the full path the Cache's private key file
func (c *Cache) GetPrivateKeyPath() string {
	return filepath.Join(c.CacheDir, c.PrivateKeyFilename)
}

func (c *Cache) GetTlsCertificate() (*tls.Certificate, error) {
	if !fileExists(c.GetPrivateKeyPath()) {
		return nil, fmt.Errorf("private key file missing")
	}

	if !fileExists(c.GetCertificatePath()) {
		return nil, fmt.Errorf("certificate file missing")
	}

	tlsCert, err := tls.LoadX509KeyPair(c.GetCertificatePath(), c.GetPrivateKeyPath())
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func (c *Cache) Valid(strict bool) bool {
	if !fileExists(c.GetCertificatePath()) || !fileExists(c.GetPrivateKeyPath()) {
		return false
	}
	pair, err := tls.LoadX509KeyPair(c.GetCertificatePath(), c.GetPrivateKeyPath())
	if err != nil {
		return false
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}

	diff := cert.NotAfter.Sub(time.Now())
	if diff.Hours() < 24*minCertValidity {
		return false
	}

	if strict {
		// TODO check OCSP responder
	}

	return true
}
