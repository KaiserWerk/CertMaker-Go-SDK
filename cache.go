package certmaker

import "path/filepath"

// Cache represents local directory and file paths for certificates and private keys
type Cache struct {
	CacheDir            string
	PrivateKeyFilename  string
	CertificateFilename string
}

// NewCache returns a *Cache with default values: Cache.CacheDir is `.certs`,
// Cache.CertificateFilename is `cert.pem,` Cache.PrivateKeyFilename is `key.pem`
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
