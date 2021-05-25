package certmaker

import "path/filepath"

type Cache struct {
	CacheDir            string
	PrivateKeyFilename  string
	CertificateFilename string
}

func NewCache() (*Cache, error) {
	cache := Cache{}
	baseDir, err := filepath.Abs(".")
	if err != nil {
		return nil, err
	}
	cache.CacheDir = filepath.Join(baseDir, ".certs")
	cache.CertificateFilename = "cert.pem"
	cache.PrivateKeyFilename = "token.pem"

	return &cache, nil
}

func (c Cache) GetCertificatePath() string {
	return filepath.Join(c.CacheDir, c.CertificateFilename)
}

func (c Cache) GetPrivateKeyPath() string {
	return filepath.Join(c.CacheDir, c.PrivateKeyFilename)
}

