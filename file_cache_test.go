package certmaker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewCache(t *testing.T) {
	c, err := NewFileCache(".")
	if err != nil {
		t.Fatalf("expeced no error with NewCache(), got %s", err.Error())
	}
	if filepath.Base(c.CacheDir) != ".certs" {
		t.Fatalf("expected CacheDir .certs, got %s", c.CacheDir)
	}

	if c.PrivateKeyFilename != "key.pem" {
		t.Fatalf("expected private key filename key.pem, got %s", c.PrivateKeyFilename)
	}

	if c.CertificateFilename != "cert.pem" {
		t.Fatalf("expected certificate filename cert.pem, got %s", c.CertificateFilename)
	}
	c.Clear(true)
	t.Cleanup(func() {
		_ = os.RemoveAll(c.CacheDir)
	})
}
