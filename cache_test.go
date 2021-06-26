package certmaker

import (
	"path/filepath"
	"testing"
)

func TestNewCache(t *testing.T) {
	c, err := NewCache()
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
}

func TestCache_GetCertificatePath(t *testing.T) {
	type fields struct {
		CacheDir            string
		PrivateKeyFilename  string
		CertificateFilename string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cache{
				PrivateKeyFilename:  tt.fields.PrivateKeyFilename,
				CertificateFilename: tt.fields.CertificateFilename,
			}
			if err := c.SetDir(tt.fields.CacheDir); err != nil {
				t.Fatalf("expected no error; got %s", err.Error())
			}
			if got := c.GetCertificatePath(); got != tt.want {
				t.Errorf("GetCertificatePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
