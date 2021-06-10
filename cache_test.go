package certmaker

import (
	"reflect"
	"testing"
)

func TestNewCache(t *testing.T) {
	tests := []struct {
		name    string
		want    *Cache
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCache()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCache() got = %v, want %v", got, tt.want)
			}
		})
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
				CacheDir:            tt.fields.CacheDir,
				PrivateKeyFilename:  tt.fields.PrivateKeyFilename,
				CertificateFilename: tt.fields.CertificateFilename,
			}
			if got := c.GetCertificatePath(); got != tt.want {
				t.Errorf("GetCertificatePath() = %v, want %v", got, tt.want)
			}
		})
	}
}