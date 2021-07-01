package certmaker

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"reflect"
	"testing"
)

func TestClient_DownloadRootCertificate(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache *Cache
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.DownloadRootCertificate(tt.args.cache); (err != nil) != tt.wantErr {
				t.Errorf("DownloadRootCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_GetCertificateFunc(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		chi *tls.ClientHelloInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *tls.Certificate
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			got, err := c.GetCertificateFunc(tt.args.chi)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificateFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetCertificateFunc() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_Request(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache *Cache
		cr    *SimpleRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.Request(tt.args.cache, tt.args.cr); (err != nil) != tt.wantErr {
				t.Errorf("Request() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_RequestForDomains(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache  *Cache
		domain []string
		days   int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.RequestForDomains(tt.args.cache, tt.args.domain, tt.args.days); (err != nil) != tt.wantErr {
				t.Errorf("RequestForDomains() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_RequestForEmails(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache  *Cache
		emails []string
		days   int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.RequestForEmails(tt.args.cache, tt.args.emails, tt.args.days); (err != nil) != tt.wantErr {
				t.Errorf("RequestForEmails() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_RequestForIps(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache *Cache
		ips   []string
		days  int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.RequestForIps(tt.args.cache, tt.args.ips, tt.args.days); (err != nil) != tt.wantErr {
				t.Errorf("RequestForIps() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_RequestWithCSR(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache *Cache
		csr   *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.RequestWithCSR(tt.args.cache, tt.args.csr); (err != nil) != tt.wantErr {
				t.Errorf("RequestWithCSR() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_SetProxy(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		addr string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.SetProxy(tt.args.addr); (err != nil) != tt.wantErr {
				t.Errorf("SetProxy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_SetupWithCSR(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache *Cache
		csr   *x509.CertificateRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
		})
	}
}

func TestClient_SetupWithSimpleRequest(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache *Cache
		sr    *SimpleRequest
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
		})
	}
}

func TestClient_downloadCertificateFromLocation(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache        *Cache
		certLocation string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.downloadCertificateFromLocation(tt.args.cache, tt.args.certLocation); (err != nil) != tt.wantErr {
				t.Errorf("downloadCertificateFromLocation() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_downloadPrivateKeyFromLocation(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		cache       *Cache
		keyLocation string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			if err := c.downloadPrivateKeyFromLocation(tt.args.cache, tt.args.keyLocation); (err != nil) != tt.wantErr {
				t.Errorf("downloadPrivateKeyFromLocation() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_requestNewKeyPair(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		body io.Reader
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			got, got1, err := c.requestNewKeyPair(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestNewKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("requestNewKeyPair() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("requestNewKeyPair() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestClient_resolveSimpleRequestChallenge(t *testing.T) {
	type fields struct {
		httpClient    *http.Client
		baseUrl       string
		token         string
		strictMode    bool
		challengePort uint16
		updater       *Updater
	}
	type args struct {
		locationUrl   string
		token         []byte
		challengePort uint16
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				httpClient:    tt.fields.httpClient,
				baseUrl:       tt.fields.baseUrl,
				token:         tt.fields.token,
				strictMode:    tt.fields.strictMode,
				challengePort: tt.fields.challengePort,
				updater:       tt.fields.updater,
			}
			got, got1, err := c.resolveSimpleRequestChallenge(tt.args.locationUrl, tt.args.token, tt.args.challengePort)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveSimpleRequestChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("resolveSimpleRequestChallenge() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("resolveSimpleRequestChallenge() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	type args struct {
		baseUrl  string
		token    string
		settings *ClientSettings
	}
	tests := []struct {
		name string
		args args
		want *Client
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewClient(tt.args.baseUrl, tt.args.token, tt.args.settings); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewClient() = %v, want %v", got, tt.want)
			}
		})
	}
}
