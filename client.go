package certmaker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	apiPrefix = "/api"
	requestCertificatePath = apiPrefix + "/certificate/request"
	requestCertificateWithCSRPath = apiPrefix + "/certificate/request-with-csr"

	authenticationHeader = "X-Auth-Key"
	certificateLocationHeader = "X-Certificate-Location"
	privateKeyLocationHeader = "X-Privatekey-Location"
)

type Client struct {
	httpClient *http.Client
	baseUrl    string
	token      string
}

func NewClient(baseUrl, token string) (*Client, error) {
	c := Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseUrl:    baseUrl,
		token:      token,
	}

	return &c, nil
}
// RequestForDomains is a convenience function to fetch a certificate and a private
// token for just the selected domain without a care about other settings.
func (c *Client) RequestForDomains(cache *Cache, domain []string) error {
	// make sure the cache directory exists
	_ = os.Mkdir(cache.CacheDir, 0755)

	cr := CertificateRequest{
		Domains: domain,
	}

	jsonCont, err := json.Marshal(cr)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(jsonCont)

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s", c.baseUrl, requestCertificatePath), buf)
	if err != nil {
		return err
	}

	req.Header.Set(authenticationHeader, c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	err = c.downloadCertificateFromLocation(resp.Header, cache)
	if err != nil {
		return fmt.Errorf("error downloading certificate from location: " + err.Error())
	}
	err = c.downloadPrivateKeyFromLocation(resp.Header, cache)
	if err != nil {
		return fmt.Errorf("error downloading private key from location: " + err.Error())
	}

	return nil
}

func (c *Client) downloadCertificateFromLocation(header http.Header, cache *Cache) error {
	certLoc := header.Get(certificateLocationHeader)
	if certLoc == "" {
		return fmt.Errorf("missing %s header", certificateLocationHeader)
	}

	req, err := http.NewRequest(http.MethodGet, header.Get(certificateLocationHeader), nil)
	if err != nil {
		return err
	}
	certReq, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	dstWriter, err := os.Create(cache.GetCertificatePath())
	if err != nil {
		return err
	}
	_, err = io.Copy(dstWriter, certReq.Body)
	if err != nil {
		return err
	}
	_ = certReq.Body.Close()
	_ = dstWriter.Close()

	return nil
}

func (c *Client) downloadPrivateKeyFromLocation(header http.Header, cache *Cache) error {
	pkLoc := header.Get(privateKeyLocationHeader)
	if pkLoc == "" {
		return fmt.Errorf("missing %s header", privateKeyLocationHeader)
	}

	req, err := http.NewRequest(http.MethodGet, header.Get(privateKeyLocationHeader), nil)
	if err != nil {
		return err
	}
	keyReq, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	dstWriter, err := os.Create(cache.GetPrivateKeyPath())
	if err != nil {
		return err
	}
	_, err = io.Copy(dstWriter, keyReq.Body)
	if err != nil {
		return err
	}
	_ = keyReq.Body.Close()
	_ = dstWriter.Close()

	return nil
}

