package certmaker

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	requestCertificatePath        = "/api/certificate/request"
	requestCertificateWithCSRPath = "/api/certificate/request-with-csr"

	authenticationHeader      = "X-Auth-Token"
	certificateLocationHeader = "X-Certificate-Location"
	privateKeyLocationHeader  = "X-Privatekey-Location"

	minCertValidity = 3 // in days
)

// Client represents the structure required to obtain certificates (and private keys) from a remote location.
type Client struct {
	httpClient *http.Client
	baseUrl    string
	token      string
}

// NewClient returns a *Client with a new *http.Client and baseUrl and token set to their parameter values
func NewClient(baseUrl, token string) *Client {
	c := Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseUrl:    baseUrl,
		token:      token,
	}

	return &c
}

// RequestForDomains is a convenience function to fetch a certificate and a private
// key for just the selected domain(s) without a care about other settings.
func (c *Client) RequestForDomains(cache *Cache, domain []string) error {
	// make sure the cache directory exists
	_ = os.Mkdir(cache.CacheDir, 0755)

	// check if both files exist and if cert validity > minCertValidity
	if fileExists(cache.GetCertificatePath()) && fileExists(cache.GetPrivateKeyPath()) {
		pair, err := tls.LoadX509KeyPair(cache.GetCertificatePath(), cache.GetPrivateKeyPath())
		// if err != nil, continue to fetch fresh certificate(s)
		if err == nil {
			cert, err := x509.ParseCertificate(pair.Certificate[0])
			if err == nil {
				// return here if certificate validity is still > minCertValidity
				diff := cert.NotAfter.Sub(time.Now())
				if diff.Hours() > 24 * minCertValidity {
					return nil
				}
			}
		}
	}

	cr := CertificateRequest{
		Domains: domain,
		Days: 30,
	}

	jsonCont, err := json.Marshal(cr)
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(jsonCont)

	url := c.baseUrl + requestCertificatePath

	req, err := http.NewRequest(http.MethodPost, url, buf)
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

	certLoc := resp.Header.Get(certificateLocationHeader)
	if certLoc == "" {
		return fmt.Errorf("missing %s header", certificateLocationHeader)
	}
	err = c.downloadCertificateFromLocation(certLoc, cache)
	if err != nil {
		return fmt.Errorf("error downloading certificate from location: " + err.Error())
	}

	pkLoc := resp.Header.Get(privateKeyLocationHeader)
	if pkLoc == "" {
		return fmt.Errorf("missing %s header", privateKeyLocationHeader)
	}

	err = c.downloadPrivateKeyFromLocation(pkLoc, cache)
	if err != nil {
		return fmt.Errorf("error downloading private key from location: " + err.Error())
	}

	return nil
}

func (c *Client) downloadCertificateFromLocation(certLocation string, cache *Cache) error {
	req, err := http.NewRequest(http.MethodGet, certLocation, nil)
	if err != nil {
		return err
	}
	req.Header.Set(authenticationHeader, c.token)

	certReq, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	if certReq.StatusCode != http.StatusOK {
		return fmt.Errorf("private key request: expected status 200, got %d", certReq.StatusCode)
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

func (c *Client) downloadPrivateKeyFromLocation(keyLocation string, cache *Cache) error {
	req, err := http.NewRequest(http.MethodGet, keyLocation, nil)
	if err != nil {
		return err
	}
	req.Header.Set(authenticationHeader, c.token)

	keyReq, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	if keyReq.StatusCode != http.StatusOK {
		return fmt.Errorf("private key request: expected status 200, got %d", keyReq.StatusCode)
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
