package certmaker

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	apiPrefix                     = "/api/v1"
	requestCertificatePath        = apiPrefix + "/certificate/request"
	requestCertificateWithCSRPath = apiPrefix + "/certificate/request-with-csr"
	obtainCertificatePath         = apiPrefix + "/certificate/%d/obtain"
	obtainPrivateKeyPath          = apiPrefix + "/privatekey/%d/obtain"
	solveChallengePath            = apiPrefix + "/challenge/%d/solve"
	revokeCertificatePath         = apiPrefix + "/certificate/%d/revoke"

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

func (c *Client) SetProxy(addr string) error {
	u, err := url.ParseRequestURI(addr)
	if err != nil {
		return err
	}

	c.httpClient.Transport = &http.Transport{
		Proxy: http.ProxyURL(u),
	}

	return nil
}

// RequestForDomains is a convenience method to fetch a certificate and a private
// key for just the selected domain(s) without a care about other settings.
func (c *Client) RequestForDomains(cache *Cache, domain []string, days int) error {
	_ = os.Mkdir(cache.CacheDir, 0755)

	if valid := isKeyPairValid(cache); valid {
		return nil
	}

	cr := CertificateRequest{
		Domains: domain,
		Days:    days,
	}

	jsonCont, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(jsonCont)

	certLoc, pkLoc, err := c.requestNewKeyPair(buf)
	if err != nil {
		return err
	}

	err = c.downloadCertificateFromLocation(cache, certLoc)
	if err != nil {
		return fmt.Errorf("error downloading certificate from location: " + err.Error())
	}

	err = c.downloadPrivateKeyFromLocation(cache, pkLoc)
	if err != nil {
		return fmt.Errorf("error downloading private key from location: " + err.Error())
	}

	return nil
}

// RequestForIps is a convenience method to fetch a certificate and a private
// key for just the selected IP address(es) without a care about other settings.
func (c *Client) RequestForIps(cache *Cache, ips []string, days int) error {
	_ = os.Mkdir(cache.CacheDir, 0755)

	if valid := isKeyPairValid(cache); valid {
		return nil
	}

	cr := CertificateRequest{
		IPs:  ips,
		Days: days,
	}

	jsonCont, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(jsonCont)

	certLoc, pkLoc, err := c.requestNewKeyPair(buf)
	if err != nil {
		return err
	}

	err = c.downloadCertificateFromLocation(cache, certLoc)
	if err != nil {
		return fmt.Errorf("error downloading certificate from location: " + err.Error())
	}

	err = c.downloadPrivateKeyFromLocation(cache, pkLoc)
	if err != nil {
		return fmt.Errorf("error downloading private key from location: " + err.Error())
	}

	return nil
}

// RequestForEmails is a convenience method to fetch a certificate and a private
// key for just the selected email address(es) without a care about other settings.
func (c *Client) RequestForEmails(cache *Cache, emails []string, days int) error {
	_ = os.Mkdir(cache.CacheDir, 0755)

	if valid := isKeyPairValid(cache); valid {
		return nil
	}

	cr := CertificateRequest{
		EmailAddresses: emails,
		Days:           days,
	}

	jsonCont, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(jsonCont)

	certLoc, pkLoc, err := c.requestNewKeyPair(buf)
	if err != nil {
		return err
	}

	err = c.downloadCertificateFromLocation(cache, certLoc)
	if err != nil {
		return fmt.Errorf("error downloading certificate from location: " + err.Error())
	}

	err = c.downloadPrivateKeyFromLocation(cache, pkLoc)
	if err != nil {
		return fmt.Errorf("error downloading private key from location: " + err.Error())
	}

	return nil
}

// Request requests a fresh certificate and private key with the meta data contained in the
// CertificateRequest.
func (c *Client) Request(cache *Cache, cr *CertificateRequest) error {
	_ = os.Mkdir(cache.CacheDir, 0755)

	if valid := isKeyPairValid(cache); valid {
		return nil
	}

	jsonCont, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(jsonCont)

	certLoc, pkLoc, err := c.requestNewKeyPair(buf)
	if err != nil {
		return err
	}

	err = c.downloadCertificateFromLocation(cache, certLoc)
	if err != nil {
		return fmt.Errorf("error downloading certificate from location: " + err.Error())
	}

	err = c.downloadPrivateKeyFromLocation(cache, pkLoc)
	if err != nil {
		return fmt.Errorf("error downloading private key from location: " + err.Error())
	}

	return nil
}

// RequestWithCSR is like Request but with the subtle difference that it takes a x509.CertificateRequest, which is
// commonly known as a Certificate Signing Request (CSR).
// The *Cache must have the PrivateKeyFilename field set to a file containing a valid private key. Otherwise
// the process will fail.
func (c *Client) RequestWithCSR(cache *Cache, csr x509.CertificateRequest) error {
	_ = os.Mkdir(cache.CacheDir, 0755)

	if !fileExists(cache.GetPrivateKeyPath()) {
		return fmt.Errorf("private key file missing")
	}

	//if valid := isKeyPairValid(cache); valid {
	//	return ErrStillValid(fmt.Errorf("key pair is still valid")))
	//}

	jsonCont, err := json.Marshal(csr)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(jsonCont)

	certLoc, pkLoc, err := c.requestNewKeyPair(buf)
	if err != nil {
		return err
	}

	err = c.downloadCertificateFromLocation(cache, certLoc)
	if err != nil {
		return fmt.Errorf("error downloading certificate from location '%s': %s", certLoc, err.Error())
	}

	err = c.downloadPrivateKeyFromLocation(cache, pkLoc)
	if err != nil {
		return fmt.Errorf("error downloading private key from location '%s': %s", pkLoc, err.Error())
	}

	return nil
}

// RequestRepeatedly is like Request, but runs repeatedly with the supplied interval until you tell it to stop. This is
// useful for servers that run for weeks or months without interruption.
// Since this is a blocking method, please call it as a goroutine.
//
// To stop execution, write true into the stopChan channel. If you don't need the ability to stop, pass nil
// as parameter for the stopChan.
func (c *Client) RequestRepeatedly(cache *Cache, cr *CertificateRequest, interval time.Duration, stopChan chan bool) error {
	return nil
}

// RequestRepeatedlyWithCSR is like RequestWithCSR, but runs repeatedly with the supplied interval
// until you tell it to stop. This is useful for servers that run for weeks or months without interruption.
// Since this is a blocking method, please call it as a goroutine.
//
// To stop execution, write true into the stopChan channel. If you don't need the ability to stop, pass nil
// as parameter for the stopChan.
func (c *Client) RequestRepeatedlyWithCSR(cache *Cache, csr x509.CertificateRequest, interval time.Duration, stopChan chan bool) error {
	return nil
}

func isKeyPairValid(cache *Cache) bool {
	if !fileExists(cache.GetCertificatePath()) || !fileExists(cache.GetPrivateKeyPath()) {
		return false
	}
	pair, err := tls.LoadX509KeyPair(cache.GetCertificatePath(), cache.GetPrivateKeyPath())
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

	// TODO check OCSP responder

	return true
}

func (c *Client) downloadCertificateFromLocation(cache *Cache, certLocation string) error {
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
		return fmt.Errorf("certificate request: expected status 200, got %d", certReq.StatusCode)
	}

	dstWriter, err := os.OpenFile(cache.GetCertificatePath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0744)
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

func (c *Client) downloadPrivateKeyFromLocation(cache *Cache, keyLocation string) error {
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

	dstWriter, err := os.OpenFile(cache.GetPrivateKeyPath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0744)
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

func (c *Client) requestNewKeyPair(body io.Reader) (string, string, error) {

	url := c.baseUrl + requestCertificatePath
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return "", "", err
	}

	req.Header.Set(authenticationHeader, c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	certLoc := resp.Header.Get(certificateLocationHeader)
	if certLoc == "" {
		return "", "", fmt.Errorf("missing %s header", certificateLocationHeader)
	}

	pkLoc := resp.Header.Get(privateKeyLocationHeader)
	if pkLoc == "" {
		return "", "", fmt.Errorf("missing %s header", privateKeyLocationHeader)
	}

	return certLoc, pkLoc, nil
}
