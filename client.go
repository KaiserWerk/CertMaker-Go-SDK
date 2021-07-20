package certmaker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

const (
	// paths for the CertMaker API
	apiPrefix                     = "/api/v1"
	downloadRootCertificatePath   = apiPrefix + "/root-certificate/obtain"
	requestCertificatePath        = apiPrefix + "/certificate/request"
	requestCertificateWithCSRPath = apiPrefix + "/certificate/request-with-csr"
	//solveChallengePath            = apiPrefix + "/challenge/%d/solve"
	revokeCertificatePath         = apiPrefix + "/certificate/%d/revoke"
	ocspStatusPath                = apiPrefix + "/ocsp"

	// local path to place a token for solving the certificate challenge
	wellKnownPath = ".well-known/certmaker-challenge/token.txt"

	// used HTTP header
	authenticationHeader      = "X-Auth-Token"
	certificateLocationHeader = "X-Certificate-Location"
	privateKeyLocationHeader  = "X-Privatekey-Location"
	challengeLocationHeader   = "X-Challenge-Location"

	pemContentType = "application/x-pem-file"

	minCertValidityDays  = 3
	clientDefaultTimeout = 5 * time.Second
)

// Client represents the structure required to obtain certificates (and private keys) from a remote location.
type Client struct {
	httpClient    *http.Client
	baseUrl       string
	token         string
	strictMode    bool
	challengePort uint16
	updater       *updater // required for the GetCertificateFunc
}

// NewClient returns a *Client with a new *http.Client and baseUrl and token fields set to their parameter values
func NewClient(baseUrl, token string, settings *ClientSettings) *Client {
	c := Client{
		baseUrl: baseUrl,
		token:   token,
	}
	if settings != nil {
		timeout := clientDefaultTimeout
		if settings.ClientTimeout > 0 {
			timeout = settings.ClientTimeout
		}
		c.httpClient = &http.Client{Timeout: timeout}

		if settings.Transport != nil {
			c.httpClient.Transport = settings.Transport
		}

		c.strictMode = settings.StrictMode

	} else {
		c.httpClient = &http.Client{Timeout: clientDefaultTimeout}
	}

	return &c
}

// SetupWithSimpleRequest is a preparatory call in order to use GetCertificateFunc with an http.Server struct
func (c *Client) SetupWithSimpleRequest(cache *Cache, sr *SimpleRequest) {
	c.updater = &updater{
		cache:         cache,
		simpleRequest: sr,
	}
}

// SetupWithCSR is a preparatory call in order to use GetCertificateFunc with an http.Server struct
func (c *Client) SetupWithCSR(cache *Cache, csr *x509.CertificateRequest) {
	c.updater = &updater{
		cache: cache,
		csr:   csr,
	}
}

// RequestForDomains is a convenience method to fetch a certificate and a private
// key for just the selected domain(s) without a care about other settings.
func (c *Client) RequestForDomains(cache *Cache, domains []string, days int) error {
	_ = os.Mkdir(cache.CacheDir, 0755)

	if valid := cache.Valid(c); valid {
		return ErrStillValid{}
	}

	cr := SimpleRequest{
		Domains: domains,
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
		return fmt.Errorf("RequestForDomains: error downloading certificate from location: " + err.Error())
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

	if valid := cache.Valid(c); valid {
		return ErrStillValid{}
	}

	cr := SimpleRequest{
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
		return fmt.Errorf("RequestForIps: error downloading certificate from location: " + err.Error())
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

	if valid := cache.Valid(c); valid {
		return ErrStillValid{}
	}

	cr := SimpleRequest{
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
		return fmt.Errorf("RequestForEmails: error downloading certificate from location: " + err.Error())
	}

	err = c.downloadPrivateKeyFromLocation(cache, pkLoc)
	if err != nil {
		return fmt.Errorf("error downloading private key from location: " + err.Error())
	}

	return nil
}

// Request requests a fresh certificate and private key with the meta data contained in the
// *SimpleRequest and puts it into *Cache.
func (c *Client) Request(cache *Cache, cr *SimpleRequest) error {
	_ = os.Mkdir(cache.CacheDir, 0755)

	if valid := cache.Valid(c); valid {
		return ErrStillValid{}
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

	if certLoc == "" {
		return fmt.Errorf("cert location is empty")
	}

	if pkLoc == "" {
		return fmt.Errorf("private key Location is empty")
	}

	err = c.downloadCertificateFromLocation(cache, certLoc)
	if err != nil {
		return fmt.Errorf("Request: error downloading certificate from location: " + err.Error())
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
func (c *Client) RequestWithCSR(cache *Cache, csr *x509.CertificateRequest) error {
	_ = os.Mkdir(cache.CacheDir, 0755)

	if !fileExists(cache.GetPrivateKeyPath()) {
		return fmt.Errorf("private key file missing")
	}

	if valid := cache.Valid(c); valid {
		return ErrStillValid{}
	}

	jsonCont, err := json.Marshal(csr)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(jsonCont)

	certLoc, _, err := c.requestNewKeyPair(buf) // TODO adapt for CSR
	if err != nil {
		return err
	}

	err = c.downloadCertificateFromLocation(cache, certLoc)
	if err != nil {
		return fmt.Errorf("RequestWithCSR: error downloading certificate from location '%s': %s", certLoc, err.Error())
	}

	//err = c.downloadPrivateKeyFromLocation(cache, pkLoc)
	//if err != nil {
	//	return fmt.Errorf("error downloading private key from location '%s': %s", pkLoc, err.Error())
	//}

	return nil
}

// RequestRepeatedly is like Request, but runs repeatedly with the supplied interval until you tell it to stop. This is
// useful for servers that run for weeks or months without interruption.
// Since this is a blocking method, please call it as a goroutine.
//
// To stop execution, write true into the stopChan channel. If you don't need the ability to stop, pass nil
// as parameter for the stopChan.
//func (c *Client) RequestRepeatedly(cache *Cache, cr *SimpleRequest, interval time.Duration, stopChan chan bool) error {
//	return nil
//}

// RequestRepeatedlyWithCSR is like RequestWithCSR, but runs repeatedly with the supplied interval
// until you tell it to stop. This is useful for servers that run for weeks or months without interruption.
// Since this is a blocking method, please call it as a goroutine.
//
// To stop execution, write true into the stopChan channel. If you don't need the ability to stop, pass nil
// as parameter for the stopChan.
//func (c *Client) RequestRepeatedlyWithCSR(cache *Cache, csr x509.CertificateRequest, interval time.Duration, stopChan chan bool) error {
//	return nil
//}

func (c *Client) GetCertificateFunc(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("client is nil")
	}

	if c.updater == nil || c.updater.cache == nil {
		return nil, fmt.Errorf("updater or cache are nil")
	}

	_ = os.Mkdir(c.updater.cache.CacheDir, 0755)

	if valid := c.updater.cache.Valid(c); valid {
		return c.updater.cache.GetTlsCertificate()
	}

	var err error
	if c.updater.simpleRequest != nil {
		err = c.Request(c.updater.cache, c.updater.simpleRequest)
	} else if c.updater.csr != nil {
		err = c.RequestWithCSR(c.updater.cache, c.updater.csr)
	} else {
		return nil, fmt.Errorf("both SimpleRequest and CSR were nil")
	}

	if err != nil {
		return nil, err
	}

	tlsCert, err := c.updater.cache.GetTlsCertificate()
	if err != nil {
		return nil, err
	}

	if tlsCert == nil {
		return nil, fmt.Errorf("for whatever reason the *tls.Certificate was nil")
	}

	return tlsCert, nil
}

func (c *Client) downloadCertificateFromLocation(cache *Cache, certLocation string) error {
	if certLocation == "" {
		return fmt.Errorf("certificate Location is empty")
	}
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

	dstWriter, err := os.OpenFile(cache.GetCertificatePath(), os.O_WRONLY|os.O_CREATE, 0700)
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
	if keyLocation == "" {
		return fmt.Errorf("key Location is empty")
	}

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

	dstWriter, err := os.OpenFile(cache.GetPrivateKeyPath(), os.O_WRONLY|os.O_CREATE, 0700)
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
	req, err := http.NewRequest(http.MethodPost, c.baseUrl+requestCertificatePath, body)
	if err != nil {
		return "", "", fmt.Errorf("could not create new HTTP request: " + err.Error())
	}

	req.Header.Set(authenticationHeader, c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("could not execute HTTP request: " + err.Error())
	}
	defer resp.Body.Close()

	var certLoc, pkLoc string
	switch resp.StatusCode {
	case http.StatusOK:
		// w/o challenge
		certLoc = resp.Header.Get(certificateLocationHeader)
		if certLoc == "" {
			return "", "", fmt.Errorf("missing %s header", certificateLocationHeader)
		}

		pkLoc = resp.Header.Get(privateKeyLocationHeader)
		if pkLoc == "" {
			return "", "", fmt.Errorf("missing %s header", privateKeyLocationHeader)
		}
	case http.StatusAccepted:
		// with challenge
		loc := resp.Header.Get(challengeLocationHeader)
		if loc == "" {
			return "", "", fmt.Errorf("missing %s header", challengeLocationHeader)
		}

		token, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", "", err
		}

		certLoc, pkLoc, err = c.resolveSimpleRequestChallenge(loc, token, c.challengePort)
		if err != nil {
			return "", "", err
		}
	default:
		// if it's neither of both, return error
		return "", "", fmt.Errorf("expected status code 200 or 202, got %d", resp.StatusCode)
	}

	return certLoc, pkLoc, nil
}

func (c *Client) resolveSimpleRequestChallenge(locationUrl string, token []byte, challengePort uint16) (string, string, error) {
	if challengePort == 0 {
		challengePort = 80
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/certmaker-challenge/token.txt", func(rw http.ResponseWriter, r *http.Request) { rw.Write(token) })
	server := http.Server{
		Handler: mux,
		Addr:    fmt.Sprintf(":%d", challengePort),
		ReadTimeout: 3 * time.Second,
		WriteTimeout: 3 * time.Second,
		ReadHeaderTimeout: 1 * time.Second,
	}
	server.SetKeepAlivesEnabled(false)

	go server.ListenAndServe()
	defer server.Shutdown(context.Background())

	req, err := http.NewRequest(http.MethodGet, locationUrl, nil)
	if err != nil {
		return "", "", err
	}

	req.Header.Set(authenticationHeader, c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}

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

func (c *Client) DownloadRootCertificate(cache *Cache) error {
	req, err := http.NewRequest(http.MethodGet, c.baseUrl+downloadRootCertificatePath, nil)
	if err != nil {
		return err
	}

	req.Header.Set(authenticationHeader, c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != pemContentType {
		return fmt.Errorf("expected Content-Type %s, git %s", pemContentType, resp.Header.Get("Content-Type"))
	}

	fh, err := os.OpenFile(cache.GetRootCertificatePath(), os.O_CREATE|os.O_WRONLY, 0744)
	if err != nil {
		return err
	}
	defer fh.Close()

	_, err = io.Copy(fh, resp.Body)
	if err != nil {
		return err
	}

	return nil
}
