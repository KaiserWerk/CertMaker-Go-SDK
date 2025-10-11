package certmaker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	// paths for the CertMaker API
	apiPrefix                     = "/api/v1"
	downloadRootCertificatePath   = apiPrefix + "/root-certificate/obtain"
	requestCertificatePath        = apiPrefix + "/certificate/request-with-simplerequest"
	requestCertificateWithCSRPath = apiPrefix + "/certificate/request-with-csr"
	solveHTTP01ChallengePath      = apiPrefix + "/http-01/%d/solve"
	solveDNS01ChallengePath       = apiPrefix + "/dns-01/%d/solve"
	revokeCertificatePath         = apiPrefix + "/certificate/%d/revoke"
	ocspStatusPath                = apiPrefix + "/ocsp"

	// local path to place a token for solving the certificate challenge
	wellKnownPath = ".well-known/certmaker-challenge/token.txt"

	// used HTTP header
	authenticationHeader = "X-Auth-Token"

	pemContentType = "application/x-pem-file"

	defaultMinimumValidity = 72 * time.Hour
	clientDefaultTimeout   = 60 * time.Second
)

// Client represents the structure required to obtain certificates (and private keys) from a remote location.
type Client struct {
	httpClient         *http.Client
	baseUrl            string
	token              string
	strictMode         bool
	challengePort      uint16
	preferredChallenge string   // "http-01" or "dns-01"
	updater            *updater // required for the GetCertificateFunc
	challengeSolver    ChallengeSolver
}

// NewClient returns a *Client with a new *http.Client and baseUrl and token fields set to their parameter values.
// A *Client is used to perform HTTP requests to a CertMaker instance.
// Optionally, you can pass a *ClientSettings struct to alter the behaviour of the client.
// If settings is nil, the client will use default values.
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
		c.challengePort = settings.ChallengePort
		if settings.ChallengeSolver != nil {
			c.challengeSolver = settings.ChallengeSolver
		}
	} else {
		c.httpClient = &http.Client{Timeout: clientDefaultTimeout}
	}

	return &c
}

// SetupWithSimpleRequest is a preparatory call in order to use GetCertificateFunc with an http.Server struct
func (c *Client) SetupWithSimpleRequest(cache *FileCache, srFunc func() (*SimpleRequest, error), minValidity time.Duration) {
	c.updater = &updater{
		cache:       cache,
		srFunc:      srFunc,
		minValidity: minValidity,
	}
}

// SetupWithCSR is a preparatory call in order to use GetCertificateFunc with an http.Server struct
func (c *Client) SetupWithCSR(cache *FileCache, csrFunc func() (*x509.CertificateRequest, error), privKeyFunc func() (string, error), minValidity time.Duration) {
	c.updater = &updater{
		cache:       cache,
		csrFunc:     csrFunc,
		privKeyFunc: privKeyFunc,
		minValidity: minValidity,
	}
}

// RequestForDomains is a convenience method to fetch a certificate and a private
// key for just the selected domain(s) disregarding other options.
func (c *Client) RequestForDomains(cache *FileCache, domains []string, days int) error {
	err := os.MkdirAll(cache.CacheDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating cache directory: %s", err.Error())
	}

	err = cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	sr := SimpleRequest{
		Domains: domains,
		Days:    days,
	}

	if sr.PreferredChallenge == "" {
		sr.PreferredChallenge = c.preferredChallenge
	}

	return c.Request(cache, &sr)
}

// RequestForIPs is a convenience method to fetch a certificate and a private
// key for just the selected IP address(es) disregarding other options.
func (c *Client) RequestForIPs(cache *FileCache, ips []string, days int) error {
	err := os.MkdirAll(cache.CacheDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating cache directory: %s", err.Error())
	}

	err = cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	sr := SimpleRequest{
		IPs:  ips,
		Days: days,
	}

	if sr.PreferredChallenge == "" {
		sr.PreferredChallenge = c.preferredChallenge
	}

	return c.Request(cache, &sr)
}

// RequestForEmails is a convenience method to fetch a certificate and a private
// key for just the selected email address(es) disregarding other options.
func (c *Client) RequestForEmails(cache *FileCache, emails []string, days int) error {
	err := os.MkdirAll(cache.CacheDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating cache directory: %s", err.Error())
	}

	err = cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	sr := SimpleRequest{
		EmailAddresses: emails,
		Days:           days,
	}

	if sr.PreferredChallenge == "" {
		sr.PreferredChallenge = c.preferredChallenge
	}

	return c.Request(cache, &sr)
}

// Request requests a fresh certificate and private key with the metadata contained in the
// *SimpleRequest and puts it into *Cache.
func (c *Client) Request(cache *FileCache, simpleRequest *SimpleRequest) error {
	err := os.MkdirAll(cache.CacheDir, 0755)
	if err != nil {
		return fmt.Errorf("certmaker-sdk: error creating cache directory: %s", err.Error())
	}

	err = cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	jsonCont, err := json.Marshal(simpleRequest)
	if err != nil {
		return err
	}

	// send POST request with the SimpleRequest as JSON body
	resp, err := c.httpClient.Post(c.baseUrl+requestCertificatePath, "application/json", bytes.NewBuffer(jsonCont))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var response CertificateResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusAccepted {
		// with challenge

		if !response.HTTP01Challenge && !response.DNS01Challenge {
			return ErrNoChallengeIssued
		}

		if len(simpleRequest.Domains) == 0 {
			return ErrNoDomainsProvided
		}

		challengeCtx, challengeCancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer challengeCancel()

		err = c.challengeSolver.Setup(challengeCtx, response.ChallengeToken, simpleRequest.Domains)
		if err != nil {
			return fmt.Errorf("certmaker-sdk: could not set up challenge: " + err.Error())
		}

		certificateResponse, err := c.challengeSolver.Solve(challengeCtx, c.baseUrl, response.ChallengeID)
		if err != nil {
			return fmt.Errorf("certmaker-sdk: could not solve challenge: " + err.Error())
		}

		err = os.WriteFile(cache.CertificatePath(), []byte(certificateResponse.CertificatePEM), 0644)
		if err != nil {
			return fmt.Errorf("certmaker-sdk: could not write certificate file: " + err.Error())
		}
		err = os.WriteFile(cache.PrivateKeyPath(), []byte(certificateResponse.PrivateKeyPEM), 0600)
		if err != nil {
			return fmt.Errorf("certmaker-sdk: could not write private key file: " + err.Error())
		}
	} else if resp.StatusCode == http.StatusCreated {
		// w/o challenge, just write the certificate and private key to file
		err = os.WriteFile(cache.CertificatePath(), []byte(response.CertificatePEM), 0644)
		if err != nil {
			return fmt.Errorf("certmaker-sdk: could not write certificate file: " + err.Error())
		}

		err = os.WriteFile(cache.PrivateKeyPath(), []byte(response.PrivateKeyPEM), 0600)
		if err != nil {
			return fmt.Errorf("certmaker-sdk: could not write private key file: " + err.Error())
		}
	} else {
		// if it's neither of both, return error
		return fmt.Errorf("certmaker-sdk: expected status code 201 or 202, got %d", resp.StatusCode)
	}

	return nil
}

// RequestWithCSR is like Request but with the subtle difference that it takes a x509.CertificateRequest, which is
// commonly known as a Certificate Signing Request (CSR).
// The *Cache must have the PrivateKeyFilename field set to a file containing a valid private key. Otherwise
// the process will fail.
func (c *Client) RequestWithCSR(cache *FileCache, csr *x509.CertificateRequest) error {
	err := os.MkdirAll(cache.CacheDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating cache directory: %s", err.Error())
	}

	err = cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	// TODO: REWORK!
	// certLoc, _, err := c.requestCertificateForCSR(bytes.NewBuffer(csr.Raw)) // TODO: adapt for CSR
	// if err != nil {
	// 	return err
	// }

	// err = c.downloadCertificateFromLocation(cache, certLoc)
	// if err != nil {
	// 	return fmt.Errorf("RequestWithCSR: error downloading certificate from location '%s': %s", certLoc, err.Error())
	// }

	// private key is not downloaded as it must already exist beforehand

	return nil
}

// RequestRepeatedly is like Request, but runs repeatedly with the supplied interval.
// This is a blocking method, call it as a goroutine.
func (c *Client) RequestRepeatedly(ctx context.Context, cache *FileCache, cr *SimpleRequest, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Request(cache, cr); err != nil {
				if errors.Is(err, ErrStillValid) {
					fmt.Println("RequestRepeatedly: certificate still valid, not requesting a new one")
					continue
				}
				fmt.Println("RequestRepeatedly: error requesting certificate:", err)
			}
		}
	}
}

// RequestRepeatedlyWithCSR is like RequestWithCSR, but runs repeatedly with the supplied interval.
// This is a blocking method, call it as a goroutine.
func (c *Client) RequestRepeatedlyWithCSR(ctx context.Context, cache *FileCache, csr *x509.CertificateRequest, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.RequestWithCSR(cache, csr); err != nil {
				if errors.Is(err, ErrStillValid) {
					fmt.Println("RequestRepeatedlyWithCSR: certificate still valid, not requesting a new one")
					continue
				}
				fmt.Println("RequestRepeatedlyWithCSR: error requesting certificate:", err)
			}
		}
	}
}

// GetCertificateFunc returns a function suitable for use as tls.Config.GetCertificate.
// It will automatically request a new certificate if the existing one is not valid anymore.
// You must call either SetupWithSimpleRequest or SetupWithCSR before calling this method,
// otherwise it will return an error.
func (c *Client) GetCertificateFunc(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("client is nil")
	}

	if c.updater == nil || c.updater.cache == nil {
		return nil, fmt.Errorf("updater or cache are nil")
	}

	err := os.MkdirAll(c.updater.cache.CacheDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating cache directory: %s", err.Error())
	}

	if c.updater.csrFunc != nil && c.updater.privKeyFunc != nil {
		if !c.updater.cache.HasPrivateKey() {
			if c.updater.privKeyFunc != nil {
				privKeyPath, err := c.updater.privKeyFunc()
				if err != nil {
					return nil, fmt.Errorf("error calling private key function: %w", err)
				}

				err = c.updater.cache.CopyPrivateKeyFromFile(privKeyPath)
				if err != nil {
					return nil, fmt.Errorf("error copying private key from file: %w", err)
				}
			} else {
				return nil, fmt.Errorf("private key file is missing and no function to obtain it was supplied")
			}
		}
	}

	err = c.updater.cache.Valid(c, c.updater.minValidity)
	if err == nil {
		return c.updater.cache.TLSCertificate()
	}

	if c.updater.srFunc != nil {
		sr, err := c.updater.srFunc()
		if err != nil {
			return nil, fmt.Errorf("error calling SimpleRequest function: %w", err)
		}
		err = c.Request(c.updater.cache, sr)
		if err != nil {
			return nil, fmt.Errorf("error requesting certificate with SimpleRequest: %w", err)
		}
	} else if c.updater.csrFunc != nil {
		csr, err := c.updater.csrFunc()
		if err != nil {
			return nil, fmt.Errorf("error calling CSR function: %w", err)
		}
		err = c.RequestWithCSR(c.updater.cache, csr)
		if err != nil {
			return nil, fmt.Errorf("error requesting certificate with CSR: %w", err)
		}
	} else {
		return nil, ErrMissingSetup
	}

	tlsCert, err := c.updater.cache.TLSCertificate()
	if err != nil {
		return nil, err
	}

	if tlsCert == nil {
		return nil, fmt.Errorf("the *tls.Certificate was nil")
	}

	return tlsCert, nil
}

// DownloadRootCertificate downloads the root certificate from the CertMaker instance
// and stores it in the location specified by cache.RootCertificatePath().
// If there is already a file at that location, it will be overwritten.
func (c *Client) DownloadRootCertificate(cache *FileCache) error {
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

	fh, err := os.OpenFile(cache.RootCertificatePath(), os.O_CREATE|os.O_WRONLY, 0744)
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

// func (c *Client) downloadCertificateFromLocation(cache *FileCache, certLocation string) error {
// 	if certLocation == "" {
// 		return fmt.Errorf("certificate Location is empty")
// 	}
// 	req, err := http.NewRequest(http.MethodGet, certLocation, nil)
// 	if err != nil {
// 		return err
// 	}
// 	req.Header.Set(authenticationHeader, c.token)

// 	certReq, err := c.httpClient.Do(req)
// 	if err != nil {
// 		return err
// 	}

// 	if certReq.StatusCode != http.StatusOK {
// 		return fmt.Errorf("certificate request: expected status 200, got %d", certReq.StatusCode)
// 	}

// 	dstWriter, err := os.OpenFile(cache.CertificatePath(), os.O_WRONLY|os.O_CREATE, 0700)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = io.Copy(dstWriter, certReq.Body)
// 	if err != nil {
// 		return err
// 	}
// 	_ = certReq.Body.Close()
// 	_ = dstWriter.Close()

// 	return nil
// }

// func (c *Client) downloadPrivateKeyFromLocation(cache *FileCache, keyLocation string) error {
// 	if keyLocation == "" {
// 		return fmt.Errorf("key Location is empty")
// 	}

// 	req, err := http.NewRequest(http.MethodGet, keyLocation, nil)
// 	if err != nil {
// 		return err
// 	}
// 	req.Header.Set(authenticationHeader, c.token)

// 	keyReq, err := c.httpClient.Do(req)
// 	if err != nil {
// 		return err
// 	}

// 	if keyReq.StatusCode != http.StatusOK {
// 		return fmt.Errorf("private key request: expected status 200, got %d", keyReq.StatusCode)
// 	}

// 	dstWriter, err := os.OpenFile(cache.PrivateKeyPath(), os.O_WRONLY|os.O_CREATE, 0700)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = io.Copy(dstWriter, keyReq.Body)
// 	if err != nil {
// 		return err
// 	}
// 	_ = keyReq.Body.Close()
// 	_ = dstWriter.Close()

// 	return nil
// }

// requestCertificateAndPrivateKey sends the actual request to the CertMaker instance and handles the response.
// It returns either a selection of challenges to be solved or PEM contents of the certificate and private key.
// func (c *Client) requestCertificateAndPrivateKey(simpleRequest *SimpleRequest) error {
// 	jsonCont, err := json.Marshal(simpleRequest)
// 	if err != nil {
// 		return err
// 	}

// 	req, err := http.NewRequest(http.MethodPost, c.baseUrl+requestCertificatePath, bytes.NewBuffer(jsonCont))
// 	if err != nil {
// 		return fmt.Errorf("certmaker-sdk: could not create HTTP request: " + err.Error())
// 	}

// 	req.Header.Set(authenticationHeader, c.token)

// 	resp, err := c.httpClient.Do(req)
// 	if err != nil {
// 		return fmt.Errorf("certmaker-sdk: could not execute HTTP request: " + err.Error())
// 	}
// 	defer resp.Body.Close()

// 	var response CertificateResponse
// 	err = json.NewDecoder(resp.Body).Decode(&response)
// 	if err != nil {
// 		return fmt.Errorf("certmaker-sdk: could not decode response body: " + err.Error())
// 	}

// 	switch resp.StatusCode {
// 	case http.StatusCreated:
// 		// w/o challenge, just write the certificate and private key to file
// 		err = os.WriteFile(c.updater.cache.CertificatePath(), []byte(response.CertificatePEM), 0644)
// 		if err != nil {
// 			return fmt.Errorf("certmaker-sdk: could not write certificate file: " + err.Error())
// 		}
// 		err = os.WriteFile(c.updater.cache.PrivateKeyPath(), []byte(response.PrivateKeyPEM), 0600)
// 		if err != nil {
// 			return fmt.Errorf("certmaker-sdk: could not write private key file: " + err.Error())
// 		}
// 	case http.StatusAccepted:
// 		// with challenge

// 	default:
// 		// if it's neither of both, return error
// 		return fmt.Errorf("certmaker-sdk: expected status code 201 or 202, got %d", resp.StatusCode)
// 	}

// 	return nil
// }

// func (c *Client) requestCertificateForCSR(body io.Reader) (string, string, error) {
// 	req, err := http.NewRequest(http.MethodPost, c.baseUrl+requestCertificateWithCSRPath, body)
// 	if err != nil {
// 		return "", "", fmt.Errorf("requestCertificateForCSR: could not create new HTTP request: " + err.Error())
// 	}

// 	req.Header.Set(authenticationHeader, c.token)

// 	resp, err := c.httpClient.Do(req)
// 	if err != nil {
// 		return "", "", fmt.Errorf("requestCertificateForCSR: could not execute HTTP request: " + err.Error())
// 	}
// 	defer resp.Body.Close()

// 	var certLoc string
// 	switch resp.StatusCode {
// 	case http.StatusCreated:
// 		// w/o challenge
// 		certLoc = resp.Header.Get(certificateLocationHeader)
// 		if certLoc == "" {
// 			return "", "", fmt.Errorf("missing %s header", certificateLocationHeader)
// 		}
// 	case http.StatusAccepted:
// 		// with challenge
// 		loc := resp.Header.Get(challengeLocationHeader)
// 		if loc == "" {
// 			return "", "", fmt.Errorf("missing %s header", challengeLocationHeader)
// 		}

// 		token, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			return "", "", err
// 		}

// 		certLoc, _, err = c.resolveHTTPChallenge(loc, token, c.challengePort)
// 		if err != nil {
// 			return "", "", err
// 		}
// 	default:
// 		// if it's neither of both, return error
// 		return "", "", fmt.Errorf("requestCertificateForCSR: expected status code 201 or 202, got %d", resp.StatusCode)
// 	}

// 	return certLoc, "", nil
// }

// func (c *Client) resolveHTTPChallenge(resolveURL string, token []byte, challengePort uint16) (string, string, error) {
// 	if challengePort == 0 {
// 		challengePort = 80
// 	}

// 	mux := http.NewServeMux()
// 	mux.HandleFunc(wellKnownPath, func(w http.ResponseWriter, r *http.Request) { w.Write(token) })
// 	server := http.Server{
// 		Handler:           mux,
// 		Addr:              fmt.Sprintf(":%d", challengePort),
// 		ReadTimeout:       60 * time.Second,
// 		WriteTimeout:      60 * time.Second,
// 		ReadHeaderTimeout: 20 * time.Second,
// 	}
// 	server.SetKeepAlivesEnabled(false)

// 	go server.ListenAndServe()
// 	defer server.Shutdown(context.Background()) // TODO: supply proper context with deadline

// 	req, err := http.NewRequest(http.MethodGet, resolveURL, nil)
// 	if err != nil {
// 		return "", "", err
// 	}

// 	req.Header.Set(authenticationHeader, c.token)

// 	resp, err := c.httpClient.Do(req)
// 	if err != nil {
// 		return "", "", err
// 	}

// 	certLoc := resp.Header.Get(certificateLocationHeader)
// 	if certLoc == "" {
// 		return "", "", fmt.Errorf("missing %s header", certificateLocationHeader)
// 	}

// 	// pkLoc might be empty for requests with CSR
// 	pkLoc := resp.Header.Get(privateKeyLocationHeader)

// 	return certLoc, pkLoc, nil
// }
