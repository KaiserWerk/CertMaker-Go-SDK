package certmaker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
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

	defaultMinimumValidity = 1 * time.Minute
	clientDefaultTimeout   = 60 * time.Second
)

// Client represents the structure required to obtain certificates (and private keys) from a remote location.
type Client struct {
	httpClient      *http.Client
	baseUrl         string
	token           string
	strictMode      bool
	challengePort   uint16
	updater         *updater // required for the GetCertificateFunc
	challengeSolver []ChallengeSolver
	mut             *sync.Mutex
}

// NewClient returns a *Client with a new *http.Client and baseUrl and token fields set to their parameter values.
// A *Client is used to perform HTTP requests to a CertMaker instance.
// Optionally, you can pass a *ClientSettings struct to alter the behaviour of the client.
// If settings is nil, the client will use default values.
func NewClient(baseUrl, token string, settings *ClientSettings) *Client {
	c := Client{
		baseUrl: baseUrl,
		token:   token,
		mut:     &sync.Mutex{},
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
		c.challengeSolver = []ChallengeSolver{}
	}

	return &c
}

// SetupWithSimpleRequest is a preparatory call in order to use GetCertificateFunc with an http.Server struct
func (c *Client) SetupWithSimpleRequest(cache Cache, minValidity time.Duration, srFunc func() (*SimpleRequest, error)) {
	c.updater = &updater{
		cache:       cache,
		srFunc:      srFunc,
		minValidity: minValidity,
	}
}

// SetupWithCSR is a preparatory call in order to use GetCertificateFunc with an http.Server struct
func (c *Client) SetupWithCSR(cache Cache, minValidity time.Duration, csrFunc func() (*x509.CertificateRequest, error), privKeyFunc func() (any, error)) {
	c.updater = &updater{
		cache:       cache,
		csrFunc:     csrFunc,
		privKeyFunc: privKeyFunc,
		minValidity: minValidity,
	}
}

// RequestForDomains is a convenience method to fetch a certificate and a private
// key for just the selected domain(s) disregarding other options.
func (c *Client) RequestForDomains(cache Cache, domains []string, validity time.Duration) error {
	err := cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	sr := SimpleRequest{
		Domains:  domains,
		Validity: validity,
	}

	return c.Request(cache, &sr)
}

// RequestForIPs is a convenience method to fetch a certificate and a private
// key for just the selected IP address(es) disregarding other options.
func (c *Client) RequestForIPs(cache Cache, ips []string, validity time.Duration) error {
	err := cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	sr := SimpleRequest{
		IPs:      ips,
		Validity: validity,
	}

	return c.Request(cache, &sr)
}

// RequestForEmails is a convenience method to fetch a certificate and a private
// key for just the selected email address(es) disregarding other options.
func (c *Client) RequestForEmails(cache Cache, emails []string, validity time.Duration) error {
	err := cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	sr := SimpleRequest{
		EmailAddresses: emails,
		Validity:       validity,
	}

	return c.Request(cache, &sr)
}

// Request requests a fresh certificate and private key with the metadata contained in the
// *SimpleRequest and puts it into *Cache.
func (c *Client) Request(cache Cache, simpleRequest *SimpleRequest) error {
	err := cache.Valid(c, defaultMinimumValidity)
	if err == nil {
		return ErrStillValid
	}

	jsonCont, err := json.Marshal(simpleRequest)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+requestCertificatePath, bytes.NewBuffer(jsonCont))
	if err != nil {
		return err
	}
	c.setHeader(req)

	// send POST request with the SimpleRequest as JSON body
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusBadRequest:
		return ErrBadRequest
	}

	var response CertificateResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusAccepted {
		// with challenge

		if len(response.Challenges) == 0 {
			return ErrNoChallengeIssued
		}

		if len(simpleRequest.Domains) == 0 {
			return ErrNoDomainsProvided
		}

		challengeCtx, challengeCancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer challengeCancel()

		for _, challenge := range response.Challenges {
			for _, solver := range c.challengeSolver {
				if solver.CanSolve(challenge.ChallengeType) {
					err = solver.Setup(challengeCtx, challenge.ChallengeToken, simpleRequest.Domains)
					if err != nil {
						return errors.New("certmaker-sdk: could not set up challenge: " + err.Error())
					}

					certificateResponse, err := solver.Solve(challengeCtx, c.baseUrl, challenge.ChallengeID, c.setHeader)
					if err != nil {
						return errors.New("certmaker-sdk: could not solve challenge: " + err.Error())
					}

					// certificate to file
					certContents, err := base64.StdEncoding.DecodeString(certificateResponse.CertificatePEM)
					if err != nil {
						return errors.New("certmaker-sdk: could not decode certificate from base64: " + err.Error())
					}

					var b bytes.Buffer
					err = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certContents})
					if err != nil {
						return errors.New("certmaker-sdk: could not encode certificate to PEM format: " + err.Error())
					}

					certPath, _ := cache.CertificatePath()
					err = os.WriteFile(certPath, b.Bytes(), 0644)
					if err != nil {
						return errors.New("certmaker-sdk: could not write certificate file: " + err.Error())
					}

					b.Reset()

					// private key to file
					privateKeyContents, err := base64.StdEncoding.DecodeString(certificateResponse.PrivateKeyPEM)
					if err != nil {
						return errors.New("certmaker-sdk: could not decode private key from base64: " + err.Error())
					}

					err = pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyContents})
					if err != nil {
						return errors.New("certmaker-sdk: could not encode private key to PEM format: " + err.Error())
					}

					privKeyPath, _ := cache.PrivateKeyPath()
					err = os.WriteFile(privKeyPath, b.Bytes(), 0600)
					if err != nil {
						return errors.New("certmaker-sdk: could not write private key file: " + err.Error())
					}

					// immediately cancel the context to stop any running challenge server
					challengeCancel()

					// no need to solve another challenge
					break
				}
			}
		}
	} else if resp.StatusCode == http.StatusCreated {
		// w/o challenge, just write the certificate and private key to file
		certContents, err := base64.StdEncoding.DecodeString(response.CertificatePEM)
		if err != nil {
			return errors.New("certmaker-sdk: could not decode certificate from base64: " + err.Error())
		}

		var b bytes.Buffer
		pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certContents})
		err = cache.SetCertificate(b.Bytes())
		if err != nil {
			return errors.New("certmaker-sdk: could not write certificate file: " + err.Error())
		}

		b.Reset()

		// private key to file
		privateKeyContents, err := base64.StdEncoding.DecodeString(response.PrivateKeyPEM)
		if err != nil {
			return errors.New("certmaker-sdk: could not decode private key from base64: " + err.Error())
		}

		pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyContents})
		err = cache.SetPrivateKey(b.Bytes())
		if err != nil {
			return errors.New("certmaker-sdk: could not write private key file: " + err.Error())
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
func (c *Client) RequestWithCSR(cache Cache, csr *x509.CertificateRequest) error {
	err := cache.Valid(c, defaultMinimumValidity)
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
func (c *Client) RequestRepeatedly(ctx context.Context, cache Cache, cr *SimpleRequest, interval time.Duration) {
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
func (c *Client) RequestRepeatedlyWithCSR(ctx context.Context, cache Cache, csr *x509.CertificateRequest, interval time.Duration) {
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
	c.mut.Lock()
	defer c.mut.Unlock()

	if c.updater == nil || c.updater.cache == nil {
		return nil, fmt.Errorf("updater or cache are nil")
	}

	// first, check whether the cached certificate is still valid
	err := c.updater.cache.Valid(c, c.updater.minValidity)
	if err == nil {
		return c.updater.cache.TLSCertificate()
	}

	// // not a simple request. must have CSR and optionally private key functions set
	// if c.updater.csrFunc != nil && c.updater.privKeyFunc != nil {
	// 	if !c.updater.cache.HasPrivateKey() {
	// 		if c.updater.privKeyFunc != nil {
	// 			privKeyPath, err := c.updater.privKeyFunc()
	// 			if err != nil {
	// 				return nil, fmt.Errorf("error calling private key function: %w", err)
	// 			}

	// 			err = c.updater.cache.CopyPrivateKeyFromFile(privKeyPath)
	// 			if err != nil {
	// 				return nil, fmt.Errorf("error copying private key from file: %w", err)
	// 			}
	// 		} else {
	// 			return nil, fmt.Errorf("private key file is missing and no function to obtain it was supplied")
	// 		}
	// 	}
	// }

	if c.updater.srFunc != nil {
		sr, err := c.updater.srFunc() // fetches the SimpleRequest
		if err != nil {
			return nil, fmt.Errorf("error calling SimpleRequest function: %w", err)
		}
		err = c.Request(c.updater.cache, sr) // orders a new certificate based on the SimpleRequest
		if err != nil {
			return nil, fmt.Errorf("error requesting certificate with SimpleRequest: %w", err)
		}
	} else if c.updater.csrFunc != nil {
		csr, err := c.updater.csrFunc() // fetches the CSR
		if err != nil {
			return nil, fmt.Errorf("error calling CSR function: %w", err)
		}
		err = c.RequestWithCSR(c.updater.cache, csr) // orders a new certificate based on the CSR
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
func (c *Client) DownloadRootCertificate(cache Cache) error {
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

	var rootCertBytes bytes.Buffer
	_, err = io.Copy(&rootCertBytes, resp.Body)
	if err != nil {
		return err
	}

	cache.SetRootCertificate(rootCertBytes.Bytes())

	return nil
}

func (c *Client) setHeader(req *http.Request) {
	req.Header.Set(authenticationHeader, c.token)
	req.Header.Set("Content-Type", "application/json")
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
