package certmaker

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Cache represents local directory and file paths for certificates and private keys
type Cache struct {
	CacheDir                string
	PrivateKeyFilename      string
	CertificateFilename     string
	RootCertificateFilename string
}

// NewCache returns a *Cache with default values: CacheDir is .certs,
// CertificateFilename is cert.pem, PrivateKeyFilename is key.pem
func NewCache() (*Cache, error) {
	cache := Cache{}
	baseDir, err := filepath.Abs(".")
	if err != nil {
		return nil, err
	}
	cache.CacheDir = filepath.Join(baseDir, ".certs")
	cache.CertificateFilename = "cert.pem"
	cache.PrivateKeyFilename = "key.pem"
	cache.RootCertificateFilename = "root-cert.pem"

	return &cache, nil
}

func (c *Cache) SetDir(dir string) error {
	baseDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	c.CacheDir = baseDir
	return nil
}

// GetCertificatePath returns the full path the Cache's certificate file
func (c *Cache) GetCertificatePath() string {
	return filepath.Join(c.CacheDir, c.CertificateFilename)
}

// GetPrivateKeyPath returns the full path the Cache's private key file
func (c *Cache) GetPrivateKeyPath() string {
	return filepath.Join(c.CacheDir, c.PrivateKeyFilename)
}

// GetRootCertificatePath returns the full path the Cache's root certificate file
// Usually there is no need to touch that at all
func (c *Cache) GetRootCertificatePath() string {
	return filepath.Join(c.CacheDir, c.RootCertificateFilename)
}

func (c *Cache) GetTlsCertificate() (*tls.Certificate, error) {
	if !fileExists(c.GetPrivateKeyPath()) {
		return nil, fmt.Errorf("private key file missing")
	}

	if !fileExists(c.GetCertificatePath()) {
		return nil, fmt.Errorf("certificate file missing")
	}

	tlsCert, err := tls.LoadX509KeyPair(c.GetCertificatePath(), c.GetPrivateKeyPath())
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func (c *Cache) GetRootCertificate() (*x509.Certificate, error) {
	if !c.hasRootCertificate() {
		return nil, fmt.Errorf("root certificate file does not exist")
	}

	cont, err := ioutil.ReadFile(c.GetRootCertificatePath())
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(cont)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Valid returns whether the certificate in *Cache is valid (file exists, it is not expired, and if strictmode
// is enabled, also checks if it is revoked)
func (c *Cache) Valid(client *Client) bool {
	if !fileExists(c.GetCertificatePath()) {
		return false
	}

	cont, err := ioutil.ReadFile(c.GetCertificatePath())
	if err != nil {
		return false
	}

	block, _ := pem.Decode(cont)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	diff := cert.NotAfter.Sub(time.Now())
	if diff.Hours() < 24*minCertValidityDays {
		return false
	}

	if client.strictMode {
		err = nil
		fmt.Println("strict mode enabled")
		if !c.hasRootCertificate() {
			err = client.DownloadRootCertificate(c)
			if err != nil {
				fmt.Println("could not download root cert")
				return false
			}
		}

		rootCert, err := c.GetRootCertificate()
		if err == nil {
			ocspReq, err := ocsp.CreateRequest(cert, rootCert, &ocsp.RequestOptions{
				Hash: crypto.SHA512,
			})
			if err == nil {
				req, err := http.NewRequest(http.MethodPost, client.baseUrl+ocspStatusPath, bytes.NewBuffer(ocspReq))
				if err == nil {
					req.Header.Set("Content-Type", "application/ocsp-request")
					req.Header.Set("Accept", "application/ocsp-response")
					resp, err := client.httpClient.Do(req)
					if err == nil {
						defer resp.Body.Close()
						var b bytes.Buffer
						_, err = io.Copy(&b, resp.Body)
						if err == nil {
							ocspResp, err := ocsp.ParseResponse(b.Bytes(), rootCert)
							if err == nil {
								if ocspResp.Status != ocsp.Good && ocspResp.Status != ocsp.Unknown {
									fmt.Println("status is neither good nor unknown!")
									return false
								}
								fmt.Println("certificate validated!")
							} else {
								fmt.Println("could not parse response: " + err.Error())
							}
						} else {
							fmt.Println("could not copy: " + err.Error())
						}
					} else {
						fmt.Println("could not execute request: " + err.Error())
					}
				} else {
					fmt.Println("could not create request: " + err.Error())
				}
			} else {
				fmt.Println("could not create OCSP request: " + err.Error())
			}
		} else {
			fmt.Println("could not get root certificate: " + err.Error())
		}

		if err != nil {
			fmt.Println("strict mode error: " + err.Error())
			return false
		}
	}

	return true
}

func (c *Cache) hasRootCertificate() bool {
	return fileExists(c.GetRootCertificatePath())
}
