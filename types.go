package certmaker

import (
	"crypto/x509"
	"net/http"
	"time"
)

// SimpleRequest defines a request for a new certificate and private key. The field Subject
// is optional and can be omitted. Days can be between 1 and 182. If the value is higher than 182, then it
// will be set to 182 on the server side. If it is lower than 1, it will be set to 1 on the server side.
//
// You can either supply zero or more Domains, zero or more IPs and zero or more EmailAddresses.
type SimpleRequest struct {
	Domains        []string             `json:"domains"`
	IPs            []string             `json:"ips"`
	EmailAddresses []string             `json:"emails"`
	Subject        SimpleRequestSubject `json:"subject,omitempty"`
	Days           int                  `json:"days"`
}

// SimpleRequestSubject represents the subject of a SimpleRequest
type SimpleRequestSubject struct {
	Organization  string `json:"organization"`
	Country       string `json:"country"`
	Province      string `json:"province"`
	Locality      string `json:"locality"`
	StreetAddress string `json:"street_address"`
	PostalCode    string `json:"postal_code"`
}

// Updater contains data relevant to automatic certificate updating
type Updater struct {
	cache         *Cache
	simpleRequest *SimpleRequest
	csr           *x509.CertificateRequest
}

// ClientSettings represent meta data useful for altering the behaviour of a *Client
type ClientSettings struct {
	Transport     *http.Transport
	ClientTimeout time.Duration
}
