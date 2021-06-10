package certmaker

// CertificateRequest defines a request for a new certificate and private key. The field Subject
// is optional and can be omitted. Days can be between 1 and 182. If the value is higher than 182, then it
// will be set to 182 on the server side. If it is lower than 1, it will be set to 1 on the server side.
//
// You can either supply zero or more Domains, zero or more IPs in v4 format and zero or more EmailAddresses.
type CertificateRequest struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	EmailAddresses  []string `json:"emails"`
	Subject struct {
		Organization  string `json:"organization"`
		Country       string `json:"country"`
		Province      string `json:"province"`
		Locality      string `json:"locality"`
		StreetAddress string `json:"street_address"`
		PostalCode    string `json:"postal_code"`
	} `json:"subject,omitempty"`
	Days     int    `json:"days"`
}
