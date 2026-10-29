# CertMaker Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/KaiserWerk/CertMaker-Go-SDK.svg)](https://pkg.go.dev/github.com/KaiserWerk/CertMaker-Go-SDK)

The Golang *software development kit* for the *[CertMaker](https://github.com/KaiserWerk/CertMaker)*.

The SDK allows you to easily obtain and revoke certificates in your custom Go applications. There are quite a few
convenience methods but also some lower level methods for more fine-tuned control.

## Installation

Import it with
```golang
import certmaker "github.com/KaiserWerk/CertMaker-Go-SDK"
```
and either 
```bash
go get github.com/KaiserWerk/CertMaker-Go-SDK
```
or
```bash
go mod tidy
```

## Usage

The `Client`'s purpose is to request and download certificates (and private keys, if any). Supply an API Key and a base URL to the `NewClient()` function. The `Client` requires a `Cache` to function.

There are two different cache implementations. A `FileCache` and a `MemoryCache`. Both cache types have a pseudo-constructor. You can also implement your own, as long as it satisfies the `Cache` interface.
In most cases, a `FileCache` should be preferred for storing certificates and private keys on the filesystem, so they can be read and re-used on app restart.

### Basic setup

```golang
cache, _ := certmaker.NewFileCache()
// do a certificate request before using the paths
// ...

certPath := cache.GetCertificatePath() // e.g. /opt/app-certs/localhost/cert.pem
keyPath := cache.GetPrivateKeyPath() // e.g. /opt/app-certs/localhost/key.pem
http.ListenAndServeTLS(":1234", certPath, keyPath, nil)
```

### Extended setup
To put it all together, here is an example (errors ignored for brevity):
```golang
certMakerInstance := "http://12.34.56.78:8880" // no trailing slash needed
token := "Ar8S71NBblDCMVJD0dkftX36ea5zG7QSI7Q2trkEVwBZpqsQzNTFneSgMcM1" // taken from the account info

solver := &MyDNS01ChallengeSolver{}

cache := certmaker.NewMemoryCache()
client := certmaker.NewClient(certMakerInstance, token, &certmaker.ClientSettings{
    // a custom *http.Transport{} for the HTTP client
    Transport:     nil, 
    // the timeout for the HTTP client (default is 5 seconds)
    ClientTimeout: 4 * time.Second,
    // when checking if a local certificate is still valid, also checks with the CertMaker API whether it's been revoked
    StrictMode:    true,
    // the port is only required if the verification challenge HTTP-01 (see below) is enabled on the remote side and make sure it is open
    ChallengePort: 8000, 
    // Supply the actual challenge solver(s) to be used for solving verification challenges
    // Implement your own solvers by satisfying the ChallengeSolver interface
    ChallengeSolver: []ChallengeSolver{solver},
})
```

### More examples

Please refer to the `examples` directory.

## The HTTP-01 challenge

CertMaker uses a slightly simplified version of the HTTP-01 challenge.
If the challenge is enabled on the server side, a token has to be reachable via every DNS name or IP
address. This means that at least one port must be open and free to bind to to be used to solve the verification challenge. You can supply it using the `certmaker.ClientSettings{}`.
Email addresses have no relevance in the verification challenge, only IP addresses and domain names.

## The DNS-01 challenge

CertMaker also supports the DNS-01 challenge, which requires creating specific DNS records to prove domain ownership. You need to implement a `ChallengeSolver` that can handle the DNS-01 challenge for your DNS provider.
This challenge is only available for domain names, not for IP addresses.

In short, the DNS-01 challenge requires you to prove domain ownership by creating a TXT record with the `_certmaker_challenge` name and a specific value provided by the challenge. Your `ChallengeSolver` implementation will handle the creation and verification of these records with your DNS provider.

You may use the existing `OVHDNS01ChallengeSolver` as a ready-made implementation for handling the DNS-01 challenge with OVH DNS.

## Request types

There are two types of certificate requests. 

1. A `SimpleRequest` requests a private key with the corresponding certificate with the supplied request information.
2. A `*x509.CertificateRequest` is created from an existing private key, so just a certificate is requested. This is the default that is used by most certificate authorities.

## Convenience methods

`RequestForDomains(cache Cache, domains []string, days int) error` tries to obtain a 
certificate and private key with a validity of `days` for every DNS name in `domains` and writes the downloaded data into `cache`.

`RequestForIPs(cache Cache, ips []string, days int) error` tries to obtain a
certificate and private key for with a validity of `days` every IP address in `ips` and writes the downloaded data into `cache`.

`RequestForEmails(cache Cache, emails []string, days int) error` tries to obtain a
certificate and private key for with a validity of `days` every email address in `emails` and writes the downloaded data into `cache`.

## Lower-level methods

`Request(cache Cache, cr *SimpleRequest) error` requires a `SimpleRequest` to obtain
a certificate and private key into `cache`. This method allows for more fine-grained control.

Example:
```golang
// Just omit what is not needed, e.g. the email addresses
err = client.Request(cache, &certmaker.SimpleRequest{
    Domains:        []string{"localhost", "myhost.com"},
    IPs:            []string{"127.0.0.1", "::1"},
    EmailAddresses: []string{"some@myhost.org", "other@myhost.com"}
    Days: 25, // the desired validity in days
    Subject: certmaker.SimpleRequestSubject{
        CommonName:    "myhost.com",
        Organization:  "KAISERWERK Ltd.",
        Country:       "Germany",
        Province:      "NRW",
        Locality:      "Cologne",
        StreetAddress: "Random Street 1337",
        PostalCode:    "12345",
    },
})
```

`RequestWithCSR(cache Cache, csr *x509.CertificateRequest) error` takes a *Certificate Signing Request*
and tries to obtain a certificate (no private key) as requested and writes the
downloaded data into `cache`.

Example:
```golang
var data []byte // from file or HTTP request or byte buffer or...
b, _ := pem.Decode(data) // this step might not be necessary, depending on data
csr, _ := x509.ParseCertificateRequest(b.Bytes)
err = client.RequestWithCSR(cache, csr)
```

## Special utility methods

`SetupWithSimpleRequest(cache Cache, srFunc func() (*SimpleRequest, error))` and 
`SetupWithCSR(cache Cache, csrFunc func() (*x509.CertificateRequest, error))` are preparatory calls to make before using ``GetCertificateFunc``.
Supply a function which returns either one of the requests and an error. This is to allow the request data to be different for each request for a new certificate.

`GetCertificateFunc(chi *tls.ClientHelloInfo) (*tls.Certificate, error)` can be used by anything 
that uses a `&tls.Config{}` to read a certificate from a dynamic source. 
Also, certificates are automatically re-read when required (shortly 
before expiration at the latest). That means fire and forget, no need for loops or cronjobs.

This feature is __Work in Progress__ and does not yet work as intended!

Example: 
```golang
client.SetupWithSimpleRequest(cache, &certmaker.SimpleRequest{
    Domains:        []string{"localhost"},
    IPs:            []string{"127.0.0.1", "::1"},
    EmailAddresses: []string{"some@mail.org", "other@mail.com"},
    Subject: certmaker.SimpleRequestSubject{
        Organization:  "KAISERWERK Ltd.",
        Country:       "Germany",
        Province:      "NRW",
        Locality:      "Cologne",
        StreetAddress: "Random Street 1337",
        PostalCode:    "12345",
    },
    Days: 25,
})

// set up the HTTP server
router := http.NewServeMux()
router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprint(w, "Hello World!")
})
srv := http.Server{
    Addr: ":1337",
    Handler: router,
    TLSConfig: &tls.Config{
        GetCertificate: client.GetCertificateFunc,
    }, 
}

log.Fatal(srv.ListenAndServeTLS("", "")) // leave these two fields empty
// now make a call to https://localhost:1337/ (https, not http!)
// If you get an error message stating that the certificate is invalid, that just
// means that you didn't install the root certificate yet.
```
