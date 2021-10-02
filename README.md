# CertMaker Go SDK

The Golang *software development kit* for the *[CertMaker](https://github.com/KaiserWerk/CertMaker)*.

The SDK allows you to easily obtain and revoke certificates in your custom Go applications. There are quite a few
convenience methods but also some lower level methods for more fine-tuned control.

## Installation



## Usage

There are two important structs you should understand before diving into development, the *Client* and the *Cache*:

```golang
type Client struct {
	// unexported fields
}
```

The ``Client``'s purpose is to request and download certificates (and private keys, if any). That's why you can supply
an API Key and a base URL to the ``NewClient()`` function. The ``Client`` requires a valid ``Cache`` to work
properly.


```golang
type Cache struct {
    CacheDir                string
    PrivateKeyFilename      string
    CertificateFilename     string
    RootCertificateFilename string
}
```

Unlike the ``Client``, the ``Cache`` only has exported fields which can be manipulated by you, the developer.
There is also a ``NewCache()`` function, which sets up a ``Cache`` with useful defaults. The ``Cache`` is required
to interact with the filesystem. *CacheDir* is the directory (without filename) where the certificate/private key reside, 
``PrivateKeyFilename`` contains just the private key file name, ``CertificateFilename`` contains just the
certificate file name.


There are two methods to obtain the complete certificate/private key paths:
```golang
certPath := cache.GetCertificatePath() // e.g. /opt/app-certs/localhost/cert.pem
keyPath := cache.GetPrivateKeyPath() // e.g. /opt/app-certs/localhost/key.pem
http.ListenAndServeTLS(":1234", certPath, keyPath, nil)
```

### Usage example
To put it all together, here is an example (errors ignored for brevity):
```golang
certMakerInstance := "http://12.34.56.78:8880" // no trailing slash needed
token := "Ar8S71NBblDCMVJD0dkftX36ea5zG7QSI7Q2trkEVwBZpqsQzNTFneSgMcM1" // taken from the account info

cache, _ := certmaker.NewCache()
client := certmaker.NewClient(certMakerInstance, token, nil)
```
You can modify the ``Client``'s underlying HTTP client and other options by supplying client settings as third
parameter, e.g.:

```golang
// ...
cache, _ := certmaker.NewCache()
client := certmaker.NewClient(certMakerInstance, token, &certmaker.ClientSettings{
    Transport:     nil, // for the HTTP client
    ClientTimeout: 4 * time.Second, // for the HTTP client
    StrictMode:    true, // when checking if a local certificate is still valid, also check with the CertMaker API if it's been revoked
    ChallengePort: 8000, // make sure the port is open
})
```

## The DNS name/IP address verification challenge

If the challenge is enabled on the server side, a token has to be reachable via every DNS name or IP
address. This means that at least one port must be open to be used for the solving part. You can supply
it using the ``certmaker.ClientSettings{}``

## Convenience methods

``RequestForDomains(cache *Cache, domains []string, days int) error`` tries to obtain a 
certificate and private key with a validity of ``days`` for every DNS name in ``domains`` and writes the 
downloaded data into ``cache``.

``RequestForIps(cache *Cache, ips []string, days int) error`` tries to obtain a
certificate and private key for with a validity of ``days`` every IP address in ``ips`` and writes the
downloaded data into ``cache``.

``RequestForEmails(cache *Cache, emails []string, days int) error`` tries to obtain a
certificate and private key for with a validity of ``days`` every email address in ``emails`` and writes the
downloaded data into ``cache``.

## Lower-level methods

``Request(cache *Cache, cr *SimpleRequest) error`` requires a ``SimpleRequest`` to obtain
a certificate and private key into ``cache``. This method allows for more fine-grained control.

Example:
```golang
// Just omitwhat is not needed, e.g. the email addresses
err = client.Request(cache, &certmaker.SimpleRequest{
    Domains:        []string{"localhost"},
    IPs:            []string{"127.0.0.1", "::1"},
    EmailAddresses: []string{"some@mail.org", "other@mail.com"}
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
```

``RequestWithCSR(cache *Cache, csr *x509.CertificateRequest) error`` takes a *Certificate Signing Request*
and tries to obtain a certificate (no private key) as requested and writes the
downloaded data into ``cache``.

Example:
```golang
var data []byte // from file or HTTP request or byte buffer or...
b, _ := pem.Decode(data)
csr, _ := x509.ParseCertificateRequest(b.Bytes)
err = client.RequestWithCSR(cache, csr)
```

## Special utility methods

``SetupWithSimpleRequest(cache *Cache, sr *SimpleRequest)`` and 
``SetupWithCSR(cache *Cache, csr *x509.CertificateRequest)`` are preparing calls to make 
before using ``GetCertificateFunc``.

``GetCertificateFunc(chi *tls.ClientHelloInfo) (*tls.Certificate, error)`` can be used by an 
``http.Server`` struct (actually anything that uses a ``*tls.Config{}``) to read certificate 
from an arbitrary source. Also, certificates are automatically re-read when required (usually shortly 
before expiration). That means fire and forget, no need for loops or cronjobs.

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

log.Fatal(srv.ListenAndServeTLS("", "")) 
// now make a call to https://localhost:1337/
// If you get an error message stating that the certificate is invalid, that just
// means that you didn't install the root certificate yet.
```