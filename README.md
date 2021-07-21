# CertMaker Go SDK

The Golang *software development kit* for the *[CertMaker](https://github.com/KaiserWerk/CertMaker)*.

The SDK allows you to easily obtain and revoke certificates in your custom Go applications. There a quite a few
convenience functions but also some lower level function for more fine-tuned control.

There are two important structs you should understand before diving into development, the *Client* and the *Cache*:

```golang
type Client struct {
	// unexported fields
}
```

The ``Client``'s purpose is to request and download certificates (and private keys, if any). That's why you can supply
an API Key and a base URL to the ``NewClient()`` function. The ``Client`` usually requires a valid ``Cache`` to work
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
to interact with the filesystem.

## The DNS name/IP address verification challenge

If the challenge is enabled on the server side, a token has to be reachable via every DNS name or IP
address. This means that at least one port must be open to be used for the solving part.

## Convenience functions

``RequestForDomains(cache *Cache, domains []string, days int) error`` tries to request and download a certificate for 
every DNS name in domains.