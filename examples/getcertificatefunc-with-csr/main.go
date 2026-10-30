package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	certmaker "github.com/KaiserWerk/CertMaker-Go-SDK"
)

func main() {
	certMakerInstance := "http://localhost:8880"
	token := "<token>"

	cache := certmaker.NewMemoryCache()
	client := certmaker.NewClient(certMakerInstance, token, &certmaker.ClientSettings{
		ClientTimeout: 10 * time.Minute,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	privKeyFile := "./some/dir/key.pem"
	privKeyBytes, err := os.ReadFile(privKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(privKeyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}
	_ = cache.SetPrivateKey(block.Bytes)
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	_ = privKey

	csrFile := "./some/dir/csr.pem"
	csrFileBytes, err := os.ReadFile(csrFile)
	if err != nil {
		log.Fatal(err)
	}

	// Only the first PEM block is used; rest is ignored.
	block, _ = pem.Decode(csrFileBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		log.Fatal("failed to decode PEM block containing certificate request")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	client.SetupWithCSR(
		cache,
		3*time.Hour,
		// set func to return the CSR, allows for differing CSRs to be used dynamically if needed
		func() (*x509.CertificateRequest, error) {
			return csr, nil
		},
		nil, // not set, will be taken from cache if available
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})
	server := &http.Server{
		Addr:    ":25000",
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: client.GetCertificateFunc,
		},
	}
	go server.ListenAndServeTLS("", "")

	<-ctx.Done()
}
