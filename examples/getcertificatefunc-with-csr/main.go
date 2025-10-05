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
	token := "c2c56c2dfd076045b0bf356f7ce600c2039e9131bf7043397bdf1e242c0d638d697459c83e127b6b"

	cache, _ := certmaker.NewCache()
	client := certmaker.NewClient(certMakerInstance, token, &certmaker.ClientSettings{
		ClientTimeout: 10 * time.Minute,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	privKeyFile := "./some/dir/key.pem"
	csrFile := "./some/dir/csr.pem"
	cont, err := os.ReadFile(csrFile)
	if err != nil {
		log.Fatal(err)
	}

	// Only the first PEM block is used; rest is ignored.
	block, rest := pem.Decode(cont)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		log.Fatal("failed to decode PEM block containing certificate request")
	}
	_ = rest // rest is ignored intentionally

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	client.SetupWithCSR(
		cache,
		func() (*x509.CertificateRequest, error) {
			return csr, nil
		},
		func() (string, error) {
			return privKeyFile, nil
		},
		3*time.Hour,
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
