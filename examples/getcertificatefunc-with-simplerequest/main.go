package main

import (
	"context"
	"crypto/tls"
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

	sr := &certmaker.SimpleRequest{
		Domains:        []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"user@example.com"},
		IPs:            []string{"127.0.0.1"},

		Days: 1,
		Subject: certmaker.SimpleRequestSubject{
			Organization:  "Example Inc.",
			Country:       "DE",
			Locality:      "Berlin",
			Province:      "Brandenburg",
			PostalCode:    "12345",
			StreetAddress: "Example Street 1",
		},
	}

	client.SetupWithSimpleRequest(cache, func() (*certmaker.SimpleRequest, error) { return sr, nil }, 23*time.Hour)

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
