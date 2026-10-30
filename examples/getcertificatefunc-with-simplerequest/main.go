package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	certmaker "github.com/KaiserWerk/CertMaker-Go-SDK"
)

func main() {
	certMakerInstance := "http://localhost:8880"
	token := "<token>"

	cache, _ := certmaker.NewFileCache(".")
	client := certmaker.NewClient(certMakerInstance, token, &certmaker.ClientSettings{
		ClientTimeout: 2 * time.Minute,
	})

	sr := &certmaker.SimpleRequest{
		Domains:  []string{"localhost", "myapp.local"},
		IPs:      []string{"127.0.0.1"},
		Validity: 3 * time.Minute,
		Subject: certmaker.SimpleRequestSubject{
			Organization:  "Example Inc.",
			Country:       "DE",
			Locality:      "Berlin",
			Province:      "Brandenburg",
			PostalCode:    "12345",
			StreetAddress: "Example Street 1",
		},
	}

	client.SetupWithSimpleRequest(cache, 1*time.Minute, func() (*certmaker.SimpleRequest, error) {
		return sr, nil
	})

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			fmt.Printf("Received ClientHello from %s\n", info.ServerName)
			cert, err := client.GetCertificateFunc(info)
			if err != nil {
				return nil, err
			}
			fmt.Printf("loaded cert sn=%v\n", cert.Leaf.SerialNumber)

			return cert, nil
		},
	}
	handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	})
	server := http.Server{
		Addr:      ":8443",
		Handler:   handlerFunc,
		TLSConfig: tlsConfig,
	}
	fmt.Println("Starting server on https://localhost:8443")
	server.ListenAndServeTLS("", "")
}
