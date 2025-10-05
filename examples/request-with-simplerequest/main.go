package main

import (
	"fmt"
	"log"
	"time"

	certmaker "github.com/KaiserWerk/CertMaker-Go-SDK"
)

func main() {
	certMakerInstance := "http://localhost:8880"
	token := "<token>"

	cache, _ := certmaker.NewCache()
	client := certmaker.NewClient(certMakerInstance, token, &certmaker.ClientSettings{
		ClientTimeout: 10 * time.Minute,
	})

	sr := &certmaker.SimpleRequest{
		Domains:        []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"user@example.com"},
		IPs:            []string{"127.0.0.1"},

		Days: 100,
		Subject: certmaker.SimpleRequestSubject{
			Organization:  "Example Inc.",
			Country:       "DE",
			Locality:      "Berlin",
			Province:      "Brandenburg",
			PostalCode:    "12345",
			StreetAddress: "Example Street 1",
		},
	}

	err := client.Request(cache, sr)
	if err != nil {
		log.Fatalf("Could not request certificate: %v", err)
	}

	fmt.Println("Certificate requested successfully")
}
