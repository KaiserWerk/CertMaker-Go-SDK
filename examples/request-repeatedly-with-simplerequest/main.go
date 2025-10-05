package main

import (
	"context"
	"os"
	"os/signal"
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	sr := certmaker.SimpleRequest{
		Domains:        []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"user@example.com"},
		IPs:            []string{"127.0.0.1"},

		Days: 88,
		Subject: certmaker.SimpleRequestSubject{
			CommonName:    "example.com",
			Organization:  "Example Inc.",
			Country:       "DE",
			Locality:      "Berlin",
			Province:      "Brandenburg",
			PostalCode:    "12345",
			StreetAddress: "Example Street 1",
		},
	}

	go client.RequestRepeatedly(ctx, cache, &sr, 30*time.Second)

	<-ctx.Done()
}
