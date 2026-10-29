package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	certmaker "github.com/KaiserWerk/CertMaker-Go-SDK"
)

type MyDNS01ChallengeSolver struct {
}

func (m *MyDNS01ChallengeSolver) CanSolve(challengeType string) bool {
	return challengeType == "dns-01"
}

func (m *MyDNS01ChallengeSolver) Setup(ctx context.Context, token string, domains []string) error {
	// execute setup steps, e.g. creating DNS TXT records
	return nil
}

func (m *MyDNS01ChallengeSolver) Solve(ctx context.Context, instanceURL string, challengeID string, setHeader func(*http.Request)) (*certmaker.CertificateResponse, error) {
	// execute solve steps, e.g. verifying DNS TXT records
	return &certmaker.CertificateResponse{}, nil
}

func main() {
	certMakerInstance := "http://localhost:8880"
	token := "<token>"

	solver := &MyDNS01ChallengeSolver{}

	cache, _ := certmaker.NewFileCache()
	client := certmaker.NewClient(certMakerInstance, token, &certmaker.ClientSettings{
		ClientTimeout:   10 * time.Minute,
		ChallengeSolver: solver,
	})

	req := &certmaker.SimpleRequest{
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

	err := client.Request(cache, req)
	if err != nil {
		log.Fatalf("Could not request certificate: %v", err)
	}

	fmt.Println("Certificate requested successfully")
}
