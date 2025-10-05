package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
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

	go client.RequestRepeatedlyWithCSR(ctx, cache, csr, 30*time.Second)
	<-ctx.Done()
}
