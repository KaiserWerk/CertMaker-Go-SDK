package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"time"

	certmaker "github.com/KaiserWerk/CertMaker-Go-SDK"
)

func main() {
	certMakerInstance := "http://localhost:8880" // replace with your actual CertMaker instance URL
	token := "<token>"                           // replace with your actual token

	cache, _ := certmaker.NewCache()
	client := certmaker.NewClient(certMakerInstance, token, &certmaker.ClientSettings{
		ClientTimeout: 10 * time.Minute,
	})

	// have some CSR file, e.g. by running:
	// openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out csr.pem -subj "/CN=example.com"

	// read CSR from file
	csrFile := "./some/dir/csr.pem"
	cont, err := os.ReadFile(csrFile)
	if err != nil {
		log.Fatal(err)
	}

	// Only the first PEM block is used; rest is ignored. (Usually, there is no rest when handling CSRs.)
	block, rest := pem.Decode(cont)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		log.Fatal("failed to decode PEM block containing certificate request")
	}
	_ = rest // rest is ignored intentionally

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	err = client.RequestWithCSR(cache, csr)
	if err != nil {
		log.Fatal(err)
	}
}
