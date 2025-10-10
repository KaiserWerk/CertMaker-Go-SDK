package certmaker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ovh/go-ovh/ovh"
)

const ovhBaseURL = "https://eu.api.ovh.com/v1"

type OVHDNS01Challenge struct {
	instanceURL string
	challengeID string
	domain      string
	token       string
	recordID    int
}

func (c *OVHDNS01Challenge) Type() string {
	return "dns-01"
}

func (c *OVHDNS01Challenge) Setup(ctx context.Context) error {
	// use the DNS provider's API to create a TXT record for the domain with the token
	client, err := ovh.NewClient(
		"ovh-eu",
		os.Getenv("OVH_APP_KEY"),
		os.Getenv("OVH_APP_SECRET"),
		os.Getenv("OVH_CONSUMER_KEY"),
	)
	if err != nil {
		return err
	}

	// create the TXT record
	newRecord := DNSRecord{
		FieldType: "TXT",
		SubDomain: "_certmaker_challenge",
		Target:    c.token,
	}
	b, err := json.Marshal(newRecord)
	if err != nil {
		return err
	}
	var response DNSRecordResponse
	err = client.PostWithContext(ctx, ovhBaseURL+"/domain/zone/"+c.domain+"/record", bytes.NewBuffer(b), &response)
	if err != nil {
		return err
	}

	// the ID of the new record must be stored to delete it later
	c.recordID = response.ID

	// refresh the zone to apply the changes
	return client.PostWithContext(ctx, ovhBaseURL+"/domain/zone/"+c.domain+"/refresh", nil, nil)
}

func (c *OVHDNS01Challenge) Solve(ctx context.Context) (*CertificateResponse, error) {
	solveURL := fmt.Sprintf("%s/api/v1/dns-01/%s/solve", c.instanceURL, c.challengeID)

	httpClient := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, solveURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("certmaker-sdk: expected status code 201, got %d", resp.StatusCode)
	}

	var response CertificateResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	// clean up the DNS record
	client, err := ovh.NewClient(
		"ovh-eu",
		os.Getenv("OVH_APP_KEY"),
		os.Getenv("OVH_APP_SECRET"),
		os.Getenv("OVH_CONSUMER_KEY"),
	)
	if err != nil {
		return nil, err
	}

	err = client.DeleteWithContext(ctx, ovhBaseURL+"/domain/zone/"+c.domain+"/record/"+fmt.Sprint(c.recordID), nil)
	if err != nil {
		return nil, err
	}

	// refresh the zone to apply the changes
	err = client.PostWithContext(ctx, ovhBaseURL+"/domain/zone/"+c.domain+"/refresh", nil, nil)

	return &response, err
}
