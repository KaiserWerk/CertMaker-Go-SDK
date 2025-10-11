package certmaker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ovh/go-ovh/ovh"
)

const (
	ovhBaseURL = "https://eu.api.ovh.com/v1"

	ovhAppKeyEnv      = "CM_OVH_APP_KEY"
	ovhAppSecretEnv   = "CM_OVH_APP_SECRET"
	ovhConsumerKeyEnv = "CM_OVH_CONSUMER_KEY"
)

type OVHDNS01ChallengeSolver struct {
	recordsToDelete map[string]int // map of domain to recordID
}

func (c *OVHDNS01ChallengeSolver) Type() string {
	return "dns-01"
}

func (c *OVHDNS01ChallengeSolver) Setup(ctx context.Context, token string, domains []string) error {
	c.recordsToDelete = make(map[string]int)

	if len(domains) == 0 {
		return ErrNoDomainsProvided
	}

	// use OVH EU API to create a TXT record for the domain with the token
	client, err := ovh.NewClient(
		"ovh-eu",
		os.Getenv(ovhAppKeyEnv),
		os.Getenv(ovhAppSecretEnv),
		os.Getenv(ovhConsumerKeyEnv),
	)
	if err != nil {
		return err
	}

	// create the TXT record
	newRecord := DNSRecord{
		FieldType: "TXT",
		SubDomain: "_certmaker_challenge",
		Target:    token,
	}
	b, err := json.Marshal(newRecord)
	if err != nil {
		return err
	}

	for _, domain := range domains {
		var response DNSRecordResponse
		err = client.PostWithContext(ctx, ovhBaseURL+"/domain/zone/"+domain+"/record", bytes.NewBuffer(b), &response)
		if err != nil {
			return err
		}

		// the ID of the new record must be stored to delete it later
		c.recordsToDelete[domain] = response.ID

		// refresh the zone to apply the changes
		err = client.PostWithContext(ctx, ovhBaseURL+"/domain/zone/"+domain+"/refresh", nil, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *OVHDNS01ChallengeSolver) Solve(ctx context.Context, instanceURL, challengeID string) (*CertificateResponse, error) {
	solveURL := fmt.Sprintf("%s/api/v1/dns-01/%s/solve", instanceURL, challengeID)

	httpClient := &http.Client{Timeout: 15 * time.Minute}
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
		os.Getenv(ovhAppKeyEnv),
		os.Getenv(ovhAppSecretEnv),
		os.Getenv(ovhConsumerKeyEnv),
	)
	if err != nil {
		return nil, err
	}

	for domain, recordID := range c.recordsToDelete {
		err = client.DeleteWithContext(ctx, ovhBaseURL+"/domain/zone/"+domain+"/record/"+fmt.Sprint(recordID), nil)
		if err != nil {
			return nil, err
		}

		// refresh the zone to apply the changes
		err = client.PostWithContext(ctx, ovhBaseURL+"/domain/zone/"+domain+"/refresh", nil, nil)
		if err != nil {
			return nil, err
		}
	}

	return &response, err
}

func cleanDomainList(domains []string) []string {
	for index, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			domains[index] = domain[2:]
		}
	}

	uniqueDomains := make(map[string]struct{})
	for _, domain := range domains {
		uniqueDomains[domain] = struct{}{}
	}

	cleaned := make([]string, 0, len(uniqueDomains))
	for domain := range uniqueDomains {
		cleaned = append(cleaned, domain)
	}

	return cleaned
}
