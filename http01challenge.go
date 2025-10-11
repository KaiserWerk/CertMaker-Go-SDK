package certmaker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const wellKnownPath2 = "/.well-known/certmaker-challenge/token"

type HTTP01ChallengeSolver struct {
	challengePort uint16
}

func (c *HTTP01ChallengeSolver) Setup(ctx context.Context, token string, domains []string) error {
	if len(domains) == 0 {
		return ErrNoDomainsProvided
	}

	// serve the token on the challenge port under the well-known path
	router := http.NewServeMux()
	router.HandleFunc(wellKnownPath2, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(token))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", c.challengePort),
		Handler: router,
	}
	go server.ListenAndServe()
	<-ctx.Done()
	_ = server.Shutdown(ctx)
	return nil
}

func (c *HTTP01ChallengeSolver) Solve(ctx context.Context, instanceURL, challengeID string) (*CertificateResponse, error) {
	solveURL := fmt.Sprintf("%s/api/v1/http-01/%s/solve", instanceURL, challengeID)

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

	return &response, nil
}
