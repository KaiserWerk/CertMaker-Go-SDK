package certmaker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const wellKnownPath2 = "/.well-known/certmaker-challenge/token"

type HTTP01ChallengeSolver struct {
	ChallengePort uint16
}

func (c *HTTP01ChallengeSolver) CanSolve(challengeType string) bool {
	return challengeType == "http-01"
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
		Addr:    fmt.Sprintf(":%d", c.ChallengePort),
		Handler: router,
	}
	go server.ListenAndServe()
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(ctx)
	}()
	return nil
}

func (c *HTTP01ChallengeSolver) Solve(ctx context.Context, instanceURL, challengeID string, setHeader func(*http.Request)) (*CertificateResponse, error) {
	solveURL := fmt.Sprintf("%s/api/v1/http-01/%s/solve", instanceURL, challengeID)

	httpClient := &http.Client{Timeout: 120 * time.Second}

	request := HTTP01ChallengeRequest{
		ChallengePort: c.ChallengePort,
	}
	j, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, solveURL, bytes.NewBuffer(j))
	if err != nil {
		return nil, err
	}
	setHeader(req)

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
