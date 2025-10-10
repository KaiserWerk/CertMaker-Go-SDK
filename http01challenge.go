package certmaker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const wellKnownPath2 = "/.well-known/certmaker-challenge/token"

type HTTP01Challenge struct {
	instanceURL   string
	challengeID   string
	challengePort uint16
	token         string
}

func NewHTTP01Challenge(instanceURL, challengeID string, challengePort uint16, token string) *HTTP01Challenge {
	return &HTTP01Challenge{
		instanceURL:   instanceURL,
		challengeID:   challengeID,
		challengePort: challengePort,
		token:         token,
	}
}

func (c *HTTP01Challenge) Type() string {
	return "http-01"
}

func (c *HTTP01Challenge) Setup(ctx context.Context) error {
	// serve the token on the challenge port under the well-known path
	router := http.NewServeMux()
	router.HandleFunc(wellKnownPath2, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(c.token))
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

func (c *HTTP01Challenge) Solve(ctx context.Context, httpClient *http.Client) (*CertificateResponse, error) {
	solveURL := fmt.Sprintf("%s/api/v1/http-01/%s/solve", c.instanceURL, c.challengeID)

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
