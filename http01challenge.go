package certmaker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

func (c *HTTP01Challenge) Solve(httpClient *http.Client, cache *FileCache) error {
	solveURL := fmt.Sprintf("%s/api/v1/http-01/%s/solve", c.instanceURL, c.challengeID)

	req, err := http.NewRequest(http.MethodGet, solveURL, nil)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("certmaker-sdk: failed to solve challenge: expected status code 200, got %d", resp.StatusCode)
	}

	var response CertificateResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return err
	}

	if response.Error != "" {
		return fmt.Errorf("certmaker-sdk: failed to solve challenge with remote error: %s", response.Error)
	}

	err = os.WriteFile(cache.CertificatePath(), []byte(response.CertificatePem), 0600)
	if err != nil {
		return err
	}

	if response.PrivateKeyPem != "" {
		err = os.WriteFile(cache.PrivateKeyPath(), []byte(response.PrivateKeyPem), 0600)
		if err != nil {
			return err
		}
	}

	return nil
}
