package certmaker

import "fmt"

type DNS01Challenge struct {
	instanceURL string
	challengeID string
	domain      string
	token       string
}

func (c *DNS01Challenge) SolveURL() string {
	return fmt.Sprintf("%s/api/v1/dns-01/%s/solve", c.instanceURL, c.challengeID)
}

func (c *DNS01Challenge) Type() string {
	return "dns-01"
}

func (c *DNS01Challenge) Token() string {
	return c.token
}
