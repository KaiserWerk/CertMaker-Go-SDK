package certmaker

type CombinedResolver struct{}

func (cr *CombinedResolver) SolveChallenges(c *Client, challenges []Challenge) error {
	for _, challenge := range challenges {
		if challenge.Type == "http-01" {
			err := c.resolveHTTPChallenge(challenge.Token)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
