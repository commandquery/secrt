package main

import (
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

func (server *SecretServer) handleGetChallenge(r *http.Request, _ *jtp.None) (*secrt.ChallengeRequest, error) {
	challengeRequest, err := secrt.NewChallenge(Config.ChallengeSize, server.SignPrivateKey)
	if err != nil {
		return nil, jtp.InternalServerError(err)
	}

	return challengeRequest, nil
}
