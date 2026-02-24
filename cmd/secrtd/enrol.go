package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

// Verify the challenge. If the challenge is invalid, set the HTTP request status and return an error.
func (server *SecretServer) verifyChallenge(r *http.Request) error {
	// enrolment requires a challenge and nonce header.
	challenge64 := r.Header.Get("Challenge")
	if challenge64 == "" {
		return jtp.ForbiddenError(fmt.Errorf("no challenge provided"))
	}

	nonceStr := r.Header.Get("Nonce")
	if nonceStr == "" {
		return jtp.ForbiddenError(fmt.Errorf("no nonce provided"))
	}

	challenge, err := base64.StdEncoding.DecodeString(challenge64)
	if err != nil {
		return jtp.BadRequestError(fmt.Errorf("invalid challenge encoding: %w", err))
	}

	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		return jtp.BadRequestError(fmt.Errorf("invalid nonce encoding: %w", err))
	}

	challengeResponse := &secrt.ChallengeResponse{
		Challenge: challenge,
		Nonce:     nonce,
	}

	if err = secrt.ValidateResponse(challengeResponse, server.SignPublicKey); err != nil {
		return jtp.ForbiddenError(fmt.Errorf("invalid challenge solution: %w", err))
	}

	return nil
}

type ActivationToken struct {
	Server *SecretServer
	Alias  string
	Token  string
	Code   int
}

func (server *SecretServer) sendActivationToken(alias string, token *ActivationToken) error {
	switch Config.EnrolAction {
	case EnrolMail:
		QueueMail(alias, "Welcome to secrt.io!", activationEmail, token)
		// Queue the email up
	case EnrolFile:
		// File is used only in testing.
		f, err := os.OpenFile(Config.EnrolFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("error opening enrolment file:", err)
		}

		defer f.Close()

		_, err = fmt.Fprintf(f, "%s %06d\n", token.Token, token.Code)
		if err != nil {
			log.Println("error writing to enrolment file:", err)
		}
	}

	return nil
}

// Enrollment accepts a key from the client, and returns the server key.
func (server *SecretServer) handleEnrol(r *http.Request, req *secrt.EnrolmentRequest) (*secrt.EnrolmentResponse, error) {

	if err := server.verifyChallenge(r); err != nil {
		return nil, jtp.ForbiddenError(err)
	}

	var token []byte
	var code int

	// Generate a token.
	row := PGXPool.QueryRow(r.Context(), "select _token, _code from secrt.enrol($1, $2, $3)", server.Server, req.Alias, req.BoxPublicKey)
	if err := row.Scan(&token, &code); err != nil {
		return nil, fmt.Errorf("unable to create token: %w", err)
	}

	// Send the token to the user via some channel
	activationToken := &ActivationToken{
		Server: server,
		Alias:  req.Alias,
		Token:  base64.RawURLEncoding.EncodeToString(token),
		Code:   code,
	}

	if err := server.sendActivationToken(req.Alias, activationToken); err != nil {
		return nil, jtp.InternalServerError(err)
	}

	var msg string
	switch Config.EnrolAction {
	case EnrolMail:
		msg = "Please check your email for an activation code"
	case EnrolFile:
		msg = "Please check the enrolment file for an activation code"
	}

	return &secrt.EnrolmentResponse{
		ServerBoxKey: server.BoxPublicKey,
		Activated:    false,
		Message:      msg,
	}, nil
}
