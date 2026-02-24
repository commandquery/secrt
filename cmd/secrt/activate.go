package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/commandquery/secrt"
)

// Activate an enrolment given a token and code.

func CmdActivate(config *Config, endpoint *Endpoint, args []string) error {

	if len(args) != 2 {
		return fmt.Errorf("usage: secrt activate <token> <code>")
	}

	code, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid code: %v", err)
	}

	activationRequest := &secrt.ActivationRequest{
		Token: args[0],
		Code:  code,
	}

	var activationResponse secrt.ActivationResponse
	if err = Call(endpoint, activationRequest, &activationResponse, "POST", "activate"); err != nil {
		return fmt.Errorf("unable to activate account: %w", err)
	}

	if err = endpoint.Vaults[0].vault.Set("authToken", activationResponse.Token); err != nil {
		return fmt.Errorf("unable to store auth token: %w", err)
	}

	if activationResponse.Message != "" {
		_, _ = fmt.Fprintln(os.Stderr, activationResponse.Message)
	}

	config.modified = true

	return nil
}
