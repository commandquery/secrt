package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

func CmdInvite(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("invite", flag.ContinueOnError)
	if err := flags.Parse(args); err != nil {
		secrt.Usage("secret invite user@domain")
	}

	args = flags.Args()
	if len(args) != 1 {
		secrt.Usage("secret invite user@domain")
	}

	req := &secrt.InviteRequest{
		Alias: args[0],
	}

	err := Call(endpoint, req, jtp.Nil, "POST", "invite")

	if errors.Is(err, jtp.ErrConflict) {
		return fmt.Errorf("%s is already enrolled", req.Alias)
	}

	if errors.Is(err, &jtp.HTTPError{StatusCode: http.StatusTooManyRequests}) {
		return fmt.Errorf("your invitation quota has been reached")
	}

	return err
}
