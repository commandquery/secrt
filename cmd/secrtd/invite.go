package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

type inviteTempalte struct {
	Sender    string
	Recipient string
}

func (server *SecretServer) handleInvite(r *http.Request, req *secrt.InviteRequest) (*jtp.None, error) {
	sender, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	log.Println("received invite request")

	var exists bool
	row := PGXPool.QueryRow(r.Context(), "select secrt.invite($1, $2, $3)", server.Server, sender.Peer, req.Alias)
	err := row.Scan(&exists)
	if err != nil {
		return nil, &jtp.HTTPError{StatusCode: http.StatusTooManyRequests, Err: fmt.Errorf("unable to send invite: %v", err)}
	}

	if exists {
		return nil, jtp.ConflictError(fmt.Errorf("peer is already enrolled"))
	}

	QueueMail(req.Alias, "Invitation to secrt.io!", inviteEmail, inviteTempalte{
		Sender:    sender.Alias,
		Recipient: req.Alias,
	})

	return nil, nil
}
