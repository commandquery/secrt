package main

import (
	"fmt"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

func (server *SecretServer) handlePull(r *http.Request, pullRequest *secrt.PullRequest) (*secrt.PullResponse, error) {
	session, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	// return messages in sequence order so that certain problems on the client side
	// won't cause messages to be lost.
	rows, err := PGXPool.Query(r.Context(),
		`select message, seq, metadata, payload, claims from secrt.message where message.peer=$1 and message.seq > $2 order by message.seq`, session.Peer.Peer, pullRequest.LastSequence)
	if err != nil {
		return nil, jtp.InternalServerError(fmt.Errorf("unable to pull inbox: %w", err))
	}

	defer rows.Close()

	var response secrt.PullResponse

	for rows.Next() {
		var msg secrt.Message
		if err := rows.Scan(&msg.Message, &msg.Sequence, &msg.Metadata, &msg.Payload, &msg.Claims); err != nil {
			return nil, jtp.InternalServerError(fmt.Errorf("unable to read inbox: %w", err))
		}

		response.Messages = append(response.Messages, msg)
	}

	// 204 just means there's nothing here. No messages!
	if len(response.Messages) == 0 {
		return nil, jtp.NoContentError()
	}

	return &response, nil
}
