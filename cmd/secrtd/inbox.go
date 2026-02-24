package main

import (
	"fmt"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
)

func (server *SecretServer) handleGetInbox(r *http.Request, _ *jtp.None) (*secrt.Inbox, error) {
	peer, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	rows, err := PGXPool.Query(r.Context(),
		`select message from secrt.message where message.peer=$1`, peer.Peer)
	if err != nil {
		return nil, jtp.InternalServerError(fmt.Errorf("unable to query inbox: %w", err))
	}

	defer rows.Close()

	inbox := &secrt.Inbox{
		MessageIDs: make([]uuid.UUID, 0),
	}

	var messageID uuid.UUID

	for rows.Next() {
		if err := rows.Scan(&messageID); err != nil {
			return nil, jtp.InternalServerError(fmt.Errorf("unable to read inbox: %w", err))
		}

		inbox.MessageIDs = append(inbox.MessageIDs, messageID)
	}

	// 204 just means there's nothing here. No messages!
	if len(inbox.MessageIDs) == 0 {
		return nil, jtp.NoContentError()
	}

	return inbox, nil
}
