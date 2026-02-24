package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
)

// Message is the internal representation of a message. Use secrt.Message to
// transfer a message to a client.
type Message struct {
	Recipient   uuid.UUID
	Message     uuid.UUID
	SenderAlias string
	Received    time.Time
	Metadata    []byte
	Payload     []byte
	Claims      []byte
}

func (server *SecretServer) handlePostMessage(r *http.Request, envelope *secrt.SendRequest) (*secrt.SendResponse, error) {
	sender, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	recipient, ok := server.GetPeer(envelope.RecipientAlias)
	if !ok {
		return nil, jtp.NotFoundError(fmt.Errorf("recipient not found"))
	}

	newMessage := &Message{
		Recipient:   recipient.Peer,
		Message:     uuid.New(),
		SenderAlias: sender.Alias,
		Received:    time.Now(),
		Metadata:    envelope.Metadata,
		Payload:     envelope.Payload,
	}

	var err error
	newMessage.Claims, err = server.MakeClaims(newMessage, sender, recipient)
	if err != nil {
		return nil, fmt.Errorf("unable to create message claims: %w", err)
	}

	_, err = PGXPool.Exec(r.Context(), "select secrt.send($1, $2, $3, $4, $5, $6, $7)",
		newMessage.Message, sender.Peer, recipient.Peer, recipient.Server, envelope.Metadata, envelope.Payload, newMessage.Claims)
	if err != nil {
		return nil, jtp.InternalServerError(fmt.Errorf("unable to insert message: %w", err))
	}

	log.Println("sent message", newMessage.Message)

	// Tell the sender the message MessageID
	return &secrt.SendResponse{
		MessageID: newMessage.Message,
	}, nil
}

func (server *SecretServer) handleGetMessage(r *http.Request, _ *jtp.None) (*secrt.Message, error) {
	peer, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		return nil, jtp.BadRequestError(fmt.Errorf("invalid message id"))
	}

	msg, err := GetMessage(peer, id)
	if err != nil {
		if errors.Is(err, ErrUnknownMessageID) {
			return nil, jtp.NotFoundError(err)
		}
		if errors.Is(err, ErrAmbiguousMessageID) {
			return nil, jtp.BadRequestError(err)
		}
		return nil, jtp.InternalServerError(fmt.Errorf("error while retrieving message: %w", err))
	}

	return &secrt.Message{
		Metadata: msg.Metadata,
		Payload:  msg.Payload,
		Claims:   msg.Claims,
	}, nil
}

func (server *SecretServer) handleDeleteMessage(r *http.Request, _ *jtp.None) (*jtp.None, error) {
	peer, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		return nil, jtp.BadRequestError(fmt.Errorf("invalid message id"))
	}

	msg, err := GetMessage(peer, id)
	if err != nil {
		if errors.Is(err, ErrUnknownMessageID) {
			return nil, jtp.NotFoundError(err)
		}
		if errors.Is(err, ErrAmbiguousMessageID) {
			return nil, jtp.BadRequestError(err)
		}
		return nil, err
	}

	if err = msg.Delete(); err != nil {
		return nil, jtp.InternalServerError(fmt.Errorf("unable to delete message: %w", err))
	}

	return nil, nil
}

func (msg *Message) Delete() error {
	_, err := PGXPool.Exec(context.Background(), "delete from secrt.message where message=$1", msg.Message)
	if err != nil {
		return fmt.Errorf("unable to delete message: %w", err)
	}

	return nil
}

// GetMessage finds a message by MessageID.
func GetMessage(peer *Peer, messageId string) (*Message, error) {

	msgUuid, err := uuid.Parse(messageId)
	if err != nil {
		return nil, fmt.Errorf("unable to parse message id: %w", err)
	}

	ctx := context.Background()
	row := PGXPool.QueryRow(ctx, "select message, received, metadata, payload, claims from secrt.message where message.peer=$1 and message=$2", peer.Peer, msgUuid)

	msg := Message{
		Recipient: peer.Peer,
	}

	if err := row.Scan(&msg.Message, &msg.Received, &msg.Metadata, &msg.Payload, &msg.Claims); err != nil {
		return nil, fmt.Errorf("unable to read message: %w", err)
	}

	return &msg, nil
}
