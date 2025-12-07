package main

import "github.com/google/uuid"

// Inbox is the JSON struct used to represent the inbox.
type Inbox struct {
	Messages []InboxMessage `json:"messages"`
}

type InboxMessage struct {
	ID        uuid.UUID `json:"id"`
	Sender    string    `json:"sender"`
	Timestamp int64     `json:"timestamp"`
	Size      int       `json:"size"`
}

type Signature struct {
	Peer string `json:"peer"`
	Sig  []byte `json:"sig"`
}
