package secrt

import (
	"github.com/google/uuid"
)

// MessageSizeLimit limits the size of individual messages.
const MessageSizeLimit = 50 * 1024 // 100 KiB

// Inbox is the JSON struct used to represent the inbox.
type Inbox struct {
	MessageIDs []uuid.UUID `json:"messageIDs"`
}

// Message is the encrypted message. Claims are encrypted using the server's key,
// while Payload and Metadata are encrypted by the sending peer.
type Message struct {
	Message  uuid.UUID `json:"message"`  // Message ID
	Sequence int       `json:"sequence"` // Sequence number of this message
	Metadata []byte    `json:"metadata"` // encrypted metadata, contains unencrypted size.
	Payload  []byte    `json:"payload"`  // the actual message payload
	Claims   []byte    `json:"claims"`   // server-sealed claims for this message, including sender
}

type Metadata struct {
	Description string `json:"description"`
	Size        int    `json:"size"`
	Filename    string `json:"filename"`
}

// SendRequest wraps encrypted metadata with the encrypted payload.
// Metadata is returned for 'secrt ls', while the payload is returned
// for 'secrt get'.
type SendRequest struct {
	RecipientAlias string `json:"recipientAlias"`
	Payload        []byte `json:"payload"`
	Metadata       []byte `json:"metadata"` // encrypted secret.Metadata (json)
}

// SendResponse is the message MessageID returned by the server after a share.
type SendResponse struct {
	MessageID uuid.UUID `json:"messageId"`
}

type PeerRequest struct {
	Alias string `json:"alias"`
}

type PeerResponse struct {
	Alias        string `json:"alias"`
	BoxPublicKey []byte `json:"boxPublicKey"`
}

type Challenge struct {
	Version    int    `json:"version"`
	Complexity int    `json:"complexity"`
	Timestamp  int64  `json:"timestamp"`
	Challenge  []byte `json:"challenge"`
}

// ChallengeRequest wraps a challenge object with a signature.
// The entire signedChallenge must be returned along with the
// result. The signature, timestamp and proof are then checked.
// This enables stateless hashcash challenges, with nothing stored on the
// server side.
type ChallengeRequest struct {
	Challenge []byte `json:"challenge"`
}

// ChallengeResponse is returned by the client. It contains both the
// original, signed challenge, and the nonce.
type ChallengeResponse struct {
	Challenge []byte `json:"challenge"`
	Nonce     uint64 `json:"nonce"`
}

type EnrolmentRequest struct {
	Alias        string `json:"alias"`
	BoxPublicKey []byte `json:"boxPublicKey"`
}

type EnrolmentResponse struct {
	ServerBoxKey []byte `json:"serverBoxKey"`
	Activated    bool   `json:"activated"`
	Message      string `json:"message"`
}

type InviteRequest struct {
	Alias string `json:"alias"`
}

type ActivationRequest struct {
	Token string `json:"token"`
	Code  int    `json:"code"`
}

type ActivationResponse struct {
	Message string `json:"message"`
	Token   []byte `json:"token"`
}

// Claims is server-sealed metadata containing identifying information about the sender and message.
type Claims struct {
	Message      uuid.UUID `json:"message"`
	Alias        string    `json:"alias"`
	BoxPublicKey []byte    `json:"boxPublicKey"`
	PayloadHash  []byte    `json:"payloadHash"`
	MetadataHash []byte    `json:"metadataHash,omitzero"`
	Timestamp    int64     `json:"timestamp"`
}

// How did we do..?
type Telemetry struct {
	BuildID   string `json:"buildId"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	Command   string `json:"command"`
	ElapsedMs int64  `json:"elapsedMs"`
	UtimeMs   *int64 `json:"utimeMs,omitempty"`
	StimeMs   *int64 `json:"stimeMs,omitempty"`
	ExitCode  int    `json:"exitCode"`
}

type PullRequest struct {
	LastSequence int // last sequence number seen by pull
}

type PullResponse struct {
	Messages []Message // list of messages since the last pull
}
