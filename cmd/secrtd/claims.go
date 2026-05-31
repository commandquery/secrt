package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/commandquery/secrt"
	"golang.org/x/crypto/nacl/box"
)

func (server *SecretServer) Encrypt(plaintext []byte, peerBoxKey []byte) ([]byte, error) {
	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of collisions.
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("unable to generate nonce: %w", err)
	}

	// Prefix the message with a version number of the ciphertext message.
	// Current version is zero.
	var ciphertext = []byte{0}

	// Append the nonce, which is a fixed length (24 bytes).
	ciphertext = append(ciphertext, nonce[:]...)

	// Encrypt the message itself and append to the nonce + public key
	return box.Seal(ciphertext, plaintext, &nonce, secrt.To32(peerBoxKey), secrt.To32(server.BoxPrivateKey)), nil
}

// MakeClaims returns a sealed set of claims, effectively a server-supplied signature over the message
// that asserts a sender's identity.
func (server *SecretServer) MakeClaims(msg *Message, session *Session, recipient *Peer) ([]byte, error) {
	payloadHash := sha256.Sum256(msg.Payload)
	metadataHash := sha256.Sum256(msg.Metadata)

	claim := &secrt.Claims{
		Message:      msg.Message,
		Alias:        session.Peer.Alias,
		BoxPublicKey: session.PublicKey,
		PayloadHash:  payloadHash[:],
		MetadataHash: metadataHash[:],
		Timestamp:    time.Now().Unix(),
	}

	claimBytes, err := json.Marshal(claim)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %v", err)
	}

	sealed, err := server.Encrypt(claimBytes, recipient.DefaultPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt claims: %v", err)
	}

	return sealed, nil
}
