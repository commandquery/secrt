package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
)

// Cleartext is a message that's been decrypted. Returned by GetCleartext.
type Cleartext struct {
	Message          *secrt.Message
	UnacceptablePeer bool
	Metadata         *secrt.Metadata
	Cleartext        []byte
	Claims           *secrt.Claims
}

// FindMessageID takes a (potentially) partial message ID and attempts to turn it
// into a full uuid. If a partial message ID is provided (ie, a prefix), FindMessageID
// searches for an unambiguous, full message ID in the cache. If a full message ID is provided,
// it's returned as a uuid unconditionally.
//
// The role of FindMessageID is not to find an existing message, but to use the cache
// as a kind of autocomplete if the message ID is partially entered, as a convenience
// to the user. This works because a user will typically either already have the full message
// UUID (ie, sent to them in another channel) or they will have used `secrt ls`, which
// downloads new messages to cache, making their ID searchable.
func FindMessageID(config *Config, partialID string) (uuid.UUID, error) {

	if len(partialID) > 36 {
		return uuid.Nil, fmt.Errorf("message ID too long")
	}

	// if a full message UUID is provided, just return it.
	if len(partialID) == 36 {
		return uuid.Parse(partialID)
	}

	// It's a partial message ID, see if we can find the whole ID in the cache.
	// If the cache is disabled then there's no point looking, we just didn't find it.
	if !config.Properties.Cache {
		return uuid.Nil, ErrMessageNotFound
	}

	var found string

	cache := filepath.Join(config.store, "cache")
	cacheEntries, err := os.ReadDir(cache)
	if err == nil {
		for _, cacheFile := range cacheEntries {
			if strings.HasPrefix(cacheFile.Name(), partialID) {
				// if 'found' is already set, we've got a duplicate match
				if found != "" {
					return uuid.Nil, fmt.Errorf("multiple messages found")
				}
				found = cacheFile.Name()
			}
		}
	}

	if found == "" {
		return uuid.Nil, ErrMessageNotFound
	}

	return uuid.Parse(found)
}

func GetMessage(config *Config, endpoint *Endpoint, msgID uuid.UUID) (*secrt.Message, error) {
	var message secrt.Message

	cacheDir := filepath.Join(config.store, "cache")
	cacheFile := filepath.Join(cacheDir, msgID.String())

	// If caching is enabled, and if the file exists in cache, and if it's
	// valid json ... then return the encrypted object from the cache.
	if config.Properties.Cache {
		if f, err := os.Open(cacheFile); err == nil {
			if msgBytes, err := io.ReadAll(f); err == nil {
				if err = json.Unmarshal(msgBytes, &message); err == nil {
					return &message, nil
				}
				_, _ = fmt.Fprintf(os.Stderr, "error reading cache file %s: %v\n", cacheFile, err)
			}
		}
	}

	if err := Call(endpoint, jtp.Nil, &message, "GET", "message", msgID.String()); err != nil {
		return nil, fmt.Errorf("unable to get message %s: %w", msgID, err)
	}

	if !config.Properties.Cache {
		return &message, nil
	}

	var err error
	if err = os.MkdirAll(cacheDir, 0700); err == nil {
		if msgBytes, err := json.Marshal(message); err == nil {
			if err = os.WriteFile(cacheFile, msgBytes, 0600); err == nil {
				return &message, nil
			}
		}
	}

	_, _ = fmt.Fprintf(os.Stderr, "error writing cache file: %v\n", err)

	return &message, nil
}

// GetCleartext retrieves the given message, either from the cache or the server.
// It attempts to decrypt the message, but may return a partial message
// if the peer is unacceptable.
func GetCleartext(config *Config, endpoint *Endpoint, msgID uuid.UUID) (*Cleartext, error) {
	message, err := GetMessage(config, endpoint, msgID)
	if err != nil {
		return nil, err
	}

	claims, err := endpoint.GetClaims(config, message.Claims)
	if err != nil {
		return nil, fmt.Errorf("unable to get claims: %w", err)
	}

	cleartext := Cleartext{
		Message: message,
		Claims:  claims,
	}

	// Verify that the claimed public key matches the published public key
	// for the given peer. The public key is cached, which results in the peer
	// being added to the user's config, if it doesn't already exist.
	// GetPeer is gated by AcceptPeers, so this stops an unknown peer's
	// message from being readable, e.g. if the peer's public key has changed.
	peer, err := endpoint.GetPeer(config, claims.Alias)
	if err != nil {
		if errors.Is(err, ErrUnacceptablePeer) {
			cleartext.UnacceptablePeer = true
			return &cleartext, nil
		}
		return nil, fmt.Errorf("unable to get peer %s: %w", claims.Alias, err)
	}

	if !bytes.Equal(peer.BoxPublicKey, claims.BoxPublicKey) {
		return nil, fmt.Errorf("message claim does not match public key")
	}

	// Verify that the claim contains hashes that match the actual payload and metadata.
	// Since the claim is signed by the server but the message data is sent by a peer,
	// this is intended to ensure that server-generated claims can't be replayed.
	payloadHash := sha256.Sum256(message.Payload)
	if !bytes.Equal(payloadHash[:], claims.PayloadHash) {
		return nil, fmt.Errorf("payload claim does not match message payload")
	}

	metadataHash := sha256.Sum256(message.Metadata)
	if !bytes.Equal(metadataHash[:], claims.MetadataHash) {
		return nil, fmt.Errorf("metadata claim does not match message metadata")
	}

	cleartext.Cleartext, err = endpoint.Decrypt(config, claims.BoxPublicKey, message.Payload)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt message: %w", err)
	}

	var metadata secrt.Metadata

	metajs, err := endpoint.Decrypt(config, claims.BoxPublicKey, message.Metadata)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt metadata: %w", err)
	}

	if err = json.Unmarshal(metajs, &metadata); err != nil {
		return nil, fmt.Errorf("unable to unmarshal metadata: %w", err)
	}

	cleartext.Metadata = &metadata
	return &cleartext, nil
}

// CmdGet gets a secret message (and decrypts it). You can use either the short, 8-character UUID, or the full UUID
// If there's more than one secret with the same short MessageID, the server will send us an error.
func CmdGet(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	targetFilename := flags.String("o", "", "output to the given filename")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("unable to parse flags: %w", err)
	}

	args = flags.Args()
	if len(args) != 1 {
		return fmt.Errorf("message MessageID not specified")
	}

	msgID, err := FindMessageID(config, args[0])
	if err != nil {
		return fmt.Errorf("unable to find message %s: %w", args[0], err)
	}

	cleartext, err := GetCleartext(config, endpoint, msgID)
	if err != nil {
		return fmt.Errorf("unable to get message %s: %w", args[0], err)
	}

	if cleartext.UnacceptablePeer {
		return fmt.Errorf("unknown peer: %s", cleartext.Claims.Alias)
	}

	var target = os.Stdout
	if *targetFilename != "" {
		target, err = os.OpenFile(*targetFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("unable to open output file %s: %w", *targetFilename, err)
		}
	}

	defer target.Close()

	_, err = target.Write(cleartext.Cleartext)
	if err != nil {
		return err
	}

	return nil
}
