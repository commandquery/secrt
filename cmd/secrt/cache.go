package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

// CacheState is written to the "state.json" file in the root of the cache.
type CacheState struct {
	Seq int // highest sequence number from pull()
}

// Cache is a local cache of secrets. It's the primary interface through which secrets
// are accessed. If modified, and if enabled, cached secrets are written o disk when the CLI terminates.
// Note: the cache stores only encrypted data; decrypted data is never persisted.
type Cache struct {
	Config    *Config                      // config for this cache session
	Endpoint  *Endpoint                    // endpoint for this cache session
	state     *CacheState                  // cache metadata
	enabled   bool                         // If the cache is enabled (inherited from config)
	dir       string                       // Cache storage directory (if enabled)
	pullCache map[uuid.UUID]*secrt.Message // results of latest pull
}

func OpenCache(config *Config, endpoint *Endpoint) (*Cache, error) {
	cache := &Cache{
		enabled:   config.Properties.Cache,
		Config:    config,
		Endpoint:  endpoint,
		pullCache: make(map[uuid.UUID]*secrt.Message),
	}

	// secrt can operate without a persistent cache, but we still use the cache
	// object to read and write secrets.
	if !cache.enabled {
		return cache, nil
	}

	cache.dir = filepath.Join(config.store, "cache")

	stateFile := filepath.Join(cache.dir, "state.json")
	stateBytes, err := os.ReadFile(stateFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("unable to read cache state from %s: %w", stateFile, err)
		}
	}

	state := &CacheState{}
	if err == nil {
		err = json.Unmarshal(stateBytes, state)
		if err != nil {
			return nil, fmt.Errorf("unable to parse cache state from %s: %w", stateFile, err)
		}
	}

	cache.state = state
	return cache, nil
}

// Entries returns a slice of message UUIDs from the cache.
func (c *Cache) Entries() ([]uuid.UUID, error) {
	if !c.enabled {
		return nil, nil
	}

	entries := make([]uuid.UUID, 0)

	cacheEntries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, err
	}

	for _, cacheFile := range cacheEntries {
		id, err := uuid.Parse(cacheFile.Name())
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "unexpected file in cache directory:", cacheFile.Name())
			continue
		}

		entries = append(entries, id)
	}

	return entries, nil
}

func (c *Cache) Remove(id uuid.UUID) error {
	if !c.enabled {
		return nil
	}

	cacheFile := filepath.Join(c.dir, id.String())
	return os.Remove(cacheFile)
}

// Pull requests any new entries from the server.
func (c *Cache) pull() error {
	pullRequest := secrt.PullRequest{
		LastSequence: c.state.Seq,
	}

	var pullResponse secrt.PullResponse

	if err := Call(c.Endpoint, &pullRequest, &pullResponse, "GET", "pull"); err != nil {
		if !errors.Is(err, jtp.ErrNoContent) {
			return err
		}
	}

	if c.enabled {
		if err := os.MkdirAll(c.dir, 0700); err != nil {
			return fmt.Errorf("error creating cache directory %s: %w", c.dir, err)
		}
	}

	// cache each new message before we do anything else.
	for _, message := range pullResponse.Messages {
		c.pullCache[message.Message] = &message
		if !c.enabled {
			continue
		}

		cacheFile := filepath.Join(c.dir, message.Message.String())

		// don't overwrite the file if it already exists.
		_, err := os.Stat(cacheFile)
		if err == nil {
			continue
		}

		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("error pulling message %s: %w", message.Message, err)
		}

		if msgBytes, err := json.Marshal(message); err == nil {
			if err = os.WriteFile(cacheFile, msgBytes, 0600); err != nil {
				return fmt.Errorf("could not write cache message to %s: %w", cacheFile, err)
			}
		}

		// Remember the highest sequence number we saw.
		if message.Sequence > c.state.Seq {
			c.state.Seq = message.Sequence
		}
	}

	return c.Save()
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
func (c *Cache) FindMessageID(partialID string) (uuid.UUID, error) {

	if len(partialID) < 4 {
		return uuid.Nil, fmt.Errorf("message ID too short: %q", partialID)
	}

	if len(partialID) > 36 {
		return uuid.Nil, fmt.Errorf("message ID too long: %q", partialID)
	}

	// if a full message UUID is provided, just return it.
	if len(partialID) == 36 {
		return uuid.Parse(partialID)
	}

	// It's a partial message ID, see if we can find the whole ID in the cache.
	// If the cache is disabled then there's no point looking, we just didn't find it.
	if !c.enabled {
		return uuid.Nil, ErrMessageNotFound
	}

	partialID = strings.ToLower(partialID)
	var found string

	cacheEntries, err := c.Entries()
	if err == nil {
		for _, msgid := range cacheEntries {
			name := msgid.String()
			if strings.HasPrefix(name, partialID) {
				// if 'found' is already set, we've got a duplicate match
				if found != "" {
					return uuid.Nil, fmt.Errorf("multiple messages found")
				}
				found = name
			}
		}
	}

	if found == "" {
		return uuid.Nil, ErrMessageNotFound
	}

	return uuid.Parse(found)
}

func (c *Cache) FindMessage(partialID string) (*Cleartext, error) {
	msgID, err := c.FindMessageID(partialID)
	if err != nil {
		return nil, fmt.Errorf("unable to find message ID %s: %w", partialID, err)
	}

	cleartext, err := c.GetCleartext(msgID)
	if err != nil {
		return nil, fmt.Errorf("unable to get message %s: %w", partialID, err)
	}

	if cleartext.UnacceptablePeer {
		return nil, fmt.Errorf("unknown peer: %s", cleartext.Claims.Alias)
	}

	return cleartext, nil
}

func (c *Cache) GetMessage(msgID uuid.UUID) (*secrt.Message, error) {

	// pullCache allows secrt to work without an on-disk cache. pull() populates the
	// cache and GetMessage() returns it preferentially. This means we don't need
	// to store the entire cache in memory, but we can still operate without one.
	pulled, ok := c.pullCache[msgID]
	if ok {
		return pulled, nil
	}

	// If caching is enabled, and if the file exists in cache, and if it's
	// valid json, then return the encrypted object from the cache.
	if !c.enabled {
		return nil, ErrMessageNotFound
	}

	cacheFile := filepath.Join(c.dir, msgID.String())
	var message secrt.Message
	if f, err := os.Open(cacheFile); err == nil {
		defer f.Close()
		if msgBytes, err := io.ReadAll(f); err == nil {
			if err = json.Unmarshal(msgBytes, &message); err == nil {
				return &message, nil
			}
			_, _ = fmt.Fprintf(os.Stderr, "error reading cache file %s: %v\n", cacheFile, err)
		}
	}

	return nil, ErrMessageNotFound
}

func (c *Cache) Decrypt(peerBoxKey []byte, ciphertext []byte) ([]byte, error) {
	// Check that the version number works with us.
	if ciphertext[0] != 0 {
		return nil, fmt.Errorf("ciphertext version (%d) is not supported. Try upgrading `secret`", ciphertext[0])
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	boxPrivateKey, err := c.Endpoint.GetSecretValue("boxPrivateKey")
	if err != nil {
		return nil, err
	}

	var out []byte
	out, ok := box.Open(out, ciphertext[25:], &nonce, secrt.To32(peerBoxKey), secrt.To32(boxPrivateKey))

	if !ok {
		return nil, fmt.Errorf("unable to authenticate message")
	}

	return out, nil
}

// GetClaims decrypts the claims object of a message. Claims are encrypted by the server,
// using the server's key, which is associated with this endpoint.
func (c *Cache) GetClaims(cryptclaims []byte) (*secrt.Claims, error) {
	claimbytes, err := c.Decrypt(c.Endpoint.ServerBoxKey, cryptclaims)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt message claims: %w", err)
	}

	var claims secrt.Claims
	if err := json.Unmarshal(claimbytes, &claims); err != nil {
		return nil, fmt.Errorf("unable to unmarshal claims: %w", err)
	}

	return &claims, nil
}

// GetCleartext retrieves the given message, either from the cache or the server.
// It attempts to decrypt the message, but may return a partial message
// if the peer is unacceptable.
func (c *Cache) GetCleartext(msgID uuid.UUID) (*Cleartext, error) {
	message, err := c.GetMessage(msgID)
	if err != nil {
		return nil, err
	}

	claims, err := c.GetClaims(message.Claims)
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
	peer, err := c.Endpoint.GetPeer(c.Config, claims.Alias)
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

	cleartext.Cleartext, err = c.Decrypt(claims.BoxPublicKey, message.Payload)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt message: %w", err)
	}

	var metadata secrt.Metadata

	metajs, err := c.Decrypt(claims.BoxPublicKey, message.Metadata)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt metadata: %w", err)
	}

	if err = json.Unmarshal(metajs, &metadata); err != nil {
		return nil, fmt.Errorf("unable to unmarshal metadata: %w", err)
	}

	cleartext.Metadata = &metadata
	return &cleartext, nil
}

// Save saves the cache to storage, if it's enabled.
// This simply updates the cache state file.
func (c *Cache) Save() error {
	if !c.enabled {
		return nil
	}

	stateBytes, err := json.Marshal(c.state)
	if err != nil {
		return fmt.Errorf("unable to marshal cache state: %w", err)
	}

	stateFile := filepath.Join(c.dir, "state.json")
	if err := os.WriteFile(stateFile, stateBytes, 0600); err != nil {
		return fmt.Errorf("unable to write cache state: %w", err)
	}

	return nil
}
