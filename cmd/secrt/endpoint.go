package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"golang.org/x/crypto/nacl/box"
)

var ErrUnacceptablePeer error = errors.New("unacceptable peer") // Peer can't be auotmatically accepted
var ErrExistingEnrolment error = errors.New("already enrolled")
var ErrMessageNotFound error = errors.New("message not found")

// Call sends a JSON object and receives a JSON response. It's a convenience method that
// creates a JSONRequest and calls it. The intent is that most calls should use
// this method, but some requests are more complex and require additional settings
// (unsigned requests, headers, etc).
func Call[S any, R any](endpoint *Endpoint, s *S, r *R, method string, path ...string) error {

	headers, err := endpoint.GetAuthHeader()
	if err != nil {
		return fmt.Errorf("unable to set signature: %w", err)
	}

	return jtp.Call(method, endpoint.Path(path...), headers, s, r)
}

// Path returns a path URL relative to the endpoint.
func (endpoint *Endpoint) Path(path ...string) string {
	var urlPath strings.Builder

	for i, p := range path {
		if i > 0 {
			urlPath.WriteRune('/')
		}
		urlPath.WriteString(url.PathEscape(p))
	}

	// note that endpoint URL must always end in "/".
	return endpoint.URL + urlPath.String()
}

func (endpoint *Endpoint) findPeer(alias string) *Peer {
	if endpoint.Peers != nil {
		for _, peer := range endpoint.Peers {
			if peer.Alias == alias {
				return peer
			}
		}
	}

	return nil
}

// GetPeer returns the public key for a given peer (if known).
func (endpoint *Endpoint) GetPeer(config *Config, alias string) (*Peer, error) {

	peer := endpoint.findPeer(alias)
	if peer != nil {
		return peer, nil
	}

	if !config.Properties.AcceptPeers {
		return nil, ErrUnacceptablePeer
	}

	newPeer, err := endpoint.AddPeer(alias, false)
	if err != nil {
		return nil, fmt.Errorf("unable to add peer: %w", err)
	}

	config.modified = true
	return newPeer, nil
}

func (endpoint *Endpoint) AddPeer(alias string, addKey bool) (*Peer, error) {

	existingPeer := endpoint.findPeer(alias)
	if existingPeer != nil {
		if !addKey {
			return nil, fmt.Errorf("peer already exists: %s", alias)
		}
	}

	peerReq := secrt.PeerRequest{Alias: alias}
	var peerResp secrt.PeerResponse
	if err := Call(endpoint, &peerReq, &peerResp, "GET", "peer"); err != nil {
		return nil, fmt.Errorf("unable to get peer %s: %w", alias, err)
	}

	if len(peerResp.BoxPublicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(peerResp.BoxPublicKey))
	}

	if peerResp.Alias != alias {
		return nil, fmt.Errorf("received wrong peer id: %s (expected %s)", peerResp.Alias, alias)
	}

	var newPeer *Peer

	// If there's an existing peer and we got to this point, it means we want
	// to add a new public key for this peer.
	if existingPeer != nil {
		// defer deleteing any old peer until we know the new peer will work.
		if err := endpoint.DeletePeer(alias); err != nil {
			return nil, fmt.Errorf("unable to replace peer: %w", err)
		}

		newPeer = existingPeer
		newPeer.PublicKeys = append(newPeer.PublicKeys,
			PublicKey{Type: "box", Key: peerResp.BoxPublicKey, Trust: true})
	} else {
		newPeer = &Peer{
			Alias: alias,
			PublicKeys: []PublicKey{
				{Type: "box", Key: peerResp.BoxPublicKey, Trust: true},
			},
		}
	}

	endpoint.Peers = append(endpoint.Peers, newPeer)
	endpoint.newPeers = append(endpoint.newPeers, newPeer)
	return newPeer, nil
}

func (endpoint *Endpoint) PrintNewPeers() {
	if endpoint.newPeers == nil {
		return
	}

	fmt.Fprintln(os.Stderr)

	for _, peer := range endpoint.newPeers {
		fmt.Fprintf(os.Stderr, "added new peer: %s\n", peer.Alias)
	}

	fmt.Fprintln(os.Stderr)

	if len(endpoint.newPeers) > 1 {
		fmt.Fprintln(os.Stderr, "* If you didn't expect messages from these new peers, don't trust them.")
	} else {
		fmt.Fprintf(os.Stderr, "* If you didn't expect a message from %s, don't trust it.\n", endpoint.newPeers[0].Alias)
	}
}

// GetAuthHeader returns a Signature header, which is just the auth token provided at activation.
func (endpoint *Endpoint) GetAuthHeader() (http.Header, error) {
	token, err := endpoint.GetSecretValue("authToken")
	if err != nil {
		return nil, fmt.Errorf("unable to get auth token: %w", err)
	}
	token64 := base64.StdEncoding.EncodeToString(token)

	var header http.Header = make(http.Header)
	header.Set("Authorization", "Bearer "+token64)
	return header, nil
}

// readInput reads a byte slice from a file or stdin. If the filename is "", read from stdin.
// Returns the byte array as well as file metadata.
func readInput(filename string) ([]byte, *secrt.Metadata, error) {
	metadata := &secrt.Metadata{}

	// Use a filename, or just stdin?
	var reader io.Reader
	if filename != "" {
		file, err := os.Open(filename)
		if err != nil {
			return nil, nil, err
		}

		defer file.Close()
		metadata.Filename = filepath.Base(file.Name())
		reader = file
	} else {
		metadata.Filename = ""
		reader = os.Stdin
	}

	cleartext, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	metadata.Size = len(cleartext)
	return cleartext, metadata, nil
}

func (endpoint *Endpoint) GetSecretValue(key string) ([]byte, error) {
	vault, err := endpoint.GetVault()
	if err != nil {
		return nil, fmt.Errorf("unable to get vault: %w", err)
	}

	return vault.Get(key)
}

func (endpoint *Endpoint) GetVault() (Vault, error) {
	if len(endpoint.Vaults) == 0 {
		return nil, fmt.Errorf("no vaults found")
	}

	// Try to find an unsealed vault.
	for _, envelope := range endpoint.Vaults {
		if envelope.vault != nil {
			if envelope.vault.IsUnsealed() {
				return envelope.vault, nil
			}
		}
	}

	// Try to unseal the first vault.
	envelope := endpoint.Vaults[0]

	if envelope.vault != nil {
		if err := envelope.vault.Unseal(); err != nil {
			return nil, fmt.Errorf("unable to unseal vault: %w", err)
		}

		return envelope.vault, nil
	}

	return nil, fmt.Errorf("no vault found")
}

func (endpoint *Endpoint) Encrypt(plaintext []byte, peerBoxKey []byte) ([]byte, error) {
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

	boxPrivateKey, err := endpoint.GetSecretValue("boxPrivateKey")
	if err != nil {
		return nil, err
	}

	// Encrypt the message itself and append to the nonce + public key
	return box.Seal(ciphertext, plaintext, &nonce, secrt.To32(peerBoxKey), secrt.To32(boxPrivateKey)), nil
}

func (endpoint *Endpoint) GetChallenge() (*secrt.ChallengeRequest, error) {
	endpointURL := endpoint.Path("challenge")
	resp, err := http.Get(endpointURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid challenge: %s", resp.Status)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var challenge *secrt.ChallengeRequest
	if err := json.Unmarshal(body, &challenge); err != nil {
		return nil, err
	}

	return challenge, nil
}

func (endpoint *Endpoint) DeletePeer(alias string) error {
	if endpoint.Peers == nil {
		return fmt.Errorf("no peers found")
	}

	var newPeers []*Peer
	var found bool

	for _, peer := range endpoint.Peers {
		if peer.Alias == alias {
			found = true
		} else {
			newPeers = append(newPeers, peer)
		}
	}

	if !found {
		return fmt.Errorf("peer %s not found", alias)
	}

	endpoint.Peers = newPeers
	return nil
}
