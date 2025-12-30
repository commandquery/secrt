package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/server"
	"golang.org/x/crypto/nacl/box"
)

var ErrUnknownPeer error = errors.New("unknown peer")
var ErrSecretTooBig error = errors.New("secret too big")

// GetPeer returns the public key for a given peer (if known).
func (endpoint *Endpoint) GetPeer(config *Config, peerId string) (*Peer, error) {
	if endpoint.Peers != nil {
		entry, ok := endpoint.Peers[peerId]
		if ok {
			return entry, nil
		}
	}

	if !config.Properties.AcceptPeers {
		return nil, errors.Join(ErrUnknownPeer, fmt.Errorf("unknown peer: %s", peerId))
	}

	newPeer, err := endpoint.AddPeer(peerId)
	if err != nil {
		return nil, fmt.Errorf("unable to add peer: %w", err)
	}

	return newPeer, nil
}

func (endpoint *Endpoint) AddPeer(peerId string) (*Peer, error) {

	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	u.Path = path.Join(u.Path, "peer", url.PathEscape(peerId))

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("unexpected error: %w", err)
	}

	if err = endpoint.SetSignature(req); err != nil {
		return nil, fmt.Errorf("unable to set signature: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to contact server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("peer %s not found", peerId)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("peer request failed: %s: %s", resp.Status, body)
	}

	peerjs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read peer: %w", err)
	}

	var peerResp secrt.Peer
	if err = json.Unmarshal(peerjs, &peerResp); err != nil {
		return nil, fmt.Errorf("unable to unmarshal peer: %w", err)
	}

	if len(peerResp.PublicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(peerResp.PublicKey))
	}

	if peerResp.Peer != peerId {
		return nil, fmt.Errorf("received wrong peer id: %s (expected %s)", peerResp.Peer, peerId)
	}

	// Write this to stderr so stdout isn't affected.
	_, _ = fmt.Fprintln(os.Stderr, "Adding new peer", peerId)
	peer := &Peer{
		PeerID:    peerId,
		PublicKey: peerResp.PublicKey,
	}

	endpoint.Peers[peerId] = peer
	return peer, nil
}

// SetSignature returns a Signature header, which is just the peer ID
// followed by the current timestamp, encrypted for the server itself.
// This authenticates us to the server within the request header, giving
// us strong access control without a handshake.
func (endpoint *Endpoint) SetSignature(req *http.Request) error {
	msg := fmt.Sprintf("%d", time.Now().Unix())

	ciphertext, err := endpoint.Encrypt([]byte(msg), endpoint.ServerKey)
	if err != nil {
		return fmt.Errorf("unable to generate signature: %w", err)
	}

	// entire signature is json encoded to avoid issues with little bobby table's peer ID.
	signature := &secrt.Signature{
		Peer: endpoint.PeerID,
		Sig:  ciphertext,
	}

	js, err := json.Marshal(signature)
	if err != nil {
		return fmt.Errorf("unable to marshal signature: %w", err)
	}

	req.Header.Set("Signature", base64.StdEncoding.EncodeToString(js))
	return nil
}

// CmdSend sends a secret to a peer.
func CmdSend(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("send", flag.ContinueOnError)
	longFormat := flags.Bool("l", false, "display the full uuid")
	description := flags.String("d", "", "include a description")

	if err := flags.Parse(args); err != nil {
		return err
	}

	args = flags.Args()
	recipient := args[0]

	plaintext, metadata, err := readInput(flags.Args(), 1)
	if err != nil {
		return err
	}

	metadata.Description = *description

	user, err := endpoint.GetPeer(config, recipient)
	if err != nil {
		return fmt.Errorf("unable to get peer: %w", err)
	}

	// Now we have the plaintext message and metadata; we need to encrypt them both into an Envelope.
	clearmeta, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("unable to marshal metadata: %w", err)
	}

	envelope := secrt.Envelope{}

	envelope.Metadata, err = endpoint.Encrypt(clearmeta, user.PublicKey)
	if err != nil {
		return fmt.Errorf("unable to encrypt envelope: %w", err)
	}

	envelope.Payload, err = endpoint.Encrypt(plaintext, user.PublicKey)
	if err != nil {
		return fmt.Errorf("unable to encrypt payload: %w", err)
	}

	envelopeJS, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("unable to encode envelope: %w", err)
	}

	if len(envelopeJS) > server.MessageSizeLimit {
		return ErrSecretTooBig
	}

	endpointURL := endpoint.URL + "message/" + recipient

	req, err := http.NewRequest("POST", endpointURL, bytes.NewReader(envelopeJS))
	if err != nil {
		return err
	}

	if err = endpoint.SetSignature(req); err != nil {
		return fmt.Errorf("unable to set signature: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("share failed: %s: %s", resp.Status, body)
	}

	var shareResponse secrt.SendResponse
	if err = json.NewDecoder(resp.Body).Decode(&shareResponse); err != nil {
		return fmt.Errorf("unable to decode share response: %w", err)
	}

	if *longFormat {
		fmt.Println(shareResponse.ID.String())
	} else {
		fmt.Println(shareResponse.ID.String()[:8])
	}

	return nil
}

// CmdGet gets a secret. You can use either the short, 8-character UUID, or the full UUID
// If there's more than one secret with the same short ID, the server will send us an error.
func CmdGet(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	targetFilename := flags.String("o", "", "output to the given filename")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("unable to parse flags: %w", err)
	}

	// FIXME: better handling of URL
	endpointURL := endpoint.URL + "message/" + flags.Arg(0)

	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		return err
	}

	if err = endpoint.SetSignature(req); err != nil {
		return fmt.Errorf("unable to set signature: %w", err)
	}

	req.Header.Set("Accept", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("message %s not found", args[0])
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unable to get message: %s %s", resp.Status, body)
	}

	body, _ := io.ReadAll(resp.Body)

	peerId := resp.Header.Get("Peer-ID")

	cleartext, err := endpoint.Decrypt(config, peerId, body)

	if err != nil {
		return fmt.Errorf("unable to decrypt message: %w", err)
	}

	var target = os.Stdout
	if *targetFilename != "" {
		target, err = os.OpenFile(*targetFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("unable to open output file %s: %w", targetFilename, err)
		}
	}

	defer target.Close()

	_, err = target.Write(cleartext)
	if err != nil {
		return err
	}

	return nil
}

// CmdRm asks the server to delete a message.
func CmdRm(config *Config, endpoint *Endpoint, args []string) error {

	// FIXME: better handling of URL
	endpointURL := endpoint.URL + "message/" + args[0]

	req, err := http.NewRequest("DELETE", endpointURL, nil)
	if err != nil {
		return err
	}

	if err = endpoint.SetSignature(req); err != nil {
		return fmt.Errorf("unable to set signature: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("message %s not found", args[0])
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unable to delete message: %s %s", resp.Status, body)
	}

	return nil
}

// readInput reads a byte slice from a file or stdin.
// If the filename is "-" or if it's outside the array, read from stdin.
// Otherwise, read from the file.
//
// Args is the list of arguments, and arg is the zero-value index of the argument we
// are looking for.
func readInput(args []string, arg int) ([]byte, *secrt.Metadata, error) {
	metadata := &secrt.Metadata{}

	// Use a filename, or just stdin?
	var reader io.Reader
	if len(args) > arg {
		file, err := os.Open(args[arg])
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

func (endpoint *Endpoint) Encrypt(plaintext []byte, peerKey []byte) ([]byte, error) {
	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of collisions.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("unable to generate nonce: %w", err)
	}

	// Prefix the message with a version number of the ciphertext message.
	// Current version is zero.
	var ciphertext = []byte{0}

	// Append the nonce, which is a fixed length (24 bytes).
	ciphertext = append(ciphertext, nonce[:]...)

	// Encrypt the message itself and append to the nonce + public key
	return box.Seal(ciphertext, plaintext, &nonce, secrt.To32(peerKey), secrt.To32(endpoint.PrivateKey)), nil
}

func (endpoint *Endpoint) Decrypt(config *Config, peerID string, ciphertext []byte) ([]byte, error) {
	// Check that the version number works with us.
	if ciphertext[0] != 0 {
		return nil, fmt.Errorf("ciphertext version (%d) is not supported. Try upgrading `secret`", ciphertext[0])
	}

	peer, err := endpoint.GetPeer(config, peerID)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	var out []byte
	out, ok := box.Open(out, ciphertext[25:], &nonce, secrt.To32(peer.PublicKey), secrt.To32(endpoint.PrivateKey))

	if !ok {
		return nil, fmt.Errorf("unable to authenticate message from %s", peerID)
	}

	return out, nil
}
