package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/commandquery/secret"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/term"
)

func confirm(prompt string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}

	fmt.Printf("%s [y/n] ", prompt)

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var b [1]byte
	os.Stdin.Read(b[:])
	fmt.Println() // newline after keypress

	return b[0] == 'y' || b[0] == 'Y'
}

// GetPeer returns the public key for a given peer (if known).
func (endpoint *Endpoint) GetPeer(config *Config, peerId string) (*Peer, error) {
	if endpoint.Peers != nil {
		entry, ok := endpoint.Peers[peerId]
		if ok {
			return entry, nil
		}
	}

	if !config.Properties.AcceptPeers {
		return nil, fmt.Errorf("unknown peer %s", peerId)
	}

	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	u.Path = path.Join(u.Path, "publickey", url.PathEscape(peerId))

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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("send failed: %s: %s", resp.Status, body)
	}

	key, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read public key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(key))
	}

	fmt.Println("Adding new peer", peerId)
	peer := &Peer{
		PeerID:    peerId,
		PublicKey: key,
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
	signature := &secret.Signature{
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

// Send a secret to a peer.
func CmdShare(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("share", flag.ContinueOnError)
	longFormat := flags.Bool("l", false, "display the full uuid")
	if err := flags.Parse(args); err != nil {
		return err
	}

	args = flags.Args()
	recipient := args[0]

	plaintext, err := readInput(flags.Args(), 1)
	if err != nil {
		return err
	}

	user, err := endpoint.GetPeer(config, recipient)
	if err != nil {
		return fmt.Errorf("unable to get peer: %w", err)
	}

	ciphertext, err := endpoint.Encrypt(plaintext, user.PublicKey)
	if err != nil {
		return err
	}

	// FIXME: better handling of URL
	endpointURL := endpoint.URL + "share/" + recipient

	req, err := http.NewRequest("POST", endpointURL, bytes.NewReader(ciphertext))
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

	var shareResponse secret.ShareResponse
	if err = json.NewDecoder(resp.Body).Decode(&shareResponse); err != nil {
		return fmt.Errorf("unable to decode share response: %w", err)
	}

	if *longFormat {
		fmt.Println("shared!", shareResponse.ID.String())
	} else {
		fmt.Println("shared!", shareResponse.ID.String()[:8])
	}

	return nil
}

// List the secrets on the server.
// TODO: include -l option to get the long format
func CmdLs(endpoint *Endpoint, args []string) error {

	// FIXME: better handling of URL
	endpointURL := endpoint.URL + "inbox"

	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		return err
	}

	if err = endpoint.SetSignature(req); err != nil {
		return fmt.Errorf("unable to set signature: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNoContent {
		fmt.Println("No messages")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("inbox failed: %s %s", resp.Status, body)
	}

	var inbox secret.Inbox
	err = json.Unmarshal(body, &inbox)
	if err != nil {
		return fmt.Errorf("unable to parse inbox: %w", err)
	}

	// Work out if there are any collisions with the 8-character short ID.
	// If so, use the long ID.
	prefixMap := make(map[string]bool)
	for _, msg := range inbox.Messages {
		prefix := msg.ID.String()[:8]
		if prefixMap[prefix] {
			printLongInbox(inbox)
			return nil
		}
		prefixMap[prefix] = true
	}

	printShortInbox(inbox)
	return nil
}

func printShortInbox(inbox secret.Inbox) {
	fmt.Printf("%-8s  %10s  %-19s  %-s\n", "ID", "Size", "Sent", "Sender")

	for _, msg := range inbox.Messages {
		ts := time.Unix(msg.Timestamp, 0).Local().Format("2006-01-02 15:04:05")
		fmt.Printf("%8s  %10d  %19s  %s\n", msg.ID.String()[:8], msg.Size, ts, msg.Sender)
	}
}

func printLongInbox(inbox secret.Inbox) {
	fmt.Printf("%-36s  %10s  %-19s  %-s\n", "ID", "Size", "Sent", "Sender")

	for _, msg := range inbox.Messages {
		ts := time.Unix(msg.Timestamp, 0).Local().Format("2006-01-02 15:04:05")
		fmt.Printf("%36s  %10d  %19s  %s\n", msg.ID.String(), msg.Size, ts, msg.Sender)
	}
}

// CmdGet gets a secret. You can use either the short, 8-character UUID, or the full UUID
// If there's more than one secret with the same short ID, the server will send us an error.
func CmdGet(config *Config, endpoint *Endpoint, args []string) error {

	// FIXME: better handling of URL
	endpointURL := endpoint.URL + "message/" + args[0]

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

	_, err = os.Stdout.Write(cleartext)
	if err != nil {
		return err
	}

	return nil
}

// readInput reads a byte slice from a file or stdin.
// If the filename is "-" or if it's outside the array, read from stdin.
// Otherwise, read from the file.
//
// Args is the list of arguments, and arg is the zero-value index of the argument we
// are looking for.
func readInput(args []string, arg int) ([]byte, error) {
	// Use a filename, or just stdin?
	var reader io.Reader
	if len(args) > arg {
		file, err := os.Open(args[arg])
		if err != nil {
			return nil, err
		}

		defer file.Close()
		reader = file
	} else {
		reader = os.Stdin
	}

	return io.ReadAll(reader)
}

func (endpoint *Endpoint) Encrypt(plaintext []byte, peerKey []byte) ([]byte, error) {
	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
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
	return box.Seal(ciphertext, plaintext, &nonce, secret.To32(peerKey), secret.To32(endpoint.PrivateKey)), nil
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
	out, ok := box.Open(out, ciphertext[25:], &nonce, secret.To32(peer.PublicKey), secret.To32(endpoint.PrivateKey))

	if !ok {
		return nil, fmt.Errorf("unable to authenticate message from %s", peerID)
	}

	return out, nil
}
