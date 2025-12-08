package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"
)

// GetPeer returns the public key for a given peer (if known).
func (endpoint *Endpoint) GetPeer(peerId string) (*Peer, error) {
	if endpoint.Peers != nil {
		entry, ok := endpoint.Peers[peerId]
		if ok {
			return entry, nil
		}
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
	req.Header.Set("Signature", endpoint.GetSignature())

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

	fmt.Println("Adding peer", peerId)
	peer := &Peer{
		PeerID:    peerId,
		PublicKey: key,
	}

	endpoint.Peers[peerId] = peer
	return peer, nil
}

// GetSignature returns a Signature header, which is just the peer ID
// followed by the current timestamp, encrypted for the server itself.
// This authenticates us to the server within the request header, giving
// us strong access control without a handshake.
func (endpoint *Endpoint) GetSignature() string {
	msg := fmt.Sprintf("%d", time.Now().Unix())

	ciphertext, err := encrypt(endpoint, []byte(msg), endpoint.ServerKey)
	if err != nil {
		exit(1, fmt.Errorf("unable to generate signature: %w", err))
	}

	// entire signature is json encoded to avoid issues with little bobby table's peer ID.
	signature := &Signature{
		Peer: endpoint.PeerID,
		Sig:  ciphertext,
	}

	js, err := json.Marshal(signature)
	if err != nil {
		exit(1, fmt.Errorf("unable to marshal signature: %w", err))
	}

	return base64.StdEncoding.EncodeToString(js)
}

// Send a secret to a peer.
func cmdSend(endpoint *Endpoint, args []string) error {

	// TODO: use flags package
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: send <user> [file]")
	}

	recipient := args[0]

	plaintext, err := readInput(args, 1)
	if err != nil {
		return err
	}

	user, err := endpoint.GetPeer(recipient)
	if err != nil {
		return fmt.Errorf("unable to get peer: %w", err)
	}

	ciphertext, err := encrypt(endpoint, plaintext, user.PublicKey)
	if err != nil {
		return err
	}

	// FIXME: better handling of URL
	endpointURL := endpoint.URL + "send/" + recipient

	req, err := http.NewRequest("POST", endpointURL, bytes.NewReader(ciphertext))
	if err != nil {
		return err
	}

	req.Header.Set("Signature", endpoint.GetSignature())
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("send failed: %s: %s", resp.Status, body)
	}

	return nil
}

// List the secrets on the server.
// TODO: include -l option to get the long format
func cmdLs(endpoint *Endpoint, args []string) error {

	// FIXME: better handling of URL
	endpointURL := endpoint.URL + "inbox"

	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Signature", endpoint.GetSignature())
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

	var inbox Inbox
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

func printShortInbox(inbox Inbox) {
	fmt.Printf("%-8s  %10s  %-19s  %-s\n", "ID", "Size", "Sent", "Sender")

	for _, msg := range inbox.Messages {
		ts := time.Unix(msg.Timestamp, 0).Local().Format("2006-01-02 15:04:05")
		fmt.Printf("%8s  %10d  %19s  %s\n", msg.ID.String()[:8], msg.Size, ts, msg.Sender)
	}
}

func printLongInbox(inbox Inbox) {
	fmt.Printf("%-36s  %10s  %-19s  %-s\n", "ID", "Size", "Sent", "Sender")

	for _, msg := range inbox.Messages {
		ts := time.Unix(msg.Timestamp, 0).Local().Format("2006-01-02 15:04:05")
		fmt.Printf("%36s  %10d  %19s  %s\n", msg.ID.String(), msg.Size, ts, msg.Sender)
	}
}

// Get a secret. You can use either the short, 8-character UUID, or the full UUID
// If there's more than one secret with the same short ID, the server will send us an error.
func cmdGet(endpoint *Endpoint, args []string) error {

	// FIXME: better handling of URL
	endpointURL := endpoint.URL + "message/" + args[0]

	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Signature", endpoint.GetSignature())
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

	cleartext, err := decrypt(endpoint, peerId, body)

	if err != nil {
		return fmt.Errorf("unable to decrypt message: %w", err)
	}

	_, err = os.Stdout.Write(cleartext)
	if err != nil {
		return err
	}

	return nil
}
