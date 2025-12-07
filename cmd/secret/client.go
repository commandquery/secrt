package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// GetSignature returns a Signature header, which is just the peer ID
// followed by the current timestamp, encrypted for the server itself.
// This authenticates us to the server, giving us access control.
func (endpoint *Endpoint) GetSignature() string {
	msg := fmt.Sprintf("%d", time.Now().Unix())

	//log.Printf("signing with public key: %s", base64.StdEncoding.EncodeToString(endpoint.PublicKey))

	ciphertext, err := encrypt(endpoint, []byte(msg), endpoint.ServerKey)
	if err != nil {
		exit(1, fmt.Errorf("unable to generate signature: %w", err))
	}

	// entire signature is json encoded to avoid issues with little bobby tables' peer ID.
	signature := &Signature{
		Peer: endpoint.UserID,
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
	url := endpoint.URL + "send/" + recipient

	req, err := http.NewRequest("POST", url, bytes.NewReader(ciphertext))
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
func cmdLs(endpoint *Endpoint, args []string) error {

	// FIXME: better handling of URL
	url := endpoint.URL + "inbox"

	req, err := http.NewRequest("GET", url, nil)
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
	url := endpoint.URL + "message/" + args[0]

	req, err := http.NewRequest("GET", url, nil)
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
