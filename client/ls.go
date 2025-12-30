package client

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	secrt "github.com/commandquery/secrt"
)

// We use the inbox message and metadata to generate a List entry which is then
// displayed to the user in either short or long format. If we aren't able to
// download the peer's public key, we won't be able to display metadata.
type lsEntry struct {
	ID              string
	Timestamp       time.Time
	Sender          string
	Filename        string
	Description     string
	FileDescription string
	Size            int
}

// List the secrets on the server.
// TODO: include -l option to get the long format
func CmdLs(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("ls", flag.ContinueOnError)
	longFormat := flags.Bool("l", false, "long format")
	jsFormat := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return err
	}

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

	var inbox secrt.Inbox
	err = json.Unmarshal(body, &inbox)
	if err != nil {
		return fmt.Errorf("unable to parse inbox: %w", err)
	}

	if *jsFormat {
		return printJSInbox(config, endpoint, inbox)
	}

	// If longformat was requested.
	if *longFormat {
		printLongInbox(config, endpoint, inbox)
		return nil
	}

	// Work out if there are any collisions with the 8-character short ID.
	// If so, use the long ID.
	prefixMap := make(map[string]bool)
	for _, msg := range inbox.Messages {
		prefix := msg.ID.String()[:8]
		if prefixMap[prefix] {
			printLongInbox(config, endpoint, inbox)
			return nil
		}
		prefixMap[prefix] = true
	}

	printShortInbox(config, endpoint, inbox)
	return nil
}

func getLsEntry(config *Config, endpoint *Endpoint, msg *secrt.InboxMessage) *lsEntry {

	lsEntry := &lsEntry{
		ID:              msg.ID.String(),
		Timestamp:       time.Unix(msg.Timestamp, 0).Local(),
		Sender:          msg.Sender,
		FileDescription: "",
		Size:            msg.Size,
	}

	var metadata secrt.Metadata

	metajs, err := endpoint.Decrypt(config, msg.Sender, msg.Metadata)
	if err != nil {

		// If the peer's unknown, just note it in the listing.
		if errors.Is(err, ErrUnknownPeer) {
			lsEntry.FileDescription = "unknown peer"
			return lsEntry
		}

		lsEntry.FileDescription = fmt.Sprintf("unable to decrypt metadata: %v", err)
		return lsEntry
	}

	if err = json.Unmarshal(metajs, &metadata); err != nil {
		lsEntry.FileDescription = fmt.Sprintf("unable to parse metadata: %v", err)
		return lsEntry
	}

	lsEntry.Size = metadata.Size
	lsEntry.Filename = metadata.Filename
	lsEntry.Description = metadata.Description

	if metadata.Description != "" {
		lsEntry.FileDescription = fmt.Sprintf("%s (%s)", metadata.Filename, metadata.Description)
	} else {
		lsEntry.FileDescription = fmt.Sprintf("%s", metadata.Filename)
	}

	return lsEntry
}

func printJSInbox(config *Config, endpoint *Endpoint, inbox secrt.Inbox) error {
	lsEntries := make([]*lsEntry, 0, len(inbox.Messages))

	for _, msg := range inbox.Messages {
		lsEntries = append(lsEntries, getLsEntry(config, endpoint, &msg))
	}

	return json.NewEncoder(os.Stdout).Encode(lsEntries)
}

func printShortInbox(config *Config, endpoint *Endpoint, inbox secrt.Inbox) {

	now := time.Now()
	var ts string

	fmt.Printf("%-8s %-24.24s %6s %-10s %s\n", "ID", "Peer", "Size", "Sent", "Description")

	for _, msg := range inbox.Messages {
		lsEntry := getLsEntry(config, endpoint, &msg)

		if lsEntry.Timestamp.Year() == now.Year() && lsEntry.Timestamp.YearDay() == now.YearDay() {
			ts = lsEntry.Timestamp.Format("15:04:05")
		} else {
			ts = lsEntry.Timestamp.Format("2006-01-02")
		}

		fmt.Printf("%8s %-24.24s %6d %-10s %s\n", lsEntry.ID[:8], lsEntry.Sender, lsEntry.Size, ts, lsEntry.FileDescription)
	}
}

func printLongInbox(config *Config, endpoint *Endpoint, inbox secrt.Inbox) {
	fmt.Printf("%-36s %-24.24s %6s %-19s %s\n", "ID", "Peer", "Size", "Sent", "Description")

	for _, msg := range inbox.Messages {
		lsEntry := getLsEntry(config, endpoint, &msg)
		ts := lsEntry.Timestamp.Format("2006-01-02 15:04:05")
		fmt.Printf("%36s %-24.24s %6d %-19s %s\n", lsEntry.ID, lsEntry.Sender, lsEntry.Size, ts, lsEntry.FileDescription)
	}
}
