package main

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/google/uuid"
)

// ListItem is a summary of a message based on cleartext metadata. If we aren't able to
// download the peer's public key, we won't be able to display metadata, and UnknownPeer is set.
type ListItem struct {
	ID              string `json:"messageID,omitempty"`
	Timestamp       int64  `json:"timestamp"`
	Sender          string `json:"sender,omitempty"`
	UnknownPeer     bool   `json:"unknownPeer,omitempty"`
	Filename        string `json:"filename,omitempty"`
	Description     string `json:"description,omitempty"`
	FileDescription string `json:"-"`
	Size            int    `json:"size,omitempty"`
}

// Merge any new items from the server with a list of items already in cache.
func getListItems(cache *Cache) ([]*ListItem, error) {
	entries, err := cache.Entries()
	if err != nil {
		return nil, err
	}

	// no messages?
	if len(entries) == 0 {
		return nil, nil
	}

	var listItems []*ListItem

	for _, msgID := range entries {
		entry, err := getListEntry(cache, msgID)
		if err != nil {
			return nil, fmt.Errorf("unable to get ls entry: %w", err)
		}

		listItems = append(listItems, entry)
	}

	slices.SortFunc(listItems, func(a, b *ListItem) int {
		return cmp.Compare(a.Timestamp, b.Timestamp)
	})

	return listItems, nil
}

// CmdLs lists the secrets waiting on the server.
func CmdLs(cache *Cache, args []string) error {

	flags := flag.NewFlagSet("ls", flag.ContinueOnError)
	jsFormat := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return err
	}

	listItems, err := getListItems(cache)
	if err != nil {
		return err
	}

	if *jsFormat {
		return printJSInbox(listItems)
	}

	return printInbox(listItems)
}

func getListEntry(cache *Cache, msgID uuid.UUID) (*ListItem, error) {

	var entry *ListItem
	cleartext, err := cache.GetCleartext(msgID)

	if err != nil {
		return nil, fmt.Errorf("unable to get message: %w", err)
	}

	// GetCleartext may return a partial message if a peer was unacceptable.
	entry = &ListItem{
		ID:              cleartext.Claims.Message.String(),
		Timestamp:       cleartext.Claims.Timestamp,
		FileDescription: "",
		Sender:          cleartext.Claims.Alias,
	}

	if cleartext.UnacceptablePeer {
		entry.Size = len(cleartext.Message.Payload)
		entry.Filename = "unacceptable peer"
		return entry, nil
	}

	entry.Size = len(cleartext.Cleartext)

	if cleartext.Metadata != nil {
		entry.Filename = cleartext.Metadata.Filename
		entry.Description = cleartext.Metadata.Description

		if cleartext.Metadata.Description != "" {
			entry.FileDescription = fmt.Sprintf("%s (%s)", cleartext.Metadata.Filename, cleartext.Metadata.Description)
		} else {
			entry.FileDescription = fmt.Sprintf("%s", cleartext.Metadata.Filename)
		}
	}

	return entry, nil
}

func printJSInbox(listItems []*ListItem) error {
	return json.NewEncoder(os.Stdout).Encode(listItems)
}

func printInbox(listItems []*ListItem) error {
	fmt.Printf("%-36s %-24.24s %6s %-19s %s\n", "MessageID", "Sender", "Size", "Sent", "Description")

	for _, listItem := range listItems {
		ts := time.Unix(listItem.Timestamp, 0).Local().Format("2006-01-02 15:04:05")
		fmt.Printf("%36s %-24.24s %6d %-19s %s\n", listItem.ID, listItem.Sender, listItem.Size, ts, listItem.FileDescription)
	}

	return nil
}
