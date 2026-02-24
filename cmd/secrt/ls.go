package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	secrt "github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
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
func getListItems(config *Config, endpoint *Endpoint) ([]*ListItem, error) {
	var inbox secrt.Inbox
	if err := Call(endpoint, jtp.Nil, &inbox, "GET", "inbox"); err != nil {
		if errors.Is(err, jtp.ErrNoContent) {
			return nil, nil
		}
		return nil, err
	}

	messageIndex := make(map[uuid.UUID]bool)
	for _, msgId := range inbox.MessageIDs {
		messageIndex[msgId] = true
	}

	// a cache doesn't necessarily exist.
	if config.Properties.Cache {
		cache := filepath.Join(config.store, "cache")
		cacheEntries, err := os.ReadDir(cache)
		if err == nil {
			for _, cacheFile := range cacheEntries {
				id, err := uuid.Parse(cacheFile.Name())
				if err != nil {
					_, _ = fmt.Fprintln(os.Stderr, "unexpected file in cache directory:", cacheFile.Name())
					continue
				}
				messageIndex[id] = true
			}
		}
	}

	// no messages?
	if len(messageIndex) == 0 {
		return nil, nil
	}

	var listItems []*ListItem

	for msgID, _ := range messageIndex {
		entry, err := getListEntry(config, endpoint, msgID)
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
func CmdLs(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("ls", flag.ContinueOnError)
	jsFormat := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return err
	}

	listItems, err := getListItems(config, endpoint)
	if err != nil {
		return err
	}

	if *jsFormat {
		return printJSInbox(listItems)
	}

	return printInbox(listItems)
}

func getListEntry(config *Config, endpoint *Endpoint, msgID uuid.UUID) (*ListItem, error) {

	var entry *ListItem
	cleartext, err := GetCleartext(config, endpoint, msgID)

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
