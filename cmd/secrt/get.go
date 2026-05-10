package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/commandquery/secrt"
)

// Cleartext is a message that's been decrypted. Returned by GetCleartext.
type Cleartext struct {
	Message          *secrt.Message
	UnacceptablePeer bool
	Metadata         *secrt.Metadata
	Cleartext        []byte
	Claims           *secrt.Claims
}

// CmdGet gets a secret message (and decrypts it). You can use either the short, 8-character UUID, or the full UUID
// If there's more than one secret with the same short MessageID, the server will send us an error.
func CmdGet(cache *Cache, args []string) error {

	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	targetFilename := flags.String("o", "", "output to the given filename")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("unable to parse flags: %w", err)
	}

	args = flags.Args()
	if len(args) != 1 {
		return fmt.Errorf("message MessageID not specified")
	}

	cleartext, err := cache.FindMessage(args[0])
	if err != nil {
		return fmt.Errorf("unable to find message %s: %w", args[0], err)
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
