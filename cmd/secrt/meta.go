package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/commandquery/secrt"
)

// CmdMeta prints metadata about the given message
func CmdMeta(cache *Cache, args []string) error {

	if len(args) != 1 {
		return fmt.Errorf("message ID not specified")
	}

	cleartext, err := cache.FindMessage(args[0])
	if err != nil {
		return fmt.Errorf("unable to find message %s: %w", args[0], err)
	}

	var meta = struct {
		Claims   *secrt.Claims   `json:"claims"`
		Metadata *secrt.Metadata `json:"metadata"`
	}{
		Claims:   cleartext.Claims,
		Metadata: cleartext.Metadata,
	}

	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(meta)
}
