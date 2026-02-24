package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/commandquery/secrt/jtp"
)

// CmdRm asks the server to delete a message.
func CmdRm(config *Config, endpoint *Endpoint, args []string) error {

	msgUuid, err := FindMessageID(config, args[0])
	if err != nil {
		return fmt.Errorf("could not find message ID: %v", err)
	}

	if err := Call(endpoint, jtp.Nil, jtp.Nil, "DELETE", "message", msgUuid.String()); err != nil {
		return fmt.Errorf("unable to remove message: %w", err)
	}

	cacheDir := filepath.Join(config.store, "cache")
	cacheFile := filepath.Join(cacheDir, args[0])

	err = os.Remove(cacheFile)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return fmt.Errorf("could not remove cache file: %w", err)
}
