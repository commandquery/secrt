package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/commandquery/secrt/jtp"
)

// CmdRm asks the server to delete a message. It returns an error if the cache
// or server fails to remove the secret, or if a secret wasn't removed from anywhere.
// Deleting a secret is sensitive; if it's still hanging around somewhere, that
// might be a problem.
func CmdRm(cache *Cache, args []string) error {

	msgUuid, err := cache.FindMessageID(args[0])
	if err != nil {
		return fmt.Errorf("could not find message ID: %v", err)
	}

	// Remember if the server-side delete worked or not. After this call, the value will
	// be either nil or jtp.ErrNotFound.
	var serverErr error
	if serverErr = Call(cache.Endpoint, jtp.Nil, jtp.Nil, "DELETE", "message", msgUuid.String()); serverErr != nil {
		if !errors.Is(serverErr, jtp.ErrNotFound) {
			return fmt.Errorf("unable to remove message: %w", serverErr)
		}
	}

	// If the file can't be found on either client or server, report that to the user.
	// This avoids the problem of the user attempting to delete the wrong message ID.
	// If we did successfully remove a message from either server or cache, return nil.
	cacheErr := cache.Remove(msgUuid)
	if cacheErr == nil && serverErr == nil {
		return nil
	}

	if errors.Is(cacheErr, os.ErrNotExist) && errors.Is(serverErr, jtp.ErrNotFound) {
		return fmt.Errorf("unknown message: %v", msgUuid)
	}

	return fmt.Errorf("could not remove cache file: %w", cacheErr)
}
