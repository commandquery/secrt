package client

import (
	"os"
	"path/filepath"
)

// GetStoreLocation returns the filename where the secret configuration will be stored.
// If necessary, a store directory will be created.
func GetStoreLocation() string {
	// TODO: get store location from environment.

	configDir, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}

	storeDir := filepath.Join(configDir, "secrt")
	if err = os.MkdirAll(storeDir, 0700); err != nil {
		panic(err)
	}

	return filepath.Join(storeDir, "store.json")
}
