package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

var AutoEnrolOptions = []string{"true", "false", "approve", ""}

var Config struct {
	Store            string `split_words:"true"`
	AutoEnrol        string `split_words:"true"` // See AutoEnrolOptions
	PathPrefix       string `split_words:"true" default:"/"`
	ServerConfigPath string `split_words:"true" default:"./server.json"`
}

func initConfig() error {
	if err := envconfig.Process("secret", &Config); err != nil {
		return err
	}

	if !slices.Contains(AutoEnrolOptions, Config.AutoEnrol) {
		return fmt.Errorf("unexpected value for CONFIG_AUTO_ENROL: %s", Config.AutoEnrol)
	}

	if !strings.HasSuffix(Config.PathPrefix, "/") {
		Config.PathPrefix += "/"
	}

	return nil
}

// GetStoreLocation returns the filename where the secret configuration will be stored.
func GetStoreLocation() string {
	storeLocation := Config.Store
	if storeLocation != "" {
		return storeLocation
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}

	storeLocation = filepath.Join(configDir, "secret", "store.json")
	return storeLocation
}
