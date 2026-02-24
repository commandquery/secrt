package main

//
// This library contains all the code necessary to parse a user's
// secret configuration (in ~/.config/secret) and extract the
// credentials from that file.
//

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

type VaultType string

const (
	VaultClear    VaultType = "clear"
	VaultPassword VaultType = "password"
	VaultPlatform VaultType = "platform" // Platform vaule. Uses zalando/go-keyring.
)

// Peer contains information about other users.
type Peer struct {
	Alias        string `json:"alias"`
	BoxPublicKey []byte `json:"boxPublicKey"`
}

// ConfigVersion is current default version of the configuration file.
const ConfigVersion = 1

// Config represents the client configuration file.
type Config struct {
	Version    int         `json:"version"`   // Config file version
	Endpoints  []*Endpoint `json:"endpoints"` // 0th server is the default server
	Properties *Properties `json:"properties"`

	store    string // Location of secrets store
	modified bool   // indicates that the config changed.
}

// StorageEnvelope is a concrete envelope around an abstract Vault interface.
// It provides a way to identify the instance of the key vault that's in use.
type StorageEnvelope struct {
	VaultType  VaultType       `json:"vaultType"`  // The dynamic vault type, used for marshal/unmarshal
	Properties json.RawMessage `json:"properties"` // The concrete Vault is marshalled into this field.
	vault      Vault           // The vault is instantiated into this field.
}

// Vault provides a mechanism whereby sensitive data (private key, auth tokens) can be wrapped
// using a variety of methods. This might include storing the private key offboard,
// e.g. via macOS keychain.
type Vault interface {
	Type() VaultType                    // Returns the type of this store
	IsUnsealed() bool                   // Indicates if the private key has been unsealed.
	Unseal() error                      // Requests that the private key be unsealed.
	Get(key string) ([]byte, error)     // Requests the decrypted material
	Set(key string, value []byte) error // Sets the value for the given key
	Marshal() ([]byte, error)           // Marshal to JSON
	Unmarshal([]byte) error             // Unmarshal to the type.
}

// Endpoint represents a single server as seen from a Client.
// Most of the configuration is specific to the selected server.
//
// Note that there is only a single, canonical private key per endpoint - the key from which the
// public key is derived - but that key can be encoded and stored in multiple vaults. To add a new
// vault (say, touch MessageID), it's necessary to first use an existing encoding to retrieve the underlying key.
type Endpoint struct {
	URL          string             `json:"url"`          // Endpoint URL
	Alias        string             `json:"alias"`        // Alias for this user
	ServerBoxKey []byte             `json:"serverBoxKey"` // Public key of this server
	Vaults       []*StorageEnvelope `json:"vaults"`       // Storage for sensitive data such as private keys and server tokens.
	BoxPublicKey []byte             `json:"boxPublicKey"` // Public key for the private key
	Peers        map[string]*Peer   `json:"peers"`        // Contains info about other users

	// Any newly-added peers are added to this list so we can display them on exit.
	newPeers []*Peer
}

// LoadClientConfig loads the secret configuration, if there is one.
// Returns an empty object (with Stored == false) if no configuration exists.
func LoadClientConfig(storeDirectory string) (*Config, error) {
	storeFile := filepath.Join(storeDirectory, "secrt.json")
	configJS, err := os.ReadFile(storeFile)
	if os.IsNotExist(err) {
		// return an empty, configured object.
		return &Config{
			store:     storeDirectory,
			modified:  true,
			Version:   ConfigVersion,
			Endpoints: make([]*Endpoint, 0, 1),
			Properties: &Properties{
				AcceptPeers: true,
				Telemetry:   true,
				Cache:       true,
			}}, nil
	}

	if err != nil {
		return nil, err
	}

	config := Config{store: storeDirectory}
	err = config.Unmarshal(configJS)
	if err != nil {
		return nil, err
	}

	if config.Version > ConfigVersion {
		return nil, fmt.Errorf("unable to load version %d secrets; please upgrade", config.Version)
	}

	return &config, nil
}

func (config *Config) atomicSave() error {
	contents, err := config.Marshal()
	if err != nil {
		return err
	}
	contents = append(contents, '\n')

	if err = os.MkdirAll(config.store, 0700); err != nil {
		return err
	}

	f, err := os.CreateTemp(config.store, ".tmp-")
	if err != nil {
		return err
	}
	tmpName := f.Name()

	// Clean up on any error path
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}

	if _, err = f.Write(contents); err != nil {
		f.Close()
		return err
	}

	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	configFile := filepath.Join(config.store, "secrt.json")
	if err = os.Rename(tmpName, configFile); err != nil {
		return err
	}

	tmpName = "" // prevent defer from removing
	return nil
}

// Save a secret configuration. This is saved to the location from which it
// was loaded.
func (config *Config) Save() error {

	if !config.modified {
		return nil
	}

	if err := config.atomicSave(); err != nil {
		return fmt.Errorf("could not save config: %v", err)
	}

	return nil
}

// GetFileStore returns the path to the named file.
func (config *Config) GetFileStore(filename string) (string, error) {
	uuname := uuid.NewSHA1(uuid.MustParse("F41E83C3-B3EE-4194-8B0F-5D1932041A86"), []byte(filename)).String()

	// Create the directory if we need to.
	secretStore := config.store + "/files"
	_, err := os.Stat(secretStore)
	if err == nil {
		return secretStore + "/" + uuname, nil
	}

	err = os.MkdirAll(secretStore, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}

	return secretStore + "/" + uuname, nil
}

func NewVault(endpoint *Endpoint, storeType VaultType) (Vault, error) {
	switch storeType {
	case VaultClear:
		return NewClearVault(), nil
	case VaultPassword:
		// TODO
		return nil, fmt.Errorf("unsupported key store type: %s", storeType)
	case VaultPlatform:
		return NewPlatformSecureStore(endpoint)
	default:
		return nil, fmt.Errorf("unsupported key store type: %s", storeType)

	}
}

// GetEndpoint returns any existing endpoint for the given (alias, serverURL) pair.
func (config *Config) GetEndpoint(alias, serverURL string) *Endpoint {
	for _, endpoint := range config.Endpoints {
		if endpoint.URL == serverURL && endpoint.Alias == alias {
			return endpoint
		}
	}

	return nil
}

// DeleteEndpoint deletes any existing endpoint for the given (alias, serverURL) pair.
func (config *Config) DeleteEndpoint(alias, endpointURL string) {
	config.Endpoints = slices.DeleteFunc(config.Endpoints, func(e *Endpoint) bool {
		return e.URL == endpointURL && e.Alias == alias
	})
	config.modified = true
}

// AddEndpoint adds a new server to the config, and generates a new, cleartext keypair for that server.
// This function will only replace an existing endpoint for the given (alias, endpointURL) if force is true.
func (config *Config) AddEndpoint(alias, endpointURL string, storeType VaultType, force bool) error {

	// normalise the endpoint URL to include a trailing slash
	if !strings.HasSuffix(endpointURL, "/") {
		endpointURL += "/"
	}

	// Check if there's an existing enrolment; abort if force isn't set.
	existingEndpoint := config.GetEndpoint(alias, endpointURL)
	if existingEndpoint != nil {
		if !force {
			return ErrExistingEnrolment
		}

		config.DeleteEndpoint(alias, endpointURL)
	}

	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	newEndpoint := &Endpoint{
		URL:          endpointURL,
		Alias:        alias,
		BoxPublicKey: public[:],
		Peers:        make(map[string]*Peer),
	}

	vault, err := NewVault(newEndpoint, storeType)
	if err != nil {
		return fmt.Errorf("unable to initialise value: %w", err)
	}

	if err = vault.Set("boxPrivateKey", private[:]); err != nil {
		return fmt.Errorf("unable to store private key: %w", err)
	}

	newEndpoint.Vaults = []*StorageEnvelope{
		{VaultType: storeType, vault: vault},
	}

	err = newEndpoint.enrol()
	if err != nil {
		return fmt.Errorf("unable to enrol user at %s: %w", endpointURL, err)
	}

	config.Endpoints = append(config.Endpoints, newEndpoint)
	config.modified = true

	return nil
}

// Set a property. The expression is of the form "property=value".
func (config *Config) Set(expression string) error {
	namevalue := strings.Split(expression, "=")
	if len(namevalue) != 2 {
		return fmt.Errorf("invalid expression: %s", expression)
	}

	if err := config.Properties.Set(namevalue[0], namevalue[1]); err != nil {
		return fmt.Errorf("unable to set %s: %w", namevalue[0], err)
	}

	config.modified = true

	return nil
}

// Marshal returns the JSON representation of the config. Before marshalling, it updates the
// Vault JSON representation, which enables load/save of the underlying interface data.
func (config *Config) Marshal() ([]byte, error) {
	var err error

	for _, server := range config.Endpoints {
		for _, key := range server.Vaults {
			key.Properties, err = key.vault.Marshal()
			if err != nil {
				return nil, err
			}
		}
	}

	return json.MarshalIndent(config, "", "  ")
}

// Unmarshal reads JSON and updates the associated config. As part of the unmarshalling process,
// it creates concrete vault instances (Vault interface) based on the StorageEnvelope
// types.
func (config *Config) Unmarshal(data []byte) error {
	err := json.Unmarshal(data, config)
	if err != nil {
		return fmt.Errorf("unable to parse config: %w", err)
	}

	for _, server := range config.Endpoints {
		for _, key := range server.Vaults {
			switch key.VaultType {
			case VaultClear:
				ks := &ClearVault{}
				err = ks.Unmarshal(key.Properties)
				if err != nil {
					return err
				}

				key.vault = ks

			case VaultPlatform:
				ks := &PlatformVault{}
				err = ks.Unmarshal(key.Properties)
				if err != nil {
					return err
				}

				key.vault = ks
			}
		}
	}

	return nil
}
