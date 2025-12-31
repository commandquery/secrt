package client

//
// This library contains all the code necessary to parse a user's
// secret configuration (in ~/.config/secret) and extract the
// credentials from that file.
//

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

type KeyStoreType string

const (
	KeyStoreClear    KeyStoreType = "clear"
	KeyStorePassword KeyStoreType = "password"
	KeyStorePlatform KeyStoreType = "platform" // Platform keystore. Uses zalando/go-keyring.
)

// Peer contains information about other users.
type Peer struct {
	PeerID    string `json:"peerID"`
	PublicKey []byte `json:"publicKey"`
}

// ConfigVersion is current default version of the configuration file.
const ConfigVersion = 1

// Config represents the client configuration file.
type Config struct {
	Version    int                  `json:"version"` // Config file version
	Store      string               `json:"-"`       // Location of secrets store
	Stored     bool                 `json:"-"`       // Indicates if the config came from disk (not in JSON)
	Servers    map[string]*Endpoint `json:"servers"` // 0th server is the default server
	Properties *Properties          `json:"properties"`
}

// PrivateKeyEnvelope is a concrete envelope around an abstract PrivateKeyStore interface.
type PrivateKeyEnvelope struct {
	Type       KeyStoreType    `json:"type"`       // The dynamic KeyStore type, used for marshal/unmarshal
	Properties json.RawMessage `json:"properties"` // The KeyStore is marshalled into this field.
	keyStore   PrivateKeyStore // The KeyStore is instantiated into this field.
}

// PrivateKeyStore provides a mechanism whereby a private key can be wrapped
// using a variety of methods. This might include storing the private key offboard,
// e.g. via macOS keychain.
//
// Note that there is only a single, canonical private key per endpoint - the key from which the
// public key is derived - but that key can be encoded and stored in multiple ways. To add a new
// encoding (say, touch ID), it's necessary to first use an existing encoding to retreive the underlying key.
type PrivateKeyStore interface {
	Type() KeyStoreType             // Returns the type of this store
	IsUnsealed() bool               // Indicates if the private key has been unsealed.
	Unseal() error                  // Requests that the private key be unsealed.
	GetPrivateKey() ([]byte, error) // Requests the private key material
	Marshal() ([]byte, error)       // Marshal to JSON
	Unmarshal([]byte) error         // Unmarshal to the type.
}

// Endpoint represents a single server as seen from a Client.
// Most of the configuration is specific to the selected server.
type Endpoint struct {
	URL              string                `json:"url"`              // Endpoint URL
	PeerID           string                `json:"peerID"`           // Actual PeerID for this user
	ServerKey        []byte                `json:"serverKey"`        // Public key of this server
	PrivateKeyStores []*PrivateKeyEnvelope `json:"privateKeyStores"` // Set of private keys, in order of user preference.
	PublicKey        []byte                `json:"publicKey"`        // Public key for the private key
	Peers            map[string]*Peer      `json:"peers"`            // Contains info about other users
}

// LoadClientConfig loads the secret configuration, if there is one.
// Returns an empty object (with Stored == false) if no configuration exists.
func LoadClientConfig(store string) (*Config, error) {
	configJS, err := os.ReadFile(store)
	if os.IsNotExist(err) {
		// return an empty, configured object.
		return &Config{
			Version: ConfigVersion,
			Stored:  false,
			Store:   store,
			Servers: make(map[string]*Endpoint),
			Properties: &Properties{
				AcceptPeers: true,
			}}, nil
	}

	if err != nil {
		return nil, err
	}

	config := Config{Stored: true, Store: store}
	err = config.Unmarshal(configJS)
	if err != nil {
		return nil, err
	}

	if config.Version > ConfigVersion {
		return nil, fmt.Errorf("unable to load version %d secrets; please upgrade", config.Version)
	}

	return &config, nil
}

// Save a secret configuration. This is saved to the location from which it
// was loaded.
func (config *Config) Save() error {
	secretFile := config.Store
	contents, err := config.Marshal()
	if err != nil {
		return err
	}

	contents = append(contents, '\n')

	err = os.WriteFile(secretFile, contents, 0600)
	return err
}

// GetFileStore returns the path to the named file.
func (config *Config) GetFileStore(filename string) (string, error) {
	uuname := uuid.NewSHA1(uuid.MustParse("F41E83C3-B3EE-4194-8B0F-5D1932041A86"), []byte(filename)).String()

	// Create the directory if we need to.
	secretStore := config.Store + "/files"
	_, err := os.Stat(secretStore)
	if err == nil {
		return secretStore + "/" + uuname, nil
	}

	err = os.MkdirAll(secretStore, 0700)
	if err != nil && err != os.ErrExist {
		return "", err
	}

	return secretStore + "/" + uuname, nil
}

// Enrol with the given server. Enrolling means the server knows about
// me, and I know the server's public key.
func (endpoint *Endpoint) enrol() error {
	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	u.Path = path.Join(u.Path, "enrol", url.PathEscape(endpoint.PeerID))

	// Post my public key
	resp, err := http.Post(u.String(), "application/octet-stream", bytes.NewReader(endpoint.PublicKey))
	if err != nil {
		return fmt.Errorf("unable to enrol: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Println("enrolment completed")
	case http.StatusAccepted:
		fmt.Println("enrolment requested")
	case http.StatusConflict:
		return fmt.Errorf("user already enrolled")
	default:
		return fmt.Errorf("unexpected status from server: %s", resp.Status)
	}

	serverKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read server key: %w", err)
	}

	endpoint.ServerKey = serverKey
	return nil
}

func NewKeyStore(storeType KeyStoreType, privateKey []byte) (PrivateKeyStore, error) {
	switch storeType {
	case KeyStoreClear:
		return NewClearKeyStore(privateKey), nil
	case KeyStorePassword:
		// TODO
		return nil, fmt.Errorf("unsupported key store type: %s", storeType)
	case KeyStorePlatform:
		// TODO
		return nil, fmt.Errorf("unsupported key store type: %s", storeType)
	default:
		return nil, fmt.Errorf("unsupported key store type: %s", storeType)

	}
}

// AddEndpoint adds a new server to the config, and generates a new, cleartext keypair for that server.
// TODO: shouldn't default to a clear key store; possibly needs the key to be passed in.
func (config *Config) AddEndpoint(peerID, serverURL string, storeType KeyStoreType) error {

	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	keyStore, err := NewKeyStore(storeType, private[:])
	if err != nil {
		return err
	}

	endpoint := &Endpoint{
		URL:    serverURL,
		PeerID: peerID,
		PrivateKeyStores: []*PrivateKeyEnvelope{
			{Type: KeyStoreClear, keyStore: keyStore},
		},
		PublicKey: public[:],
		Peers:     make(map[string]*Peer),
	}

	err = endpoint.enrol()
	if err != nil {
		return fmt.Errorf("unable to enrol user at %s: %w", serverURL, err)
	}

	config.Servers[serverURL] = endpoint

	if config.Properties.Server == "" {
		config.Properties.Server = serverURL
	}
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

	return nil
}

// Marshal returns the JSON representation of the config. Before marshalling, it updates the
// KeyStore JSON representation, which enables load/save of the underlying interface data.
func (config *Config) Marshal() ([]byte, error) {
	var err error

	for _, server := range config.Servers {
		for _, key := range server.PrivateKeyStores {
			key.Properties, err = key.keyStore.Marshal()
			if err != nil {
				return nil, err
			}
		}
	}

	return json.MarshalIndent(config, "", "  ")
}

// Unmarshal reads JSON and updates the associated config. As part of the unmarshalling process,
// it creates concrete KeyStore instances (PrivateKeyStore interface) based on the PrivateKeyEnvelope
// types.
func (config *Config) Unmarshal(data []byte) error {
	err := json.Unmarshal(data, config)
	if err != nil {
		return fmt.Errorf("unable to parse config: %w", err)
	}

	for _, server := range config.Servers {
		for _, key := range server.PrivateKeyStores {
			switch key.Type {
			case KeyStoreClear:
				ks := &ClearKeyStore{}
				err = ks.Unmarshal(key.Properties)
				if err != nil {
					return err
				}

				key.keyStore = ks
			}
		}
	}

	return nil
}
