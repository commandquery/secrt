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

// Endpoint represents a single server as seen from a Client.
// Most of the configuration is specific to the selected server.
type Endpoint struct {
	URL        string           `json:"url"`        // Endpoint URL
	PeerID     string           `json:"peerID"`     // Actual PeerID for this user
	ServerKey  []byte           `json:"serverKey"`  // Public key of this server
	PrivateKey []byte           `json:"privateKey"` // Private key, encrypted with user's password
	PublicKey  []byte           `json:"publicKey"`  // Public key for the private key
	Peers      map[string]*Peer `json:"peers"`      // Contains info about other users
}

// LoadSecretConfiguration loads the secret configuration, if there is one.
// Returns an empty object (with Stored == false) if no configuration exists.
func LoadSecretConfiguration(store string) (*Config, error) {
	secretContents, err := os.ReadFile(store)
	if os.IsNotExist(err) {
		// return an empty, configured object.
		return &Config{
			Version: ConfigVersion,
			Stored:  false,
			Store:   store,
			Servers: make(map[string]*Endpoint),
			Properties: &Properties{
				AcceptPeers: true,
				Metadata:    true,
			}}, nil
	}

	if err != nil {
		return nil, err
	}

	config := Config{Stored: true, Store: store}
	err = json.Unmarshal(secretContents, &config)
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
	contents, err := json.MarshalIndent(config, "", "  ")
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

	if resp.StatusCode == http.StatusAccepted {
		fmt.Println("enrolment requested")
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from server: %s", resp.Status)
	} else {
		fmt.Println("enrolment completed")
	}

	serverKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read server key: %w", err)
	}

	endpoint.ServerKey = serverKey
	return nil
}

// AddServer adds a new server to the config, and generates a new keypair for that server.
func (config *Config) AddServer(peerID, serverURL string) error {

	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	endpoint := &Endpoint{
		URL:        serverURL,
		PeerID:     peerID,
		PrivateKey: private[:],
		PublicKey:  public[:],
		Peers:      make(map[string]*Peer),
	}

	err = endpoint.enrol()
	if err != nil {
		return fmt.Errorf("unable to fetch key from server %s: %w", serverURL, err)
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
