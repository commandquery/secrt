package main

//
// This library contains all the code necessary to parse a user's
// secret configuration (in ~/.config/secret) and extract the
// double-encrypted credentials from that file.
//
// Note all the secret management code is in this package; we might need
// to move additional code into it from cli/cmd/secret/secret.go over time.
//

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

var DefaultSecretLocation = os.Getenv("SECRETS_DIR")

// Peer contains information about other users, which might later include
// their email address, discord, etc.
type Peer struct {
	Version   int
	PeerID    string `json:"peer"`
	PublicKey []byte `json:"publicKey"`
}

// The current default version of the configuration file.
const ConfigVersion = 1

// Configuration represents a Secret configuration file.
type Configuration struct {
	Version    int                  `json:"version"`    // Config file version
	UserID     string               `json:"id"`         // User's email address
	PrivateKey []byte               `json:"privateKey"` // Private key, encrypted with user's password
	PublicKey  []byte               `json:"publicKey"`  // Public key for the private key
	Peers      map[string]Peer      `json:"peers"`      // Contains info about other users
	Store      string               `json:"-"`          // Location of secrets store
	Stored     bool                 `json:"-"`          // Indicates if the config came from disk (not in JSON)
	Files      map[string]*Metadata `json:"files"`      // List of files in the file store
}

// Metadata contains metadata about an encrypted file. We don't
// store any metadata at the moment, so this will result in a JSON map
// of names to empty objects, which may help us in the future.
type Metadata struct {
}

// Convert the given slice to a 32 byte array.
func To32(bytes []byte) *[32]byte {
	var result [32]byte
	if copy(result[:], bytes) != 32 {
		panic(fmt.Errorf("Attempted to create non-32 bit key"))
	}

	return &result
}

// LoadSecretConfiguration loads the secret configuration, if there is one.
// Returns an empty object (with Stored == false) if no configuration exists.
func LoadSecretConfiguration(store string) (*Configuration, error) {
	secretFile := store + "/keys"
	secretContents, err := os.ReadFile(secretFile)
	if os.IsNotExist(err) {
		// return an empty object.
		return &Configuration{Version: ConfigVersion, Stored: false, Store: store, Files: make(map[string]*Metadata)}, nil
	}

	if err != nil {
		return nil, err
	}

	config := Configuration{Stored: true, Store: store}
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
func (config *Configuration) Save() error {
	secretFile := config.Store + "/keys"
	contents, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	contents = append(contents, '\n')

	err = os.WriteFile(secretFile, contents, 0600)
	return err
}

// GetSecretStore returns the filename where the secret configuration is stored.
func GetSecretStore() (string, error) {
	secretDirectory := DefaultSecretLocation
	if secretDirectory != "" {
		return secretDirectory, nil
	}

	home, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	secretDirectory = filepath.Join(home, "secret")
	err = os.MkdirAll(secretDirectory, 0700)
	if err != nil {
		return "", err
	}

	return secretDirectory, nil
}

// GetPeer returns the public key for a given peer (if known).
func (config *Configuration) GetPeer(peer string) (*Peer, error) {
	if config.Peers == nil {
		return nil, fmt.Errorf("Please use `secret add` to add your peer %s. See `secret help` for more details.", peer)
	}

	entry, ok := config.Peers[peer]
	if !ok {
		return nil, fmt.Errorf("Please use `secret add` to add %s to your directory. See `secret help` for more details.", peer)
	}

	return &entry, nil
}

// GetFileStore returns the path to the named file.
func (config *Configuration) GetFileStore(filename string) (string, error) {
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

// GetFile returns the decrypted version of the named file.
func (config *Configuration) GetFile(filename string) ([]byte, error) {
	loadPath, err := config.GetFileStore(filename)
	if err != nil {
		return nil, err
	}

	// Don't reveal the location of the file; smother the error with
	// something generic.
	loadedFile, err := os.Open(loadPath)
	if err != nil {
		return nil, fmt.Errorf("unable to find secret %s", filename)
	}

	defer loadedFile.Close()
	ciphertext, err := io.ReadAll(loadedFile)
	if err != nil {
		return nil, err
	}

	plaintext, ok := box.OpenAnonymous(nil, ciphertext, To32(config.PublicKey), To32(config.PrivateKey))
	if !ok {
		return nil, fmt.Errorf("unable to decrypt stored object. has your private key changed?")
	}

	return plaintext, nil
}

func (config *Configuration) SaveFile(saveName string, plaintext []byte) error {
	matched, err := regexp.Match("^[a-zA-Z0-9@$_.:-]+$", []byte(saveName))
	if err != nil {
		return err
	}

	if !matched {
		return fmt.Errorf("invalid name %s: stored files must have simple names matching [a-zA-Z0-9]*", saveName)
	}

	ciphertext, err := box.SealAnonymous(nil, plaintext, To32(config.PublicKey), rand.Reader)
	if err != nil {
		return fmt.Errorf("unable to encrypt file: %w", err)
	}

	savePath, err := config.GetFileStore(saveName)
	if err != nil {
		return fmt.Errorf("unable to store file: %w", err)
	}

	saveFile, err := os.OpenFile(savePath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("unable to save file: %w", err)
	}

	_, err = saveFile.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("unable to write file: %w", err)
	}

	err = saveFile.Close()
	if err != nil {
		return fmt.Errorf("unable to close file: %w", err)
	}

	// Create a metadata entry for the file
	config.Files[saveName] = &Metadata{}
	return config.Save()
}

func (config *Configuration) InitKeys() error {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	config.PrivateKey = private[:]
	config.PublicKey = public[:]
	return nil
}
