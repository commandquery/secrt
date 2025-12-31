package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type PlatformKeyStore struct {
	Service    string `json:"service"`  // Always "secrt.io"
	User       string `json:"user"`     // Always the URL of the endpoint
	Password   string `json:"password"` // Base64 encoded key.
	privateKey []byte // Cached (unsealed) private key, never marshalled/unmarshalled
}

func NewPlatformKeyStore(endpoint *Endpoint, privateKey []byte) *PlatformKeyStore {

	key64 := base64.StdEncoding.EncodeToString(privateKey)

	// TODO: STORE THE KEY!

	return &PlatformKeyStore{
		Service:    "secrt.io",
		User:       endpoint.URL,
		Password:   key64,
		privateKey: privateKey,
	}
}

func (s *PlatformKeyStore) Type() KeyStoreType {
	return KeyStorePlatform
}

func (s *PlatformKeyStore) IsUnsealed() bool {
	return s.privateKey != nil
}

func (s *PlatformKeyStore) Unseal() error {
	// TODO: GET THE PRIVATE KEY!
	return nil
}

func (s *PlatformKeyStore) GetPrivateKey() ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key is not initialized")
	}
	return s.privateKey, nil
}

func (s *PlatformKeyStore) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s *PlatformKeyStore) Unmarshal(bytes []byte) error {
	return json.Unmarshal(bytes, s)
}
