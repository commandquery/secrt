package client

import (
	"encoding/json"
)

// ClearKeyStore is a keystore that stores the private key in cleartext.
// You shouldn't use it if you have a choice, but it is certainly helpful for testing,
// and for devices that don't have any cryptographic key infrastructure.
type ClearKeyStore struct {
	PrivateKey []byte `json:"privateKey"`
}

func NewClearKeyStore(privateKey []byte) *ClearKeyStore {
	return &ClearKeyStore{
		PrivateKey: privateKey,
	}
}

func (s *ClearKeyStore) Type() KeyStoreType {
	return KeyStoreClear
}

func (s *ClearKeyStore) IsUnsealed() bool {
	return true
}

func (s *ClearKeyStore) Unseal() error {
	return nil
}

func (s *ClearKeyStore) GetPrivateKey() ([]byte, error) {
	return s.PrivateKey, nil
}

func (s *ClearKeyStore) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s *ClearKeyStore) Unmarshal(bytes []byte) error {
	return json.Unmarshal(bytes, s)
}
