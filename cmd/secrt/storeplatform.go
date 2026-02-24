package main

import (
	"encoding/json"
	"fmt"

	"github.com/zalando/go-keyring"
)

type PlatformVault struct {
	Service string `json:"service"` // Always "secrt.io"
	User    string `json:"user"`    // Endpoint URL including peer ID
	values  Map64  // Cached (unsealed) private key, never marshalled/unmarshalled
}

type Map64 map[string][]byte

func NewPlatformSecureStore(endpoint *Endpoint) (*PlatformVault, error) {

	vault := &PlatformVault{
		Service: "secrt.io",
		User:    endpoint.Alias + ":" + endpoint.URL,
		values:  make(Map64), // this value must be private, and never stored in the config.
	}

	js, err := json.Marshal(vault.values)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal initial value: %w", err)
	}

	err = keyring.Set(vault.Service, vault.User, string(js))
	if err != nil {
		return nil, fmt.Errorf("unable to save key to platform store: %w", err)
	}

	return vault, nil
}

func (s *PlatformVault) Type() VaultType {
	return VaultPlatform
}

func (s *PlatformVault) IsUnsealed() bool {
	return s.values != nil
}

func (s *PlatformVault) Unseal() error {
	secret, err := keyring.Get(s.Service, s.User)
	if err != nil {
		return fmt.Errorf("unable to get secret from platform store: %w", err)
	}

	if err = json.Unmarshal([]byte(secret), &s.values); err != nil {
		return fmt.Errorf("unable to unmarshal platform store: %w", err)
	}

	return nil
}

func (s *PlatformVault) Get(key string) ([]byte, error) {
	if s.values == nil {
		return nil, fmt.Errorf("uninitialized store")
	}
	return s.values[key], nil
}

func (s *PlatformVault) Set(key string, value []byte) error {

	s.values[key] = value
	js, err := json.Marshal(s.values)
	if err != nil {
		return fmt.Errorf("unable to marshal map: %w", err)
	}

	err = keyring.Set(s.Service, s.User, string(js))
	if err != nil {
		return fmt.Errorf("unable to save key to platform store: %w", err)
	}

	return nil
}

func (s *PlatformVault) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s *PlatformVault) Unmarshal(bytes []byte) error {
	return json.Unmarshal(bytes, s)
}
