package main

import (
	"encoding/json"
)

// ClearVault is a vault that stores values in cleartext. Not much of a vault.
// You shouldn't use it if you have a choice, but it is certainly helpful for testing,
// and for devices that don't have any cryptographic key infrastructure.
type ClearVault struct {
	Values map[string][]byte `json:"values"`
}

func NewClearVault() *ClearVault {
	return &ClearVault{
		Values: make(map[string][]byte),
	}
}

func (s *ClearVault) Type() VaultType {
	return VaultClear
}

func (s *ClearVault) IsUnsealed() bool {
	return true
}

func (s *ClearVault) Unseal() error {
	return nil
}

func (s *ClearVault) Get(key string) ([]byte, error) {
	return s.Values[key], nil
}

func (s *ClearVault) Set(key string, value []byte) error {
	s.Values[key] = value
	return nil
}

func (s *ClearVault) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s *ClearVault) Unmarshal(bytes []byte) error {
	return json.Unmarshal(bytes, s)
}
