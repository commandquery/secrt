package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func CmdPeer(config *Config, endpoint *Endpoint, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secrt peer {add | ls | rm}")
	}

	switch args[0] {
	case "add":
		return CmdPeerAdd(config, endpoint, args[1:])
	case "rm":
		return CmdPeerRm(config, endpoint, args[1:])
	case "ls":
		return CmdPeerLs(config, endpoint, args[1:])
	default:
		return fmt.Errorf("usage: secrt peer {add | ls | rm}")
	}
}

func CmdPeerAdd(config *Config, endpoint *Endpoint, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: secrt peer add {alias}")
	}

	alias := args[0]
	_, err := endpoint.AddPeer(alias)
	if err != nil {
		return err
	}

	config.modified = true
	return nil
}

func CmdPeerRm(config *Config, endpoint *Endpoint, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: secrt peer rm {peerId}")
	}

	alias := args[0]

	err := endpoint.DeletePeer(alias)

	if err != nil {
		return fmt.Errorf("unable to delete peer: %w", err)
	}

	config.modified = true
	return nil
}

func CmdPeerLs(config *Config, endpoint *Endpoint, args []string) error {
	for email, peer := range endpoint.Peers {
		var pks []string
		for _, pk := range peer.PublicKeys {
			if pk.Trust {
				p64 := base64.StdEncoding.EncodeToString(pk.Key)
				pks = append(pks, p64)
			}
		}

		fmt.Println(email, strings.Join(pks, ","))
	}
	return nil
}
