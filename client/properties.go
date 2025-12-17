package client

import (
	"fmt"
	"strconv"
)

// Properties is a set of configuration properties used to control
// the behaviour of the client.
type Properties struct {
	Metadata    bool   `json:"metadata"`    // Send file metadata in cleartext?
	Server      string `json:"server"`      // The default server to use
	AcceptPeers bool   `json:"acceptPeers"` // Automatically accept new peers
}

func (p *Properties) Set(name string, value string) error {
	var err error

	switch name {
	case "server":
		p.Server = value
	case "metadata":
		p.Metadata, err = strconv.ParseBool(value)
	case "acceptPeers":
		p.AcceptPeers, err = strconv.ParseBool(value)
	default:
		err = fmt.Errorf("unknown property '%s'", name)
	}

	return err
}
