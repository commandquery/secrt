package main

import (
	"fmt"
	"strconv"
)

// Properties is a set of configuration properties used to control
// the behaviour of the client.
type Properties struct {
	DefaultEndpoint int  `json:"defaultEndpoint"` // The default server to use
	AcceptPeers     bool `json:"acceptPeers"`     // Automatically accept new peers
	Telemetry       bool `json:"telemetry"`       // Send telemetry before quitting?
	Cache           bool `json:"cache"`           // Enable caching of messages
}

func (p *Properties) Set(name string, value string) error {
	var err error

	switch name {
	case "server":
		p.DefaultEndpoint, err = strconv.Atoi(value)
	case "acceptPeers":
		p.AcceptPeers, err = strconv.ParseBool(value)
	case "telemetry":
		p.Telemetry, err = strconv.ParseBool(value)
	case "cache":
		p.Cache, err = strconv.ParseBool(value)
	default:
		err = fmt.Errorf("unknown property '%s'", name)
	}

	return err
}
