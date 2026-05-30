package main

import (
	"encoding/json"
	"fmt"

	"github.com/itchyny/gojq"
)

// Config migration scripts. We use gojq to perform transformations over the
// JSON config file to bring it up to the latest version. This lets us migrate
// configuration without needing to keep all the old config structs around.

type migration struct {
	from      float64
	to        float64
	transform string
}

var migrations []migration = []migration{
	// Change the peer list from an object to an array,
	// and allow multiple public keys for a given peer.
	{from: 1, to: 2, transform: `
		.endpoints[] |= (
		  .peers = [(.peers // {}) []]
		  | .peers[] |= (
			.publicKeys = [{ "type": "box", "trust": true, "key": .boxPublicKey, "used": now | floor }]
			| del(.boxPublicKey)
		  )
		)
	`},
}

// Migrate converts a src JSON object into the latest JSON shape
// as required by the configuration objects. It does this by applying
// each of the listed migration transforms from the current config version.
// returns a boolean value indicating if migration was actually required.
func Migrate(src []byte) ([]byte, bool, error) {

	var state map[string]any
	if err := json.Unmarshal(src, &state); err != nil {
		return nil, false, fmt.Errorf("unable to determine config version number: %w", err)
	}

	configVersion, ok := state["version"]
	if !ok {
		return nil, false, fmt.Errorf("config is not an object")
	}

	version, ok := configVersion.(float64)
	if !ok {
		return nil, false, fmt.Errorf("unable to determine config version number")
	}

	modified := false

	for _, m := range migrations {
		if m.from != version {
			continue
		}

		transform, err := gojq.Parse(m.transform)
		if err != nil {
			return nil, false, fmt.Errorf("unable to parse transform from version %s: %w", version, err)
		}

		it := transform.Run(state)
		next, ok := it.Next()
		if !ok {
			return nil, false, fmt.Errorf("transform returned no result for version %s", version)
		}

		if err, ok = next.(error); ok {
			return nil, false, fmt.Errorf("transform failed for version %.0f: %w", version, err)
		}

		state, ok = next.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("transform failed for version %.0f: %w", version, err)
		}

		state["version"] = m.to
		modified = true
		version = m.to
	}

	if !modified {
		return src, false, nil
	}

	result, err := json.Marshal(state)
	if err != nil {
		return nil, false, fmt.Errorf("unable to marshal config: %w", err)
	}

	return result, true, nil
}
