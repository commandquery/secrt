package client

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// Generate a key pair. This is mostly for seting up a server
func CmdGenKey() {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Public:  %s\n", base64.StdEncoding.EncodeToString(pub[:]))
	fmt.Printf("Private: %s\n", base64.StdEncoding.EncodeToString(priv[:]))
}
