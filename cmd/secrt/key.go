package main

import (
	"encoding/base64"
	"fmt"
)

func CmdKey(server *Endpoint) error {
	b64 := base64.StdEncoding.EncodeToString(server.BoxPublicKey)
	fmt.Println(b64)
	return nil
}
