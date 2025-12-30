package main

import (
	"os"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/client"
	"github.com/commandquery/secrt/server"
)

func main() {

	args := os.Args

	if len(args) == 1 {
		// --help, or anything else.
		secrt.Usage()
	}

	if args[1] == "server" {
		secrt.Exit(0, server.StartServer())
	}

	client.Main(args)
}
