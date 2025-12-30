package client

import (
	"flag"
	"fmt"
	"os"

	"github.com/commandquery/secrt"
)

func Main(args []string) {
	var store string
	var err error

	flags := flag.NewFlagSet("secrt", flag.ContinueOnError)
	flags.StringVar(&store, "f", GetStoreLocation(), "path to store secret")
	if err := flags.Parse(os.Args[1:]); err != nil {
		secrt.Exit(1, err)
	}

	config, err := LoadSecretConfiguration(store)
	if err != nil {
		secrt.Exit(1, err)
	}

	if config.Version != ConfigVersion {
		panic(fmt.Errorf("unexpected config version: %d", config.Version))
	}

	if flags.NArg() == 0 {
		secrt.Usage()
	}

	command := flags.Args()[0]
	args = flags.Args()[1:]

	if !config.Stored && command != "enrol" {
		fmt.Fprintf(os.Stderr, "please enrol your public key before using `secret`:\n")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "    secret enrol email@example.com\n")
		os.Exit(1)
	}

	endpoint := config.Servers[config.Properties.Server]

	switch command {
	case "enrol":
		err = CmdEnrol(config, args)

	case "key":
		err = CmdKey(endpoint)

	case "send":
		err = CmdSend(config, endpoint, args)
		if err == nil {
			err = config.Save() // TODO: don't write unless modified
		}

	case "ls":
		err = CmdLs(config, endpoint, args)

	case "get":
		err = CmdGet(config, endpoint, args)
		if err == nil {
			err = config.Save() // TODO: don't write unless modified
		}

	case "peer":
		err = CmdPeer(config, endpoint, args)
		if err == nil {
			err = config.Save() // TODO: don't write unless modified
		}

	case "rm":
		err = CmdRm(config, endpoint, args)

	case "set":
		if len(args) != 1 {
			secrt.Usage()
		}

		err = config.Set(args[0])
		if err == nil {
			err = config.Save() // TODO: don't write unless modified
		}

	case "genkey":
		CmdGenKey()

	case "help", "--help", "-h":
		secrt.Usage()

	default:
		secrt.Usage()
	}

	if err == nil {
		os.Exit(0)
	}

	secrt.Exit(1, err)
}
