package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/commandquery/secrt"
)

func main() {
	startTime := time.Now()
	var storeDirectory string
	var noSaveFlag bool
	var err error

	flags := flag.NewFlagSet("secrt", flag.ContinueOnError)
	flags.StringVar(&storeDirectory, "c", GetStoreDirectory(), "path to secrt directory")
	flags.BoolVar(&noSaveFlag, "no-save", false, "do not update the config file")

	if err := flags.Parse(os.Args[1:]); err != nil {
		secrt.Exit(1, err)
	}

	config, err := LoadClientConfig(storeDirectory)
	if err != nil {
		secrt.Exit(1, err)
	}

	if config.Version != ConfigVersion {
		panic(fmt.Errorf("unexpected config version: %d", config.Version))
	}

	if flags.NArg() == 0 {
		secrt.Usage()
	}

	// sanity check for config file
	if config.Properties.DefaultEndpoint >= len(config.Endpoints) {
		config.Properties.DefaultEndpoint = 0
	}

	var endpoint *Endpoint
	if len(config.Endpoints) > config.Properties.DefaultEndpoint {
		endpoint = config.Endpoints[config.Properties.DefaultEndpoint]
	}

	command := flags.Args()[0]
	args := flags.Args()[1:]
	config.canSave = !noSaveFlag

	// Special case when there is no existing config/endpoint
	if endpoint == nil {
		//err = EnrolWalkthrough(config)
		//if err == nil {
		//	os.Exit(0)
		//}
		//
		//secrt.Exit(1, err)
		//return
		if command != "enrol" {
			fmt.Fprintf(os.Stderr, "please enrol your public key before using `secret`:\n")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "    secret enrol email@example.com\n")
			os.Exit(1)
		} else {
			err = CmdEnrol(config, args)
			if err == nil {
				err = config.Save()
			}

			if err == nil {
				os.Exit(0)
			}
		}

		secrt.Exit(1, err)
		return
	}

	cache, err := OpenCache(config, endpoint)
	if err != nil {
		secrt.Exit(1, err)
	}

	if command != "activate" {
		if err = cache.pull(); err != nil {
			secrt.Exit(1, err)
		}
	}

	switch command {
	case "enrol":
		err = CmdEnrol(config, args)
		if err == nil {
			err = config.Save()
		}

	case "key":
		err = CmdKey(endpoint)

	case "send":
		err = CmdSend(config, endpoint, args)
		if err == nil {
			err = config.Save()
		}

	case "ls":
		err = CmdLs(cache, args)
		if err == nil {
			err = config.Save()
		}

	case "get":
		err = CmdGet(cache, args)
		if err == nil {
			err = config.Save()
		}

	case "peer":
		err = CmdPeer(config, endpoint, args)
		if err == nil {
			err = config.Save()
		}

	case "rm":
		err = CmdRm(cache, args)

	case "run":
		err = CmdRun(cache, args)

	case "set":
		if len(args) != 1 {
			secrt.Usage()
		}

		err = config.Set(args[0])
		if err == nil {
			err = config.Save()
		}

	case "invite":
		err = CmdInvite(config, endpoint, args)

	case "activate":
		err = CmdActivate(config, endpoint, args)
		if err == nil {
			err = config.Save()
		}

	case "genkey":
		CmdGenKey()

	case "help", "--help", "-h":
		secrt.Usage()

	default:
		secrt.Usage()
	}

	var exitCode = 0
	if err != nil {
		exitCode = 1
	}

	SendTelemetry(config, endpoint, command, exitCode, startTime)

	endpoint.PrintNewPeers()

	secrt.Exit(exitCode, err)
}
