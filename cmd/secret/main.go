package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/commandquery/secret"
	"github.com/commandquery/secret/client"
	"github.com/commandquery/secret/server"
	"golang.org/x/crypto/nacl/box"
)

func usage(msg ...any) {

	_, _ = os.Stderr.WriteString(secret.README)
	fmt.Println()

	if len(msg) > 0 {
		fmt.Println()
		fmt.Println(msg...)
		fmt.Println()
	}

	os.Exit(1)
}

func cmdEnrol(config *client.Config, args []string) error {

	flags := flag.NewFlagSet("enrol", flag.ContinueOnError)
	force := flags.Bool("force", false, "force overwrite")
	if err := flags.Parse(args); err != nil {
		usage("secret enrol [--force] user@domain https://server/")
	}

	// If only one arg and the config came from disk, don't overwrite it.
	if config.Stored && !*force {
		exit(1, fmt.Errorf("a secret configuration already exists; use --force to overwrite it"))
	}

	args = flags.Args()
	if len(args) != 2 {
		usage("secret enrol [--force] user@domain https://server/")
	}

	if err := config.AddServer(args[0], args[1]); err != nil {
		exit(1, fmt.Errorf("unable to initialise keys: %w", err))
	}

	return config.Save()
}

func cmdKey(server *client.Endpoint) error {
	b64 := base64.StdEncoding.EncodeToString(server.PublicKey)
	fmt.Println(b64)
	return nil
}

// Generate a key pair. This is mostly for seting up a server
func cmdGenKey() {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Public:  %s\n", base64.StdEncoding.EncodeToString(pub[:]))
	fmt.Printf("Private: %s\n", base64.StdEncoding.EncodeToString(priv[:]))
}

func main() {

	if err := initConfig(); err != nil {
		exit(1, err)
	}

	args := os.Args

	if len(args) == 1 {
		// --help, or anything else.
		usage()
	}

	if args[1] == "server" {
		exit(0, server.StartServer(Config.ServerConfigPath, Config.PathPrefix, Config.AutoEnrol))
	}

	var store string
	var err error

	flags := flag.NewFlagSet("secret", flag.ContinueOnError)
	flags.StringVar(&store, "f", GetStoreLocation(), "path to store secret")
	if err := flags.Parse(os.Args[1:]); err != nil {
		exit(1, err)
	}

	config, err := client.LoadSecretConfiguration(store)
	if err != nil {
		exit(1, err)
	}

	if config.Version != client.ConfigVersion {
		panic(fmt.Errorf("unexpected config version: %d", config.Version))
	}

	if flags.NArg() == 0 {
		usage()
	}

	command := flags.Args()[0]
	args = flags.Args()[1:]

	if !config.Stored && command != "enrol" {
		fmt.Fprintf(os.Stderr, "please share your public key before using `secret`:\n")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "    secret enrol email@example.com\n")
		os.Exit(1)
	}

	endpoint := config.Servers[config.Properties.Server]

	switch command {
	case "enrol":
		err = cmdEnrol(config, args)

	case "key":
		err = cmdKey(endpoint)

	case "share":
	case "send":
		err = client.CmdShare(config, endpoint, args)
		if err == nil {
			config.Save() // TODO: should only happen if a peer was added. FIXME: no error check.
		}

	case "ls":
		err = client.CmdLs(endpoint, args)

	case "get":
		err = client.CmdGet(config, endpoint, args)
		if err == nil {
			config.Save() // TODO: should only happen if a peer was added. FIXME: no error check.
		}

	case "set":
		if len(args) != 1 {
			usage()
		}
		err = config.Set(args[0])
		if err == nil {
			config.Save()
		}

	case "genkey":
		cmdGenKey()

	case "help", "--help", "-h":
		usage()

	default:
		usage()
	}

	if err == nil {
		os.Exit(0)
	}

	exit(1, err)
}

func exit(code int, err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(code)
}
