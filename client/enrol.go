package client

import (
	"bytes"
	"flag"
	"fmt"

	"github.com/commandquery/secrt"
)

func ReadKeyPhrase() []byte {
	p1 := ReadPassword("Enter passphrase:  ")
	if p1 == nil {
		return nil
	}

	p2 := ReadPassword("Verify passphrase: ")
	if p2 == nil {
		return nil
	}

	if !bytes.Equal(p1, p2) {
		fmt.Println("passphrase mismatch")
		return nil
	}

	return p1
}

func CmdEnrol(config *Config, args []string) error {

	fmt.Println("A passphrase will be used to protect your private key.")
	fmt.Println()

	//passphrase := ReadKeyPhrase()
	//if passphrase == nil {
	//	return fmt.Errorf("no passphrase provided")
	//}

	flags := flag.NewFlagSet("enrol", flag.ContinueOnError)
	force := flags.Bool("force", false, "force overwrite")
	storeType := flags.String("store", "platform", "Storage type for private key")
	if err := flags.Parse(args); err != nil {
		secrt.Usage("secret enrol [--force] user@domain https://server/")
	}

	// If only one arg and the config came from disk, don't overwrite it.
	if config.Stored && !*force {
		secrt.Exit(1, fmt.Errorf("a secret configuration already exists; use --force to overwrite it"))
	}

	args = flags.Args()
	if len(args) != 2 {
		secrt.Usage("secret enrol [--force] user@domain https://server/")
	}

	if err := config.AddEndpoint(args[0], args[1], KeyStoreType(*storeType)); err != nil {
		secrt.Exit(1, fmt.Errorf("unable to enrol user: %w", err))
	}

	return config.Save()
}
