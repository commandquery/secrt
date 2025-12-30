package client

import (
	"flag"
	"fmt"

	"github.com/commandquery/secrt"
)

func CmdEnrol(config *Config, args []string) error {

	flags := flag.NewFlagSet("enrol", flag.ContinueOnError)
	force := flags.Bool("force", false, "force overwrite")
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

	if err := config.AddServer(args[0], args[1]); err != nil {
		secrt.Exit(1, fmt.Errorf("unable to enrol user: %w", err))
	}

	return config.Save()
}
